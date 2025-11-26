#!/usr/bin/env python3
"""
Certbot deploy-hook: automatic TLS certificate deployment to Cisco ESA (AsyncOS).

Author: Magnus Frödell

High-level flow
---------------
1. Certbot renews a certificate and invokes this script as a deploy-hook.
2. The script:
   - Verifies that the renewed certificate covers the ESA's FQDN.
   - Builds a PKCS#12 (.pfx) bundle from the Let's Encrypt lineage
     (leaf cert + intermediate chain, no duplicate fullchain).
   - Copies the PFX to the ESA over SSH (SCP, legacy mode, suitable for Cisco).
   - SSHes to the ESA and drives `certconfig` via pexpect to:
       * import/overwrite a certificate profile,
       * handle FQDN validation prompts,
       * supply the PFX passphrase.
   - Exits back to the main ESA prompt and runs `commit` (or no-op if nothing to commit).

Design goals
------------
- Non-interactive: suitable for cron/systemd-based Certbot renewals.
- Idempotent: safe to run multiple times, overwriting the same profile.
- Minimal assumptions about AsyncOS prompts; robust handling of:
    * existing profile overwrite prompt,
    * optional FQDN check prompts,
    * "There is no data to commit." commits.

Security considerations
-----------------------
- Prefer SSH key-based authentication to the ESA (no passwords in the hook).
- The PKCS#12 password is provided via environment variable
  (ESA_PFX_PASSWORD) and used only for:
    * openssl pkcs12 -export
    * import into ESA
- PFX files are created in a temporary directory and removed after use.
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Optional

import pexpect


# =====================================================================================
# Configuration data classes
# =====================================================================================

@dataclass(frozen=True)
class EsaConfig:
    """
    ESA connectivity and certificate profile configuration.

    Values are primarily sourced from environment variables to avoid
    hard-coding host-specific settings into the script.

    Environment variables (all optional, but recommended in production):
        ESA_HOST
            ESA hostname or IP (FQDN recommended).
            Default: "esa.example.com"

        ESA_SSH_PORT
            SSH port to the ESA.
            Default: "22"

        ESA_USER
            ESA administrative username (typically "admin").
            Default: "admin"

        ESA_USE_PASSWORD
            "true" / "false" (case-insensitive).
            If "true", the script expects ESA_PASSWORD and uses password-based
            SSH authentication. Otherwise, key-based/agent-based SSH is assumed.
            Default: "false"

        ESA_PASSWORD
            ESA administrative password. Only used if ESA_USE_PASSWORD="true".
            Default: None

        ESA_CERT_PROFILE_NAME
            Name of the certificate profile to create/overwrite in certconfig.
            Default: "lets_encrypt_mail"

        ESA_REMOTE_PFX_PATH
            Full path (on the ESA) where the PFX will be copied.
            Only the basename is used in certconfig to avoid symbol issues.
            Default: "/configuration/esacertpfx"

        ESA_PFX_PASSWORD
            PKCS#12 password used both for OpenSSL export and for ESA import.
            Avoid problematic symbols; [A-Za-z0-9_-] is recommended.
            Default: "ChangeMe12345"

        ESA_TARGET_DOMAIN
            FQDN that must be present in the renewed certificate's domain list
            for this hook to take action. Prevents accidentally deploying a
            cert for the wrong host.
            Default: "mail.example.com"
    """

    host: str = os.environ.get("ESA_HOST", "esa.example.com")
    ssh_port: int = int(os.environ.get("ESA_SSH_PORT", "22"))
    user: str = os.environ.get("ESA_USER", "admin")

    # Authentication mode
    use_password: bool = os.environ.get("ESA_USE_PASSWORD", "false").lower() == "true"
    password: Optional[str] = os.environ.get("ESA_PASSWORD")

    # Certificate profile and remote PFX location
    cert_profile_name: str = os.environ.get("ESA_CERT_PROFILE_NAME", "lets_encrypt_mail")
    remote_pfx_path: str = os.environ.get(
        "ESA_REMOTE_PFX_PATH",
        "/configuration/esacertpfx",  # basename "esacertpfx" has no special symbols
    )

    # PKCS#12 password (for openssl and ESA)
    pfx_password: str = os.environ.get("ESA_PFX_PASSWORD", "ChangeMe12345")

    # Domain to check for in the renewed certificate
    target_domain: str = os.environ.get("ESA_TARGET_DOMAIN", "mail.example.com")


@dataclass(frozen=True)
class CertbotContext:
    """
    Context provided by Certbot deploy-hook environment.

    Environment variables:
        RENEWED_LINEAGE
            Path to certificate lineage directory
            (e.g. /etc/letsencrypt/live/mail.example.com)

        RENEWED_DOMAINS
            Space-separated list of domains in the renewed certificate
    """

    renewed_lineage: str
    renewed_domains: str

    @staticmethod
    def from_env() -> "CertbotContext":
        """Construct context from Certbot's deploy-hook environment variables."""
        lineage = os.environ.get("RENEWED_LINEAGE")
        domains = os.environ.get("RENEWED_DOMAINS")

        if not lineage or not domains:
            raise RuntimeError(
                "RENEWED_LINEAGE and/or RENEWED_DOMAINS are not set. "
                "This script is intended to be invoked by Certbot as a deploy-hook "
                "or with explicit --lineage/--domains arguments for manual testing."
            )

        return CertbotContext(renewed_lineage=lineage, renewed_domains=domains)


# =====================================================================================
# Logging and subprocess utilities
# =====================================================================================

LOGGER = logging.getLogger("esa_deploy")


def configure_logging(verbose: bool = False) -> None:
    """Configure root logger for console output."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        stream=sys.stderr,
    )


def run_subprocess(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    """
    Run a subprocess with logging.

    Args:
        cmd:
            Command and arguments (argv-style).
        check:
            If True, raise CalledProcessError on non-zero exit.

    Returns:
        subprocess.CompletedProcess

    Raises:
        subprocess.CalledProcessError if check=True and the command fails.
    """
    LOGGER.debug("Executing command: %s", " ".join(cmd))
    return subprocess.run(cmd, check=check)


# =====================================================================================
# PKI helpers: chain and PKCS#12 generation
# =====================================================================================

def ensure_chain(lineage: str) -> str:
    """
    Ensure that chain.pem exists in the given lineage directory.

    If chain.pem is missing, it is derived from fullchain.pem by removing
    the leaf certificate and keeping only the intermediate CA certificates.

    This is important for Cisco ESA, which expects the PKCS#12 "extra chain"
    to be pure CA chain (no duplicate leaf cert).
    """
    chain_path = os.path.join(lineage, "chain.pem")
    fullchain_path = os.path.join(lineage, "fullchain.pem")

    if os.path.exists(chain_path):
        LOGGER.debug("Found existing chain.pem at %s", chain_path)
        return chain_path

    if not os.path.exists(fullchain_path):
        raise FileNotFoundError(
            f"Neither chain.pem nor fullchain.pem exist under lineage {lineage}"
        )

    LOGGER.info("chain.pem not found; deriving from fullchain.pem by stripping leaf certificate.")
    tmp_chain = f"{chain_path}.tmp"

    with open(fullchain_path, "r", encoding="ascii") as src, \
            open(tmp_chain, "w", encoding="ascii") as dst:
        content = src.read()
        blocks = content.split("-----BEGIN CERTIFICATE-----")

        # blocks[0] is any preamble; blocks[1] is leaf; blocks[2:] are intermediates.
        intermediates = blocks[2:]
        if not intermediates:
            raise RuntimeError("fullchain.pem does not contain any intermediate certificates.")

        dst.write("".join("-----BEGIN CERTIFICATE-----" + b for b in intermediates))

    os.replace(tmp_chain, chain_path)
    LOGGER.info("Derived chain.pem written to %s", chain_path)
    return chain_path


def build_pfx(lineage: str, pfx_password: str) -> str:
    """
    Build a PKCS#12 (.pfx) bundle from the Let's Encrypt lineage.

    The resulting PFX contains:
        - Leaf certificate (cert.pem)     [CA:FALSE]
        - Intermediate chain (chain.pem)  [CA:TRUE]

    Args:
        lineage:
            Path to the Certbot lineage (e.g. /etc/letsencrypt/live/example.com).
        pfx_password:
            Password used to protect the PFX.

    Returns:
        Path to the generated PFX file (inside a temporary directory).

    Note:
        The caller is responsible for cleaning up the temp directory that
        contains the PFX file.
    """
    cert_path = os.path.join(lineage, "cert.pem")
    key_path = os.path.join(lineage, "privkey.pem")
    chain_path = ensure_chain(lineage)

    for fpath in (cert_path, key_path, chain_path):
        if not os.path.exists(fpath):
            raise FileNotFoundError(f"Required file does not exist: {fpath}")

    temp_dir = tempfile.mkdtemp(prefix="esa_pfx_")
    pfx_path = os.path.join(temp_dir, "esacert.pfx")

    LOGGER.info("Building PKCS#12 bundle at %s", pfx_path)

    cmd = [
        "openssl",
        "pkcs12",
        "-export",
        "-out", pfx_path,
        "-inkey", key_path,
        "-in", cert_path,
        "-certfile", chain_path,
        "-passout", f"pass:{pfx_password}",
    ]
    run_subprocess(cmd)

    return pfx_path


def scp_to_esa(pfx_path: str, cfg: EsaConfig) -> None:
    """
    Copy the PFX file to the ESA using scp.

    Uses legacy SCP mode (-O) because many Cisco appliances do not
    support the newer SFTP-based scp protocol used by OpenSSH 9.x+.

    Args:
        pfx_path:
            Local path to the PFX file.
        cfg:
            ESA configuration (host, user, port, remote path).
    """
    destination = f"{cfg.user}@{cfg.host}:{cfg.remote_pfx_path}"
    LOGGER.info("Copying PFX to ESA: %s", destination)

    cmd = [
        "scp",
        "-O",                      # force legacy SCP (important for Cisco appliances)
        "-P", str(cfg.ssh_port),
        pfx_path,
        destination,
    ]
    run_subprocess(cmd)


# =====================================================================================
# ESA CLI automation via pexpect
# =====================================================================================

class EsaCertImportError(Exception):
    """Raised when ESA certificate import or commit operations fail."""


class EsaCertImporter:
    """
    Handles SSH connection to ESA and automation of certconfig to import
    a PKCS#12 bundle as a certificate profile, then commit (if applicable).

    Typical interactive flow (simplified):

        > certconfig
        []> certificate
        []> import
        Enter a name for this certificate profile:
        > lets_encrypt_mail
        [maybe] Certificate profile "lets_encrypt_mail" already exists. Do you want to
                overwrite with this new one? [N]>
        Enter the name of the file on machine "hostname" to import:
        []> esacertpfx
        [maybe] check if Common Name or SAN:dNSName or both are in Fully
                Qualified Domain Name(FQDN) format ? [N]>
        Enter pass phrase for PKCS#12:
        ...
        []>
        [ENTER to exit certconfig, then back at hostname>]
        > commit
        [either] Please enter some comments describing your changes:
                 Do you want to save the current configuration for rollback? [Y]>
        [or]     There is no data to commit.
    """

    def __init__(self, cfg: EsaConfig, timeout: int = 90):
        self.cfg = cfg
        self.timeout = timeout

    # -------------------------------------------------------------------------
    # SSH session lifecycle
    # -------------------------------------------------------------------------

    def _spawn_ssh(self) -> pexpect.spawn:
        """Spawn an SSH session to the ESA."""
        ssh_cmd = [
            "ssh",
            "-p", str(self.cfg.ssh_port),
            f"{self.cfg.user}@{self.cfg.host}",
        ]

        LOGGER.info("Opening SSH session to ESA: %s", " ".join(ssh_cmd))
        child = pexpect.spawn(
            ssh_cmd[0],
            ssh_cmd[1:],
            encoding="utf-8",
            timeout=self.timeout,
        )
        return child

    def import_pfx_and_commit(self) -> None:
        """
        Import the PFX file (already copied to ESA) into certconfig,
        then commit changes (or gracefully no-op if there is nothing to commit).
        """
        child = self._spawn_ssh()

        # For troubleshooting, you can uncomment this to mirror the session:
        # child.logfile = sys.stdout

        try:
            self._handle_auth(child)
            self._run_certconfig_import(child)
            self._commit_changes(child)
        except (pexpect.EOF, pexpect.TIMEOUT) as exc:
            LOGGER.error("PEXPECT communication error: %s", exc)
            raise EsaCertImportError("Error during interaction with ESA via pexpect") from exc
        finally:
            try:
                child.close()
            except Exception:
                LOGGER.debug("Error closing pexpect child; ignoring.", exc_info=True)

            LOGGER.info(
                "SSH session closed (exitstatus=%s, signal=%s)",
                getattr(child, "exitstatus", None),
                getattr(child, "signalstatus", None),
            )

    # -------------------------------------------------------------------------
    # Authentication and certconfig automation
    # -------------------------------------------------------------------------

    def _handle_auth(self, child: pexpect.spawn) -> None:
        """
        Handle SSH authentication.

        Modes:
            - Password-based (if ESA_USE_PASSWORD=true)
            - Key/agent-based (default; no password prompt)
        """
        if self.cfg.use_password:
            idx = child.expect([r"[Pp]assword:", r"> "])
            if idx == 0:
                if not self.cfg.password:
                    raise EsaCertImportError(
                        "ESA_USE_PASSWORD is true but ESA_PASSWORD is not set."
                    )
                child.sendline(self.cfg.password)
                child.expect(r"> ")
        else:
            # Expect to land on the main ESA prompt directly (hostname>).
            child.expect(r"> ")

    def _run_certconfig_import(self, child: pexpect.spawn) -> None:
        """
        Drive certconfig to import the PFX as a certificate profile.

        Handles:
            - existing profile overwrite prompt,
            - FQDN check prompts (before/after import),
            - PFX passphrase prompt.
        """
        LOGGER.info("Starting certconfig to import certificate profile.")

        # Enter certconfig
        child.sendline("certconfig")

        # Top-level certconfig menu (prompt: []>)
        child.expect(r"\[]>\s*")
        child.sendline("certificate")

        # CERTIFICATE submenu
        child.expect(r"\[]>\s*")
        child.sendline("import")

        # Profile name prompt
        child.expect(r"Enter a name for this certificate profile:", timeout=self.timeout)
        child.sendline(self.cfg.cert_profile_name)

        # After entering the profile name, ESA may:
        #   1) ask whether to overwrite an existing profile; or
        #   2) go directly to the "file on machine" prompt.
        overwrite_pattern = (
            r'[Cc]ertificate profile ".*" already exists\. '
            r'Do you want to\s+overwrite with this new one\? \[N\]>'
        )
        file_prompt_pattern = r"Enter the name of the file on machine .* to import:"

        idx = child.expect(
            [
                overwrite_pattern,    # 0: overwrite confirmation
                file_prompt_pattern,  # 1: directly ask for file
            ],
            timeout=self.timeout,
        )

        if idx == 0:
            LOGGER.info(
                "ESA reports certificate profile '%s' already exists; responding with 'Y' to overwrite.",
                self.cfg.cert_profile_name,
            )
            child.sendline("Y")
            child.expect(file_prompt_pattern, timeout=self.timeout)

        # File on ESA machine – use only the basename to avoid "symbols are not allowed".
        basename = os.path.basename(self.cfg.remote_pfx_path)
        child.sendline(basename)

        # Next: either passphrase prompt or extra FQDN check.
        idx2 = child.expect(
            [
                r"[Pp]ass ?phrase",                         # 0: passphrase prompt
                r"check if Common Name.*FQDN.*\? \[N\]>",   # 1: FQDN check question
            ],
            timeout=self.timeout,
        )

        if idx2 == 1:
            LOGGER.info("ESA asked for FQDN check; responding with 'N'.")
            child.sendline("N")
            child.expect(r"[Pp]ass ?phrase", timeout=self.timeout)

        # Provide PKCS#12 passphrase
        child.sendline(self.cfg.pfx_password)

        # After password, we should see either the CERTIFICATE menu or another FQDN check.
        idx3 = child.expect(
            [
                r"\[]>\s*",                                # 0: CERTIFICATE menu
                r"check if Common Name.*FQDN.*\? \[N\]>",  # 1: FQDN question after import
            ],
            timeout=self.timeout,
        )
        if idx3 == 1:
            LOGGER.info("ESA asked for FQDN check after import; responding with 'N'.")
            child.sendline("N")
            child.expect(r"\[]>\s*", timeout=self.timeout)

        # We purposely do NOT send "exit" here; we remain inside certconfig.
        LOGGER.info(
            "Certificate profile '%s' imported; remaining inside certconfig for now.",
            self.cfg.cert_profile_name,
        )

    # -------------------------------------------------------------------------
    # Commit handling
    # -------------------------------------------------------------------------

    def _ensure_main_prompt(self, child: pexpect.spawn) -> None:
        """
        Ensure that we are at the main ESA prompt (hostname>).

        Behavior of certconfig:
            - Pressing ENTER on an empty line exits certconfig and returns
              to the main ESA prompt.
            - If already at the main prompt, ENTER will simply reprint it.

        This method sends ENTER a few times and checks whether we land on ">".
        """
        LOGGER.info("Ensuring we are at main ESA prompt before running 'commit'.")

        for _ in range(5):
            child.sendline("")  # send ENTER
            idx = child.expect([r"> ", r"\[]>\s*"], timeout=self.timeout)
            if idx == 0:
                LOGGER.debug("Confirmed main ESA prompt.")
                return
            # idx == 1 => still inside certconfig; loop and send ENTER again.

        raise EsaCertImportError("Failed to reach main ESA prompt before commit.")

    def _commit_changes(self, child: pexpect.spawn) -> None:
        """
        Run `commit` on ESA to make configuration changes active.

        Handles:
            - Normal interactive commit (comments + rollback question).
            - "There is no data to commit." no-op commits.
        """
        # Ensure we're at the main "hostname>" prompt.
        self._ensure_main_prompt(child)

        LOGGER.info("Committing ESA configuration changes.")
        child.sendline("commit")

        # Two possible flows:
        #   - No pending changes: "There is no data to commit."
        #   - Normal commit: "Please enter some comments describing your changes:"
        idx = child.expect(
            [
                r"There is no data to commit\.",  # 0: no-op commit
                r"Please enter some comments.*",  # 1: normal commit flow
            ],
            timeout=self.timeout,
        )

        if idx == 0:
            LOGGER.info("ESA reports there is no data to commit; treating as successful no-op.")
            child.expect(r"> ", timeout=self.timeout)
            child.sendline("exit")
            LOGGER.info("ESA session closed after no-op commit.")
            return

        # Normal commit flow
        child.sendline("Auto-imported Let's Encrypt certificate via deploy-hook")

        child.expect(r"rollback\?\s*\[Y\]>", timeout=self.timeout)
        child.sendline("Y")

        child.expect(r"Changes committed.*", timeout=2 * self.timeout)
        child.expect(r"> ", timeout=self.timeout)
        child.sendline("exit")

        LOGGER.info("ESA commit completed successfully.")


# =====================================================================================
# Orchestration: when and how to deploy
# =====================================================================================

def should_deploy_for_domain(context: CertbotContext, target_domain: str) -> bool:
    """
    Determine whether this deploy-hook should act for the given certificate.

    Returns:
        True if target_domain is present in the renewed certificate's domain list.
    """
    domains = context.renewed_domains.split()
    LOGGER.debug("Renewed certificate domains: %s", domains)
    return target_domain in domains


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Primarily supports:
        - Manual testing via --lineage and --domains.
        - Verbose logging via -v/--verbose.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Certbot deploy-hook to automatically deploy a renewed certificate "
            "to Cisco ESA using PKCS#12 and certconfig."
        )
    )
    parser.add_argument(
        "--lineage",
        help="Path to certificate lineage (overrides RENEWED_LINEAGE from environment).",
    )
    parser.add_argument(
        "--domains",
        help="Space-separated domain list (overrides RENEWED_DOMAINS from environment).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    return parser.parse_args()


def build_context_from_args(args: argparse.Namespace) -> CertbotContext:
    """
    Build CertbotContext from either CLI arguments or environment variables.

    Priority:
        - CLI args (--lineage, --domains) for manual testing.
        - Otherwise, Certbot's RENEWED_* environment variables.
    """
    if args.lineage and args.domains:
        LOGGER.info("Using lineage/domains from CLI arguments for testing.")
        return CertbotContext(renewed_lineage=args.lineage, renewed_domains=args.domains)
    return CertbotContext.from_env()


def main() -> int:
    args = parse_args()
    configure_logging(verbose=args.verbose)

    try:
        cfg = EsaConfig()
        context = build_context_from_args(args)

        LOGGER.info(
            "Starting ESA certificate deploy for lineage=%s domains=%s",
            context.renewed_lineage,
            context.renewed_domains,
        )

        if not should_deploy_for_domain(context, cfg.target_domain):
            LOGGER.info(
                "Target domain '%s' not present in renewed certificate; no action taken.",
                cfg.target_domain,
            )
            return 0

        LOGGER.info("Target domain '%s' found; proceeding with deployment.", cfg.target_domain)

        pfx_path = build_pfx(context.renewed_lineage, cfg.pfx_password)
        temp_dir = os.path.dirname(pfx_path)

        try:
            scp_to_esa(pfx_path, cfg)
            importer = EsaCertImporter(cfg)
            importer.import_pfx_and_commit()
        finally:
            # Clean up temporary directory that contained the PFX
            try:
                shutil.rmtree(temp_dir)
            except Exception:
                LOGGER.debug("Failed to remove temporary directory %s", temp_dir, exc_info=True)

        LOGGER.info("ESA certificate deployment completed successfully.")
        return 0

    except Exception as exc:
        LOGGER.error("ESA certificate deployment failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
