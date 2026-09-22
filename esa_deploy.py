#!/usr/bin/env python3
"""
esa_deploy.py - Certbot deploy-hook: automatic TLS certificate deployment to
Cisco Secure Email Gateway (ESA / AsyncOS) using SCP and a pexpect-driven
`certconfig` session.

High-level flow
---------------
1. Certbot renews a certificate and invokes this script as a deploy-hook
   (RENEWED_LINEAGE / RENEWED_DOMAINS in the environment). The script can also
   be run by an operator (--force, --lineage/--domains) or by a systemd timer
   (--reconcile).
2. Targets (appliances) are read from a TOML configuration file. For every
   target whose `target_domains` are covered by the renewed certificate the
   script:
     - builds a PKCS#12 bundle (leaf + intermediate chain + key) in a private
       temporary directory,
     - uploads it to the appliance over SCP,
     - opens an SSH session and drives `certconfig` with pexpect
       (import/overwrite the profile, answer FQDN questions, supply the
       passphrase), leaves certconfig and runs `commit`,
     - optionally overwrites the uploaded PKCS#12 with an empty file,
     - optionally verifies the certificate the appliance now serves
       (TLS or STARTTLS) against the local lineage.
3. Exit code 0 when every selected target succeeded (or nothing had to be
   done), 1 when at least one target failed, 2 on configuration/usage errors.

Design goals
------------
- Non-interactive and fail-fast: no dangerous defaults, missing configuration
  is an error, an unreachable or misbehaving appliance is an error.
- Secrets never appear on command lines or in logs (PKCS#12 password is passed
  to OpenSSL through the environment; all log output is redacted).
- Robust CLI automation: the appliance prompt is learned at login and matched
  exactly afterwards, every wait has a timeout, and timeouts report the last
  output received from the appliance.
- Multiple targets (cluster members, SMA) from one configuration file.
- Verification and reconciliation so that a failed deployment does not go
  unnoticed until the next renewal.

Copyright (c) 2026 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, are
disclaimed.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
import shlex
import shutil
import smtplib
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, fields
from typing import Any, Callable, Optional

try:
    import pexpect
except ImportError:  # pragma: no cover - reported at runtime with a hint
    pexpect = None  # type: ignore[assignment]

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - Python 3.9/3.10 fallback
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

__version__ = "2.0.0"
__author__ = "Magnus Frödell"
__license__ = "Cisco Sample Code License, Version 1.1"
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."

DEFAULT_CONFIG_PATH = "/etc/esa-deploy/config.toml"
CONFIG_ENV_VAR = "ESA_DEPLOY_CONFIG"
PFX_PASSWORD_ENV_VAR = "ESA_DEPLOY_PFX_PASSWORD"  # only visible to the openssl child
DEFAULT_LIVE_DIR = "/etc/letsencrypt/live"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG = 2

LOGGER = logging.getLogger("esa_deploy")


# =============================================================================
# Errors
# =============================================================================

class ConfigError(Exception):
    """Configuration or usage problem. Exit code 2."""


class DeployError(Exception):
    """A deployment step failed for one target. Exit code 1."""


EsaCertImportError = DeployError  # name kept from v1 for anyone importing it


# =============================================================================
# Secret redaction and logging
# =============================================================================

class SecretRedactor:
    """Replaces registered secrets with ****** in any text passed through it."""

    MASK = "******"
    MIN_LENGTH = 4   # shorter strings would mask fragments of ordinary words

    def __init__(self) -> None:
        self._secrets: list[str] = []

    def add(self, secret: Optional[str]) -> None:
        if secret and len(secret) >= self.MIN_LENGTH and secret not in self._secrets:
            self._secrets.append(secret)
            # Longest first so that a secret that contains another is masked whole.
            self._secrets.sort(key=len, reverse=True)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, self.MASK)
        return text


REDACTOR = SecretRedactor()


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return REDACTOR.redact(super().format(record))


class RedactingWriter:
    """File-like wrapper used as pexpect `logfile_read` for session transcripts."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle

    def write(self, data: Any) -> int:
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        self._handle.write(REDACTOR.redact(data))
        return len(data)

    def flush(self) -> None:
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()


class _MaxLevelFilter(logging.Filter):
    def __init__(self, max_level: int) -> None:
        super().__init__()
        self.max_level = max_level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno <= self.max_level


def configure_logging(verbose: bool = False, quiet: bool = False,
                      log_file: Optional[str] = None) -> None:
    """
    INFO/DEBUG go to stdout, WARNING and above to stderr.

    Certbot logs everything a hook writes on stderr as an error, so keeping
    routine messages on stdout means certbot's log only shows real problems.
    """
    level = logging.DEBUG if verbose else logging.INFO
    formatter = RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    if not quiet:
        out = logging.StreamHandler(sys.stdout)
        out.setLevel(level)
        out.addFilter(_MaxLevelFilter(logging.INFO))
        out.setFormatter(formatter)
        root.addHandler(out)

    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    err.setFormatter(formatter)
    root.addHandler(err)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
        try:
            os.chmod(log_file, 0o600)
        except OSError:
            pass


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class TargetConfig:
    """One appliance to deploy to. Built from [defaults] merged with a [[targets]] table."""

    name: str
    host: str
    target_domains: list[str]
    pfx_password: str

    # SSH / SCP
    port: int = 22
    user: str = "admin"
    auth: str = "key"                       # "key" (recommended) or "password"
    password: Optional[str] = None          # only used with auth = "password"
    identity_file: Optional[str] = None
    known_hosts_file: Optional[str] = None
    strict_host_key: bool = True            # False -> StrictHostKeyChecking=accept-new
    ssh_extra_options: list[str] = field(default_factory=list)  # extra "-o" values
    scp_legacy: str = "auto"                # "auto" | "yes" | "no"  (scp -O)
    connect_timeout: int = 20
    cli_timeout: int = 90
    commit_timeout: int = 180

    # Certificate profile
    profile_name: str = "lets_encrypt_mail"
    remote_pfx_path: str = "/configuration/esacertpfx"
    pfx_legacy: bool = False                # openssl pkcs12 -legacy (older AsyncOS)
    cleanup_remote_pfx: bool = True
    commit_comment: str = ""
    lineage: Optional[str] = None           # used by --reconcile / --force

    # Verification
    verify: list[str] = field(default_factory=list)   # "host:port[:tls|starttls]"
    verify_strict: bool = False
    verify_timeout: int = 15
    verify_retries: int = 3
    verify_retry_delay: int = 10

    # Clustered appliances (best effort, see README)
    cluster_mode: str = ""                  # "" | "cluster" | "group" | "machine"
    cluster_name: str = ""
    cluster_level_answer: str = ""

    def lineage_path(self) -> str:
        return self.lineage or os.path.join(DEFAULT_LIVE_DIR, self.target_domains[0])


_TARGET_FIELD_TYPES: dict[str, type] = {f.name: f.type for f in fields(TargetConfig)}  # type: ignore[misc]
_EXTRA_INPUT_KEYS = {"target_domain", "password_file", "pfx_password_file"}
_ALLOWED_KEYS = set(_TARGET_FIELD_TYPES) | _EXTRA_INPUT_KEYS
_LIST_KEYS = {"target_domains", "verify", "ssh_extra_options"}
_INT_KEYS = {"port", "connect_timeout", "cli_timeout", "commit_timeout", "verify_timeout",
             "verify_retries", "verify_retry_delay"}
_BOOL_KEYS = {"strict_host_key", "pfx_legacy", "cleanup_remote_pfx", "verify_strict"}


def _warn_if_readable_by_others(path: str, what: str) -> None:
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return
    if mode & 0o077:
        LOGGER.warning("%s %s is readable by group/others (mode %o); chmod 600 recommended.",
                       what, path, mode)


def _read_secret_file(path: str, where: str, key: str) -> str:
    if not os.path.isabs(path):
        raise ConfigError(f"{where}: {key} must be an absolute path (got {path!r})")
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.read().rstrip("\r\n")
    except OSError as exc:
        raise ConfigError(f"{where}: cannot read {key} {path}: {exc}") from exc
    if not value:
        raise ConfigError(f"{where}: {key} {path} is empty")
    _warn_if_readable_by_others(path, "Secret file")
    return value


def _coerce(where: str, key: str, value: Any) -> Any:
    if key in _LIST_KEYS:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where}: {key} must be a list of strings")
        return [v.strip() for v in value if v.strip()]
    if key in _INT_KEYS:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where}: {key} must be an integer")
        if value < 0:
            raise ConfigError(f"{where}: {key} must not be negative")
        return value
    if key in _BOOL_KEYS:
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in ("true", "yes", "1"):
                return True
            if lowered in ("false", "no", "0"):
                return False
        if not isinstance(value, bool):
            raise ConfigError(f"{where}: {key} must be true or false")
        return value
    if not isinstance(value, str):
        raise ConfigError(f"{where}: {key} must be a string")
    return value.strip()


def build_target(raw: dict[str, Any], where: str) -> TargetConfig:
    """Validate one merged target table and turn it into a TargetConfig."""
    unknown = sorted(set(raw) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(unknown)}. "
                          f"Allowed: {', '.join(sorted(_ALLOWED_KEYS))}")

    values: dict[str, Any] = {}
    for key, value in raw.items():
        values[key] = _coerce(where, key, value)

    domains = list(values.get("target_domains", []))
    single = values.pop("target_domain", None)
    if single:
        domains.append(single)
    values["target_domains"] = [d.lower().rstrip(".") for d in domains]

    if values.pop("password_file", None) is not None:
        values["password"] = _read_secret_file(raw["password_file"], where, "password_file")
    if values.pop("pfx_password_file", None) is not None:
        values["pfx_password"] = _read_secret_file(raw["pfx_password_file"], where, "pfx_password_file")

    for key in ("host", "target_domains", "pfx_password"):
        if not values.get(key):
            hint = " (pfx_password or pfx_password_file)" if key == "pfx_password" else ""
            raise ConfigError(f"{where}: {key} is required{hint}")
    values.setdefault("name", values["host"])

    if values.get("auth", "key") not in ("key", "password"):
        raise ConfigError(f"{where}: auth must be \"key\" or \"password\"")
    if values.get("auth") == "password" and not values.get("password"):
        raise ConfigError(f"{where}: auth = \"password\" requires password or password_file")
    if values.get("scp_legacy", "auto") not in ("auto", "yes", "no"):
        raise ConfigError(f"{where}: scp_legacy must be \"auto\", \"yes\" or \"no\"")
    if values.get("cluster_mode", "") not in ("", "cluster", "group", "machine"):
        raise ConfigError(f"{where}: cluster_mode must be \"\", \"cluster\", \"group\" or \"machine\"")
    if values.get("cluster_mode") == "group" and not values.get("cluster_name"):
        raise ConfigError(f"{where}: cluster_mode = \"group\" requires cluster_name")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", values.get("profile_name", "lets_encrypt_mail")):
        raise ConfigError(f"{where}: profile_name may only contain letters, digits, _ and -")
    basename = os.path.basename(values.get("remote_pfx_path", "/configuration/esacertpfx"))
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", basename):
        raise ConfigError(f"{where}: remote_pfx_path basename may only contain letters, digits, _ . -")
    for spec in values.get("verify", []):
        parse_verify_endpoint(spec, where)

    for key in ("pfx_password", "password"):
        REDACTOR.add(values.get(key))
    if len(values["pfx_password"]) < 8:
        LOGGER.warning("%s: pfx_password is shorter than 8 characters.", where)

    return TargetConfig(**values)


def load_config_file(path: str) -> list[TargetConfig]:
    if tomllib is None:
        raise ConfigError("TOML support is missing: use Python 3.11+ or install 'tomli' "
                          "(apt-get install python3-tomli / pip install tomli)")
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except Exception as exc:  # tomllib.TOMLDecodeError (name differs between tomllib/tomli)
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    _warn_if_readable_by_others(path, "Config file")

    defaults = data.get("defaults", {})
    targets = data.get("targets", [])
    if not isinstance(defaults, dict):
        raise ConfigError(f"{path}: [defaults] must be a table")
    if not isinstance(targets, list) or not targets or not all(isinstance(t, dict) for t in targets):
        raise ConfigError(f"{path}: at least one [[targets]] table is required")
    unexpected = sorted(set(data) - {"defaults", "targets"})
    if unexpected:
        raise ConfigError(f"{path}: unexpected top-level key(s) {', '.join(unexpected)}")

    # Keys that come in two forms: whichever form the target table uses wins over
    # the other form from [defaults].
    alternatives = (("pfx_password", "pfx_password_file"), ("password", "password_file"),
                    ("target_domains", "target_domain"))

    result: list[TargetConfig] = []
    for index, table in enumerate(targets, start=1):
        merged = dict(defaults)
        for one, other in alternatives:
            if one in table and other not in table:
                merged.pop(other, None)
            elif other in table and one not in table:
                merged.pop(one, None)
        merged.update(table)
        result.append(build_target(merged, f"{path} targets[{index}]"))

    names = [t.name for t in result]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ConfigError(f"{path}: duplicate target name(s) {', '.join(duplicates)}")
    return result


def load_legacy_env_config() -> list[TargetConfig]:
    """v1-compatible configuration from ESA_* environment variables (single target)."""
    env = os.environ
    missing = [v for v in ("ESA_HOST", "ESA_TARGET_DOMAIN", "ESA_PFX_PASSWORD") if not env.get(v)]
    if missing:
        raise ConfigError("legacy environment configuration requires " + ", ".join(missing))
    try:
        port = int(env.get("ESA_SSH_PORT", "22"))
    except ValueError:
        raise ConfigError(f"ESA_SSH_PORT must be an integer (got {env.get('ESA_SSH_PORT')!r})") from None
    raw: dict[str, Any] = {
        "host": env["ESA_HOST"],
        "target_domain": env["ESA_TARGET_DOMAIN"],
        "pfx_password": env["ESA_PFX_PASSWORD"],
        "port": port,
        "user": env.get("ESA_USER", "admin"),
        "profile_name": env.get("ESA_CERT_PROFILE_NAME", "lets_encrypt_mail"),
        "remote_pfx_path": env.get("ESA_REMOTE_PFX_PATH", "/configuration/esacertpfx"),
    }
    if env.get("ESA_USE_PASSWORD", "false").lower() == "true":
        raw["auth"] = "password"
        raw["password"] = env.get("ESA_PASSWORD")
    LOGGER.warning("Using legacy ESA_* environment configuration; please migrate to %s.",
                   DEFAULT_CONFIG_PATH)
    return [build_target(raw, "environment")]


def load_targets(config_path: Optional[str]) -> list[TargetConfig]:
    explicit = bool(config_path)
    path = config_path or os.environ.get(CONFIG_ENV_VAR) or DEFAULT_CONFIG_PATH
    if os.path.exists(path):
        LOGGER.debug("Loading configuration from %s", path)
        return load_config_file(path)
    if not explicit and os.environ.get("ESA_HOST"):
        return load_legacy_env_config()
    raise ConfigError(f"config file not found: {path} (create it from config.example.toml, "
                      f"pass --config, or set {CONFIG_ENV_VAR})")


def select_targets(targets: list[TargetConfig], names: list[str]) -> list[TargetConfig]:
    if not names:
        return targets
    by_name = {t.name: t for t in targets}
    unknown = [n for n in names if n not in by_name]
    if unknown:
        raise ConfigError(f"unknown target(s) {', '.join(unknown)}; "
                          f"configured: {', '.join(by_name)}")
    return [by_name[n] for n in names]


def describe_targets(targets: list[TargetConfig]) -> str:
    lines = []
    for t in targets:
        lines.append(f"[{t.name}]")
        for f in fields(TargetConfig):
            value = getattr(t, f.name)
            if f.name in ("pfx_password", "password"):
                value = REDACTOR.MASK if value else None
            lines.append(f"  {f.name} = {value!r}")
    return "\n".join(lines)


# =============================================================================
# Certbot context
# =============================================================================

@dataclass(frozen=True)
class CertbotContext:
    """RENEWED_LINEAGE / RENEWED_DOMAINS as provided by certbot to deploy-hooks."""

    renewed_lineage: str
    renewed_domains: list[str]

    @staticmethod
    def from_env() -> "CertbotContext":
        lineage = os.environ.get("RENEWED_LINEAGE")
        domains = os.environ.get("RENEWED_DOMAINS")
        if not lineage or not domains:
            raise ConfigError(
                "RENEWED_LINEAGE and/or RENEWED_DOMAINS are not set. This script is meant to be "
                "run by certbot as a deploy-hook; for manual runs use --lineage/--domains, "
                "--force or --reconcile.")
        return CertbotContext(lineage, domains.split())


def domain_covered(target_domains: list[str], renewed_domains: list[str]) -> bool:
    """True if any target domain is covered by the renewed certificate (exact or wildcard)."""
    renewed = [d.lower().rstrip(".") for d in renewed_domains]
    for target in (d.lower().rstrip(".") for d in target_domains):
        for name in renewed:
            if name == target:
                return True
            if name.startswith("*.") and "." in target and target.split(".", 1)[1] == name[2:]:
                return True
    return False


# =============================================================================
# Subprocess helper
# =============================================================================

def _one_line(text: Any, limit: int = 600) -> str:
    """Collapse (redacted) multi-line tool output into one log-friendly line."""
    if not isinstance(text, str):
        text = ""
    lines = [line.strip() for line in REDACTOR.redact(text).splitlines() if line.strip()]
    return " | ".join(lines)[-limit:]


def run_subprocess(cmd: list[str], *, env: Optional[dict[str, str]] = None,
                   timeout: Optional[int] = None) -> subprocess.CompletedProcess:
    """Run a command, log its output (redacted), raise DeployError on failure."""
    LOGGER.debug("Executing: %s", " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise DeployError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DeployError(f"{cmd[0]} timed out after {timeout}s") from exc
    if proc.stdout.strip():
        LOGGER.debug("%s stdout: %s", cmd[0], proc.stdout.strip())
    if proc.returncode != 0:
        raise DeployError(f"{cmd[0]} failed with exit status {proc.returncode}: "
                          f"{_one_line(proc.stderr or proc.stdout)}")
    if proc.stderr.strip():
        LOGGER.debug("%s stderr: %s", cmd[0], proc.stderr.strip())
    return proc


# =============================================================================
# PKI helpers
# =============================================================================

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"


def split_pem_certificates(text: str) -> list[str]:
    """Return the PEM blocks of a (full)chain file, in order."""
    blocks = []
    for chunk in text.split(_PEM_BEGIN)[1:]:
        end = chunk.find("-----END CERTIFICATE-----")
        if end == -1:
            raise DeployError("malformed PEM: BEGIN without END CERTIFICATE")
        blocks.append(_PEM_BEGIN + chunk[:end] + "-----END CERTIFICATE-----\n")
    return blocks


def ensure_chain(lineage: str, workdir: str) -> str:
    """
    Return a path to the intermediate chain (CA certificates only).

    Certbot always writes chain.pem; if it is missing, the chain is derived
    from fullchain.pem by dropping the leaf and written into `workdir`
    (never into certbot's own directory).
    """
    chain_path = os.path.join(lineage, "chain.pem")
    if os.path.exists(chain_path):
        return chain_path
    fullchain_path = os.path.join(lineage, "fullchain.pem")
    if not os.path.exists(fullchain_path):
        raise DeployError(f"neither chain.pem nor fullchain.pem exists in {lineage}")
    with open(fullchain_path, encoding="utf-8") as handle:
        blocks = split_pem_certificates(handle.read())
    if len(blocks) < 2:
        raise DeployError("fullchain.pem does not contain any intermediate certificate")
    derived = os.path.join(workdir, "chain.pem")
    with open(derived, "w", encoding="utf-8") as handle:
        handle.write("".join(blocks[1:]))
    LOGGER.info("chain.pem missing in lineage; derived %d intermediate(s) from fullchain.pem",
                len(blocks) - 1)
    return derived


def build_pfx(lineage: str, pfx_password: str, workdir: str, legacy: bool = False) -> str:
    """Build esacert.pfx (leaf + chain + key) in workdir. The password is passed via the environment."""
    cert_path = os.path.join(lineage, "cert.pem")
    key_path = os.path.join(lineage, "privkey.pem")
    chain_path = ensure_chain(lineage, workdir)
    for path in (cert_path, key_path, chain_path):
        if not os.path.exists(path):
            raise DeployError(f"required file does not exist: {path}")

    pfx_path = os.path.join(workdir, "esacert.pfx")
    cmd = [
        "openssl", "pkcs12", "-export",
        "-out", pfx_path,
        "-inkey", key_path,
        "-in", cert_path,
        "-certfile", chain_path,
        "-passout", f"env:{PFX_PASSWORD_ENV_VAR}",
    ]
    if legacy:
        cmd.append("-legacy")
    env = dict(os.environ)
    env[PFX_PASSWORD_ENV_VAR] = pfx_password
    LOGGER.info("Building PKCS#12 bundle from %s", lineage)
    run_subprocess(cmd, env=env, timeout=60)
    os.chmod(pfx_path, 0o600)
    return pfx_path


def local_cert_fingerprint(cert_pem_path: str) -> str:
    """SHA-256 fingerprint (hex) of the first certificate in a PEM file."""
    with open(cert_pem_path, encoding="utf-8") as handle:
        blocks = split_pem_certificates(handle.read())
    if not blocks:
        raise DeployError(f"no certificate found in {cert_pem_path}")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(blocks[0])).hexdigest()


# =============================================================================
# SSH / SCP transport
# =============================================================================

_OPENSSH_VERSION: Optional[tuple[int, int]] = None


def openssh_version() -> Optional[tuple[int, int]]:
    global _OPENSSH_VERSION
    if _OPENSSH_VERSION is None:
        try:
            proc = subprocess.run(["ssh", "-V"], capture_output=True, text=True, timeout=10)
            match = re.search(r"OpenSSH_(\d+)\.(\d+)", proc.stderr + proc.stdout)
            _OPENSSH_VERSION = (int(match.group(1)), int(match.group(2))) if match else (0, 0)
        except (OSError, subprocess.TimeoutExpired):
            _OPENSSH_VERSION = (0, 0)
    return _OPENSSH_VERSION


class SshTransport:
    """Builds hardened ssh/scp command lines for a target and performs uploads."""

    def __init__(self, target: TargetConfig) -> None:
        self.target = target

    def _options(self) -> list[str]:
        t = self.target
        opts = [
            "-o", f"ConnectTimeout={t.connect_timeout}",
            "-o", f"StrictHostKeyChecking={'yes' if t.strict_host_key else 'accept-new'}",
        ]
        if t.known_hosts_file:
            opts += ["-o", f"UserKnownHostsFile={t.known_hosts_file}"]
        if t.auth == "key":
            opts += ["-o", "BatchMode=yes"]
            if t.identity_file:
                opts += ["-i", t.identity_file, "-o", "IdentitiesOnly=yes"]
        else:
            opts += [
                "-o", "BatchMode=no",
                "-o", "PreferredAuthentications=keyboard-interactive,password",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
            ]
        for extra in t.ssh_extra_options:
            opts += ["-o", extra]
        return opts

    def ssh_argv(self) -> list[str]:
        t = self.target
        return ["ssh", "-p", str(t.port)] + self._options() + [f"{t.user}@{t.host}"]

    def _scp_legacy_flag(self) -> bool:
        setting = self.target.scp_legacy
        if setting == "yes":
            return True
        if setting == "no":
            return False
        version = openssh_version() or (0, 0)
        return version >= (8, 7)   # -O exists since OpenSSH 8.7; SFTP became the default in 9.0

    def scp_argv(self, local_path: str, remote_path: str) -> list[str]:
        t = self.target
        argv = ["scp"]
        if self._scp_legacy_flag():
            argv.append("-O")
        argv += ["-P", str(t.port)] + self._options()
        argv += [local_path, f"{t.user}@{t.host}:{remote_path}"]
        return argv

    def spawn_shell(self) -> "pexpect.spawn":
        argv = self.ssh_argv()
        LOGGER.info("[%s] Opening SSH session: %s", self.target.name, " ".join(argv))
        return pexpect.spawn(argv[0], argv[1:], encoding="utf-8", codec_errors="replace",
                             timeout=self.target.cli_timeout)

    def upload(self, local_path: str, remote_path: str) -> None:
        t = self.target
        argv = self.scp_argv(local_path, remote_path)
        LOGGER.info("[%s] Uploading %s to %s", t.name, os.path.basename(local_path), remote_path)
        if t.auth == "key":
            run_subprocess(argv, timeout=t.connect_timeout + t.cli_timeout)
            return
        # Password authentication: scp needs the password on its terminal.
        child = pexpect.spawn(argv[0], argv[1:], encoding="utf-8", codec_errors="replace",
                              timeout=t.connect_timeout + t.cli_timeout)
        try:
            idx = child.expect([r"[Pp]assword:\s*", pexpect.EOF])
            if idx == 0:
                child.sendline(t.password)
                idx = child.expect([pexpect.EOF, r"[Pp]assword:\s*", r"Permission denied[^\r\n]*"])
                if idx != 0:
                    raise DeployError("appliance rejected the password (scp)")
        except pexpect.TIMEOUT as exc:
            raise DeployError(f"scp timed out; last output: {_one_line(child.before)}") from exc
        finally:
            child.close()
        if child.exitstatus != 0:
            raise DeployError(f"scp failed with exit status {child.exitstatus}: {_one_line(child.before)}")


# =============================================================================
# AsyncOS CLI automation (pexpect)
# =============================================================================

def _rx(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.DOTALL)


class EsaSession:
    """
    Drives one SSH session to an appliance.

    Simplified transcript this class is written against (AsyncOS 16.0.3):

        esa.example.com> certconfig
        []> certificate
        []> import
        Enter a name for this certificate profile:
        > lets_encrypt_mail
        [maybe] Certificate profile "lets_encrypt_mail" already exists. Do you want to
                overwrite with this new one? [N]> Y
        Enter the name of the file on machine "esa.example.com" to import:
        []> esacertpfx
        [maybe] Do you want to check if Common Name or SAN:dNSName or both are in Fully
                Qualified Domain Name(FQDN) format ? [N]> N
        Enter pass phrase for PKCS#12 file: ******
        [maybe] (FQDN question again)
        []>            <- ENTER twice to leave certconfig
        esa.example.com> commit
        Please enter some comments describing your changes:
        []> ...
        Do you want to save the current configuration for rollback? [Y]> Y
        Changes committed: ...
        esa.example.com> exit
    """

    # Login / prompt handling
    PROMPT_LEARN = _rx(r"(?:^|\r?\n)([^\r\n]{1,120}?)> $")
    PASSWORD_PROMPT = _rx(r"[Pp]assword:\s*")
    PERMISSION_DENIED = _rx(r"Permission denied[^\r\n]*")

    # certconfig
    CERTCONFIG_MENU = _rx(r"\[\]> ?")
    PROFILE_NAME_PROMPT = _rx(r"Enter a name for this certificate profile:")
    OVERWRITE_QUESTION = _rx(r"[Cc]ertificate profile \"[^\"]*\" already exists\..*?"
                             r"overwrite with this new one\? \[N\]> ?")
    FILE_PROMPT = _rx(r"Enter the name of the file on machine[^\r\n]* to import:")
    FQDN_QUESTION = _rx(r"check if Common Name.*?FQDN.*?\? \[N\]> ?")
    PASSPHRASE_PROMPT = _rx(r"[Pp]ass ?phrase[^\r\n]*")
    IMPORT_ERROR = _rx(r"(?:[Ii]nvalid (?:pass ?phrase|password)[^\r\n]*"
                       r"|[Ii]ncorrect (?:pass ?phrase|password)[^\r\n]*"
                       r"|[Ff]ailed to (?:import|read|open|parse|load)[^\r\n]*"
                       r"|(?:[Cc]ould not|[Cc]annot|[Uu]nable to) (?:import|read|open|parse|find|load)[^\r\n]*"
                       r"|[Nn]o such file[^\r\n]*"
                       r"|(?:file|File)[^\r\n]{0,60}does not exist[^\r\n]*"
                       r"|[Ss]ymbols are not allowed[^\r\n]*"
                       r"|[Ii]nvalid (?:name|file)[^\r\n]*"
                       r"|[Ee]rror:[^\r\n]*)")

    # commit
    NO_DATA_TO_COMMIT = _rx(r"There is no data to commit\.")
    COMMENTS_PROMPT = _rx(r"Please enter some comments describing your changes:")
    ROLLBACK_QUESTION = _rx(r"rollback\?\s*\[Y\]> ?")
    CHANGES_COMMITTED = _rx(r"Changes committed[^\r\n]*")
    COMMIT_ERROR = _rx(r"(?:[Ee]rror:[^\r\n]*|[Ff]ailed[^\r\n]*|[Ii]nvalid[^\r\n]*)")

    # cluster
    CLUSTER_LEVEL_QUESTION = _rx(r"(?:[Cc]luster|[Gg]roup|[Mm]achine) level[^\r\n]*\[[^\]\r\n]*\]> ?")
    CLUSTERMODE_MENU = _rx(r"Choose the mode to modify:.*?\[[^\]]*\]> ?")
    CLUSTERMODE_CHOOSE_NAME = _rx(r"Choose the (?:machine|group) to modify:(.*?)\[[^\]]*\]> ?")

    # logout
    YES_NO_QUESTION = _rx(r"\? \[[YN]\]> ?$")

    def __init__(self, target: TargetConfig,
                 spawn_fn: Optional[Callable[[], "pexpect.spawn"]] = None,
                 transcript: Optional[str] = None) -> None:
        self.target = target
        self._spawn_fn = spawn_fn or SshTransport(target).spawn_shell
        self._transcript_path = transcript
        self._transcript: Optional[RedactingWriter] = None
        self.child: Optional["pexpect.spawn"] = None
        self.prompt_text: str = ""
        self.main_prompt: "re.Pattern[str]" = _rx(r"(?!x)x")  # matches nothing until learned

    # ------------------------------------------------------------------ lifecycle

    def __enter__(self) -> "EsaSession":
        self.open()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def open(self) -> None:
        self.child = self._spawn_fn()
        if self._transcript_path:
            handle = open(self._transcript_path, "a", encoding="utf-8")
            try:
                os.chmod(self._transcript_path, 0o600)
            except OSError:
                pass
            self._transcript = RedactingWriter(handle)
            self._transcript.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                                   f"session to {self.target.host} =====\n")
            self.child.logfile_read = self._transcript
        self._login()

    def close(self) -> None:
        if self.child is not None:
            try:
                self.child.close(force=True)
            except Exception:  # pragma: no cover - best effort
                LOGGER.debug("Error closing session; ignoring.", exc_info=True)
            LOGGER.debug("[%s] Session closed (exitstatus=%s, signalstatus=%s)", self.target.name,
                         self.child.exitstatus, self.child.signalstatus)
            self.child = None
        if self._transcript is not None:
            self._transcript.close()
            self._transcript = None

    # ------------------------------------------------------------------ primitives

    def _tail(self, size: int = 800) -> str:
        assert self.child is not None
        before = self.child.before if isinstance(self.child.before, str) else ""
        return REDACTOR.redact(before[-size:]).strip()

    def _expect(self, patterns: list[Any], what: str, timeout: Optional[int] = None) -> int:
        """child.expect with DeployError instead of pexpect exceptions, including the last output."""
        assert self.child is not None
        timeout = timeout or self.target.cli_timeout
        try:
            return self.child.expect(patterns, timeout=timeout)
        except pexpect.TIMEOUT as exc:
            raise DeployError(f"timed out after {timeout}s waiting for {what}. "
                              f"Last output from appliance:\n{self._tail()}") from exc
        except pexpect.EOF as exc:
            raise DeployError(f"session ended unexpectedly while waiting for {what}. "
                              f"Last output from appliance:\n{self._tail()}") from exc

    def _sendline(self, text: str, secret: bool = False) -> None:
        assert self.child is not None
        LOGGER.debug("[%s] >> %s", self.target.name, REDACTOR.MASK if secret else text)
        self.child.sendline(text)

    def _drain(self, pattern: "re.Pattern[str]", wait: float = 1.0) -> None:
        """Consume a trailing prompt token if it arrives within `wait` seconds (tolerates absence)."""
        assert self.child is not None
        self.child.expect([pattern, pexpect.TIMEOUT], timeout=wait)

    def _learn_prompt(self, what: str, timeout: Optional[int] = None) -> None:
        """Wait for the main prompt at the end of the output and remember it for exact matching."""
        assert self.child is not None
        self._expect([self.PROMPT_LEARN], what, timeout)
        self.prompt_text = self.child.match.group(1).strip()
        self.main_prompt = _rx(r"(?:^|\r?\n)" + re.escape(self.prompt_text) + r"> ")
        LOGGER.debug("[%s] Main prompt is %r", self.target.name, self.prompt_text + ">")

    # ------------------------------------------------------------------ login

    def _login(self) -> None:
        t = self.target
        if t.auth == "password":
            idx = self._expect([self.PASSWORD_PROMPT, self.PROMPT_LEARN], "password prompt",
                               t.connect_timeout + t.cli_timeout)
            if idx == 0:
                self._sendline(t.password or "", secret=True)
                idx = self._expect([self.PROMPT_LEARN, self.PASSWORD_PROMPT, self.PERMISSION_DENIED],
                                   "main prompt after password")
                if idx != 0:
                    raise DeployError("appliance rejected the password")
            self.prompt_text = self.child.match.group(1).strip()  # type: ignore[union-attr]
            self.main_prompt = _rx(r"(?:^|\r?\n)" + re.escape(self.prompt_text) + r"> ")
        else:
            self._learn_prompt("main prompt after login (key authentication)",
                               t.connect_timeout + t.cli_timeout)
        LOGGER.info("[%s] Logged in; prompt is %r", t.name, self.prompt_text + ">")

    # ------------------------------------------------------------------ cluster

    def set_cluster_mode(self) -> None:
        t = self.target
        if not t.cluster_mode:
            return
        assert self.child is not None
        command = "clustermode " + t.cluster_mode
        name = t.cluster_name or (t.host if t.cluster_mode == "machine" else "")
        if t.cluster_mode in ("group", "machine") and name:
            command += " " + name
        LOGGER.info("[%s] Setting cluster configuration mode: %s", t.name, command)
        self._sendline(command)
        idx = self._expect([self.CLUSTERMODE_MENU, self.PROMPT_LEARN], "clustermode response")
        if idx == 0:
            # Interactive fallback: numbered menu.
            self._sendline({"cluster": "1", "group": "2", "machine": "3"}[t.cluster_mode])
            if t.cluster_mode != "cluster":
                idx = self._expect([self.CLUSTERMODE_CHOOSE_NAME, self.PROMPT_LEARN],
                                   "clustermode name selection")
                if idx == 0:
                    listing = self.child.match.group(1)
                    choices = re.findall(r"(\d+)\.\s+(\S+)", listing)
                    number = next((n for n, candidate in choices
                                   if candidate.lower().rstrip(".") == name.lower().rstrip(".")), None)
                    if number is None:
                        raise DeployError(f"{name!r} not found in clustermode selection: "
                                          f"{[c for _, c in choices]}")
                    self._sendline(number)
                    self._expect([self.PROMPT_LEARN], "prompt after clustermode")
            else:
                self._expect([self.PROMPT_LEARN], "prompt after clustermode")
        self.prompt_text = self.child.match.group(1).strip()
        self.main_prompt = _rx(r"(?:^|\r?\n)" + re.escape(self.prompt_text) + r"> ")
        response = self._tail(400)
        if response:
            LOGGER.info("[%s] clustermode response: %s", t.name, " ".join(response.split()))
        LOGGER.debug("[%s] Main prompt is now %r", t.name, self.prompt_text + ">")

    def _answer_cluster_level_question(self) -> None:
        assert self.child is not None
        question = " ".join(REDACTOR.redact(self.child.after).split())
        if not self.target.cluster_level_answer:
            raise DeployError(f"appliance asked a cluster-level question that this script does not "
                              f"answer automatically: {question!r}. Set cluster_level_answer for "
                              f"this target (and consider cluster_mode) after checking the prompt "
                              f"manually.")
        LOGGER.info("[%s] Cluster-level question %r; answering %r", self.target.name, question,
                    self.target.cluster_level_answer)
        self._sendline(self.target.cluster_level_answer)

    # ------------------------------------------------------------------ certconfig

    def import_pfx(self, remote_basename: str) -> None:
        t = self.target
        assert self.child is not None
        LOGGER.info("[%s] Importing %s into certificate profile %r", t.name, remote_basename,
                    t.profile_name)

        self._sendline("certconfig")
        idx = self._expect([self.CERTCONFIG_MENU, self.CLUSTER_LEVEL_QUESTION], "certconfig menu")
        if idx == 1:
            self._answer_cluster_level_question()
            self._expect([self.CERTCONFIG_MENU], "certconfig menu")

        self._sendline("certificate")
        self._expect([self.CERTCONFIG_MENU], "CERTIFICATE submenu")

        self._sendline("import")
        self._expect([self.PROFILE_NAME_PROMPT], "certificate profile name prompt")
        self._drain(_rx(r"> ?"))
        self._sendline(t.profile_name)

        idx = self._expect([self.OVERWRITE_QUESTION, self.FILE_PROMPT, self.IMPORT_ERROR],
                           "overwrite question or file name prompt")
        if idx == 0:
            LOGGER.info("[%s] Profile %r exists; overwriting.", t.name, t.profile_name)
            self._sendline("Y")
            idx = self._expect([self.FILE_PROMPT, self.IMPORT_ERROR], "file name prompt")
            if idx == 1:
                raise DeployError(f"appliance reported: {self._matched_text()}")
        elif idx == 2:
            raise DeployError(f"appliance rejected profile name {t.profile_name!r}: {self._matched_text()}")
        self._drain(self.CERTCONFIG_MENU)
        self._sendline(remote_basename)

        idx = self._expect([self.PASSPHRASE_PROMPT, self.FQDN_QUESTION, self.IMPORT_ERROR],
                           "PKCS#12 passphrase prompt")
        if idx == 1:
            LOGGER.info("[%s] FQDN check question before import; answering N.", t.name)
            self._sendline("N")
            idx = self._expect([self.PASSPHRASE_PROMPT, self.IMPORT_ERROR], "PKCS#12 passphrase prompt")
            if idx == 1:
                idx = 2
        if idx == 2:
            raise DeployError(f"appliance could not use {remote_basename!r}: {self._matched_text()}")
        self._sendline(t.pfx_password, secret=True)

        idx = self._expect([self.CERTCONFIG_MENU, self.FQDN_QUESTION, self.IMPORT_ERROR],
                           "CERTIFICATE menu after import")
        if idx == 1:
            LOGGER.info("[%s] FQDN check question after import; answering N.", t.name)
            self._sendline("N")
            idx = self._expect([self.CERTCONFIG_MENU, self.IMPORT_ERROR], "CERTIFICATE menu after import")
            if idx == 1:
                idx = 2
        if idx == 2:
            raise DeployError(f"import failed: {self._matched_text()}")
        LOGGER.info("[%s] Certificate profile %r imported.", t.name, t.profile_name)

    def _matched_text(self) -> str:
        assert self.child is not None
        return " ".join(REDACTOR.redact(self.child.after or "").split())

    def leave_certconfig(self) -> None:
        """ENTER on an empty line goes up one menu level; repeat until the main prompt appears."""
        for _ in range(5):
            self._sendline("")
            idx = self._expect([self.main_prompt, self.CERTCONFIG_MENU], "main prompt")
            if idx == 0:
                LOGGER.debug("[%s] Back at main prompt.", self.target.name)
                return
        raise DeployError("could not get back to the main prompt from certconfig")

    # ------------------------------------------------------------------ commit / logout

    def commit(self, comment: str) -> bool:
        """Run commit. Returns True if changes were committed, False for 'no data to commit'."""
        t = self.target
        LOGGER.info("[%s] Committing configuration.", t.name)
        self._sendline("commit")
        idx = self._expect([self.NO_DATA_TO_COMMIT, self.COMMENTS_PROMPT, self.CLUSTER_LEVEL_QUESTION],
                           "commit comments prompt")
        if idx == 2:
            self._answer_cluster_level_question()
            idx = self._expect([self.NO_DATA_TO_COMMIT, self.COMMENTS_PROMPT], "commit comments prompt")
        if idx == 0:
            LOGGER.info("[%s] Appliance reports there is no data to commit (no-op).", t.name)
            self._expect([self.main_prompt], "main prompt after commit")
            return False

        self._drain(self.CERTCONFIG_MENU)
        self._sendline(comment)
        idx = self._expect([self.ROLLBACK_QUESTION, self.CHANGES_COMMITTED, self.COMMIT_ERROR],
                           "rollback question or commit confirmation", t.commit_timeout)
        if idx == 0:
            self._sendline("Y")
            idx = self._expect([self.CHANGES_COMMITTED, self.COMMIT_ERROR], "commit confirmation",
                               t.commit_timeout)
            if idx == 1:
                idx = 2
        if idx == 2:
            raise DeployError(f"commit failed: {self._matched_text()}")
        committed_line = self._matched_text()
        self._expect([self.main_prompt], "main prompt after commit")
        LOGGER.info("[%s] %s", t.name, committed_line)
        return True

    def logout(self) -> None:
        assert self.child is not None
        self._sendline("exit")
        try:
            idx = self.child.expect([pexpect.EOF, self.YES_NO_QUESTION], timeout=15)
        except pexpect.TIMEOUT:
            LOGGER.warning("[%s] Appliance did not close the session after 'exit'; closing.",
                           self.target.name)
            return
        if idx == 1:
            LOGGER.warning("[%s] Appliance asked %r at logout; answering N.", self.target.name,
                           self._matched_text())
            self._sendline("N")
            try:
                self.child.expect(pexpect.EOF, timeout=15)
            except pexpect.TIMEOUT:
                pass
        LOGGER.info("[%s] Logged out.", self.target.name)


# =============================================================================
# Verification (what does the appliance actually serve?)
# =============================================================================

@dataclass(frozen=True)
class VerifyEndpoint:
    host: str
    port: int
    starttls: bool

    def __str__(self) -> str:
        return f"{self.host}:{self.port} ({'STARTTLS' if self.starttls else 'TLS'})"


def parse_verify_endpoint(spec: str, where: str = "verify") -> VerifyEndpoint:
    parts = spec.split(":")
    if len(parts) not in (2, 3) or not parts[0]:
        raise ConfigError(f"{where}: invalid verify endpoint {spec!r}; use host:port[:tls|starttls]")
    try:
        port = int(parts[1])
    except ValueError:
        raise ConfigError(f"{where}: invalid port in verify endpoint {spec!r}") from None
    if len(parts) == 3:
        mode = parts[2].strip().lower()
        if mode not in ("tls", "starttls"):
            raise ConfigError(f"{where}: verify endpoint mode must be tls or starttls ({spec!r})")
        starttls = mode == "starttls"
    else:
        starttls = port in (25, 587)
    return VerifyEndpoint(parts[0].strip(), port, starttls)


def fetch_served_certificate(endpoint: VerifyEndpoint, timeout: int) -> bytes:
    """Return the DER-encoded leaf certificate presented by the endpoint (no validation)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if endpoint.starttls:
        with smtplib.SMTP(endpoint.host, endpoint.port, timeout=timeout) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            der = smtp.sock.getpeercert(True)  # type: ignore[union-attr]
    else:
        with socket.create_connection((endpoint.host, endpoint.port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=endpoint.host) as tls:
                der = tls.getpeercert(True)
    if not der:
        raise DeployError(f"{endpoint} did not present a certificate")
    return der


def verify_target(target: TargetConfig, expected_fingerprint: str) -> list[tuple[VerifyEndpoint, str, str]]:
    """
    Probe every verify endpoint. Returns (endpoint, status, detail) with status
    "ok", "mismatch" or "error".
    """
    results = []
    for spec in target.verify:
        endpoint = parse_verify_endpoint(spec)
        try:
            served = hashlib.sha256(fetch_served_certificate(endpoint, target.verify_timeout)).hexdigest()
        except (OSError, ssl.SSLError, smtplib.SMTPException, DeployError) as exc:
            results.append((endpoint, "error", str(exc) or exc.__class__.__name__))
            continue
        if served == expected_fingerprint:
            results.append((endpoint, "ok", served[:16]))
        else:
            results.append((endpoint, "mismatch", served[:16]))
    return results


def verify_with_retries(target: TargetConfig, expected_fingerprint: str) -> bool:
    attempts = max(1, target.verify_retries)
    for attempt in range(1, attempts + 1):
        results = verify_target(target, expected_fingerprint)
        bad = [(e, s, d) for e, s, d in results if s != "ok"]
        for endpoint, status, detail in results:
            level = logging.INFO if status == "ok" else logging.WARNING
            LOGGER.log(level, "[%s] verify %s: %s (%s)", target.name, endpoint, status, detail)
        if not bad:
            return True
        if attempt < attempts:
            LOGGER.info("[%s] verification attempt %d/%d not yet successful; retrying in %ds",
                        target.name, attempt, attempts, target.verify_retry_delay)
            time.sleep(target.verify_retry_delay)
    return False


# =============================================================================
# Orchestration
# =============================================================================

def make_commit_comment(target: TargetConfig, fingerprint: str) -> str:
    if target.commit_comment:
        return target.commit_comment
    return f"esa_deploy {__version__}: imported {target.profile_name} sha256 {fingerprint[:16]}"


def deploy_target(target: TargetConfig, lineage: str, *, dry_run: bool = False,
                  transcript: Optional[str] = None,
                  transport_factory: Callable[[TargetConfig], SshTransport] = SshTransport,
                  spawn_fn: Optional[Callable[[], "pexpect.spawn"]] = None) -> None:
    """Deploy one lineage to one target. Raises DeployError on failure."""
    t = target
    LOGGER.info("[%s] Deploying %s to %s (profile %r)", t.name, lineage, t.host, t.profile_name)
    if not os.path.isdir(lineage):
        raise DeployError(f"lineage directory does not exist: {lineage}")

    workdir = tempfile.mkdtemp(prefix="esa_deploy_")   # created with mode 0700
    try:
        pfx_path = build_pfx(lineage, t.pfx_password, workdir, legacy=t.pfx_legacy)
        fingerprint = local_cert_fingerprint(os.path.join(lineage, "cert.pem"))
        LOGGER.info("[%s] Certificate SHA-256 fingerprint: %s", t.name, fingerprint)

        if dry_run:
            LOGGER.info("[%s] DRY RUN: would upload %s to %s and import it as %r on %s",
                        t.name, os.path.basename(pfx_path), t.remote_pfx_path, t.profile_name, t.host)
            return

        transport = transport_factory(t)
        transport.upload(pfx_path, t.remote_pfx_path)

        with EsaSession(t, spawn_fn=spawn_fn or transport.spawn_shell, transcript=transcript) as session:
            session.set_cluster_mode()
            session.import_pfx(os.path.basename(t.remote_pfx_path))
            session.leave_certconfig()
            session.commit(make_commit_comment(t, fingerprint))
            session.logout()

        if t.cleanup_remote_pfx:
            empty = os.path.join(workdir, "empty")
            with open(empty, "w", encoding="utf-8"):
                pass
            try:
                transport.upload(empty, t.remote_pfx_path)
                LOGGER.info("[%s] Overwrote %s on the appliance with an empty file.", t.name, t.remote_pfx_path)
            except DeployError as exc:
                LOGGER.warning("[%s] Could not overwrite remote PKCS#12 file: %s", t.name, exc)

        if t.verify:
            if verify_with_retries(t, fingerprint):
                LOGGER.info("[%s] Verification succeeded: appliance serves the new certificate.", t.name)
            elif t.verify_strict:
                raise DeployError("verification failed: appliance does not serve the new certificate "
                                  "on all verify endpoints (verify_strict = true)")
            else:
                LOGGER.warning("[%s] Verification did not succeed on all endpoints. Check that profile "
                               "%r is bound to the services behind those endpoints.", t.name, t.profile_name)
        LOGGER.info("[%s] Deployment completed successfully.", t.name)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def run_hook(targets: list[TargetConfig], context: CertbotContext, args: argparse.Namespace) -> int:
    LOGGER.info("Renewed lineage %s covers: %s", context.renewed_lineage, ", ".join(context.renewed_domains))
    matched = failed = 0
    for t in targets:
        if not domain_covered(t.target_domains, context.renewed_domains):
            LOGGER.info("[%s] Not covered by this certificate (%s); skipping.", t.name,
                        ", ".join(t.target_domains))
            continue
        matched += 1
        try:
            deploy_target(t, context.renewed_lineage, dry_run=args.dry_run, transcript=args.transcript)
        except DeployError as exc:
            failed += 1
            LOGGER.error("[%s] Deployment failed: %s", t.name, exc)
    if not matched:
        LOGGER.info("No configured target is covered by the renewed certificate; nothing to do.")
    return EXIT_FAILED if failed else EXIT_OK


def run_force(targets: list[TargetConfig], args: argparse.Namespace) -> int:
    failed = 0
    for t in targets:
        try:
            deploy_target(t, t.lineage_path(), dry_run=args.dry_run, transcript=args.transcript)
        except DeployError as exc:
            failed += 1
            LOGGER.error("[%s] Deployment failed: %s", t.name, exc)
    return EXIT_FAILED if failed else EXIT_OK


def _expected_fingerprint(target: TargetConfig) -> str:
    cert = os.path.join(target.lineage_path(), "cert.pem")
    if not os.path.exists(cert):
        raise DeployError(f"cert.pem not found in lineage {target.lineage_path()}; set 'lineage' for this target")
    return local_cert_fingerprint(cert)


def run_verify_only(targets: list[TargetConfig]) -> int:
    failed = 0
    for t in targets:
        if not t.verify:
            LOGGER.error("[%s] No verify endpoints configured.", t.name)
            failed += 1
            continue
        try:
            expected = _expected_fingerprint(t)
        except DeployError as exc:
            LOGGER.error("[%s] %s", t.name, exc)
            failed += 1
            continue
        for endpoint, status, detail in verify_target(t, expected):
            level = logging.INFO if status == "ok" else logging.ERROR
            LOGGER.log(level, "[%s] %s: %s (%s)", t.name, endpoint, status, detail)
            if status != "ok":
                failed += 1
    return EXIT_FAILED if failed else EXIT_OK


def run_reconcile(targets: list[TargetConfig], args: argparse.Namespace) -> int:
    """Deploy only where the appliance serves something other than the local lineage."""
    failed = 0
    for t in targets:
        if not t.verify:
            LOGGER.error("[%s] --reconcile requires verify endpoints for this target.", t.name)
            failed += 1
            continue
        try:
            expected = _expected_fingerprint(t)
        except DeployError as exc:
            LOGGER.error("[%s] %s", t.name, exc)
            failed += 1
            continue
        results = verify_target(t, expected)
        statuses = {s for _, s, _ in results}
        for endpoint, status, detail in results:
            LOGGER.log(logging.INFO if status == "ok" else logging.WARNING,
                       "[%s] %s: %s (%s)", t.name, endpoint, status, detail)
        if statuses == {"ok"}:
            LOGGER.info("[%s] Up to date; nothing to do.", t.name)
            continue
        if "mismatch" not in statuses:
            LOGGER.error("[%s] Could not determine the served certificate; not deploying.", t.name)
            failed += 1
            continue
        LOGGER.warning("[%s] Served certificate differs from %s; deploying.", t.name, t.lineage_path())
        try:
            deploy_target(t, t.lineage_path(), dry_run=args.dry_run, transcript=args.transcript)
        except DeployError as exc:
            failed += 1
            LOGGER.error("[%s] Deployment failed: %s", t.name, exc)
    return EXIT_FAILED if failed else EXIT_OK


# =============================================================================
# CLI
# =============================================================================

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="esa_deploy.py",
        description="Certbot deploy-hook that pushes a renewed certificate to Cisco Secure Email "
                    "Gateway (ESA/AsyncOS) appliances via SCP and certconfig.",
        epilog="Without mode flags the script behaves as a certbot deploy-hook and reads "
               "RENEWED_LINEAGE / RENEWED_DOMAINS from the environment.")
    parser.add_argument("--config", help=f"configuration file (default: ${CONFIG_ENV_VAR} or {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--target", action="append", default=[], metavar="NAME",
                        help="only act on this target (repeatable; default: all)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--force", action="store_true",
                      help="deploy each selected target's lineage now, regardless of certbot state")
    mode.add_argument("--reconcile", action="store_true",
                      help="deploy only if the appliance serves a different certificate than the lineage")
    mode.add_argument("--verify-only", action="store_true",
                      help="report what the appliance serves compared to the lineage; change nothing")
    mode.add_argument("--print-config", action="store_true",
                      help="print the effective configuration (secrets masked) and exit")
    parser.add_argument("--lineage", help="lineage directory (manual hook-mode test; overrides RENEWED_LINEAGE)")
    parser.add_argument("--domains", help="space-separated domains (manual hook-mode test; overrides RENEWED_DOMAINS)")
    parser.add_argument("--dry-run", action="store_true",
                        help="build the PKCS#12 and check the domain match but do not touch any appliance")
    parser.add_argument("--transcript", metavar="FILE",
                        help="append the (redacted) appliance CLI output to FILE for troubleshooting")
    parser.add_argument("--log-file", metavar="FILE", help="also write log messages to FILE")
    parser.add_argument("-v", "--verbose", action="store_true", help="DEBUG logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors (stderr)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if bool(args.lineage) != bool(args.domains):
        parser.error("--lineage and --domains must be given together")
    return args


def build_context_from_args(args: argparse.Namespace) -> CertbotContext:
    if args.lineage:
        LOGGER.info("Using lineage/domains from the command line.")
        return CertbotContext(args.lineage, args.domains.split())
    return CertbotContext.from_env()


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        configure_logging(verbose=args.verbose, quiet=args.quiet, log_file=args.log_file)
    except OSError as exc:
        print(f"esa_deploy: cannot set up logging: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    LOGGER.debug("esa_deploy %s starting", __version__)

    if pexpect is None:
        LOGGER.error("The 'pexpect' module is required (apt-get install python3-pexpect or pip install pexpect).")
        return EXIT_CONFIG

    try:
        targets = select_targets(load_targets(args.config), args.target)
        if args.print_config:
            print(describe_targets(targets))
            return EXIT_OK
        if args.verify_only:
            return run_verify_only(targets)
        if args.reconcile:
            return run_reconcile(targets, args)
        if args.force:
            return run_force(targets, args)
        return run_hook(targets, build_context_from_args(args), args)
    except ConfigError as exc:
        LOGGER.error("Configuration error: %s", exc)
        return EXIT_CONFIG
    except BrokenPipeError:      # e.g. --print-config | head
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return EXIT_OK
    except KeyboardInterrupt:
        LOGGER.error("Interrupted.")
        return EXIT_FAILED
    except Exception as exc:  # noqa: BLE001 - last resort, keep certbot informed
        LOGGER.error("Unexpected error: %s", exc, exc_info=True)
        return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
