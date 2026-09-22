# CiscoESA-Cert-Automation, automatic Let's Encrypt certificate deployment to Cisco Secure Email Gateway (ESA)

Cisco Secure Email Gateway (formerly the Email Security Appliance, ESA, running AsyncOS) has no
API for importing TLS certificates: a certificate profile can only be updated through the web
interface or the `certconfig` command in the CLI. Let's Encrypt certificates expire after 90 days
(and will get shorter), so keeping a gateway's SMTP listener and management interface on a
publicly trusted certificate means importing a new PKCS#12 bundle roughly every two months, by
hand, on every appliance. In practice that gets forgotten and the gateway ends up serving an
expired certificate.

`esa_deploy.py` closes that gap. It runs as a [certbot](https://certbot.eff.org/) deploy-hook:
every time certbot renews a certificate, the script builds a PKCS#12 bundle from the renewed
lineage, uploads it to each configured appliance with SCP, drives the `certconfig` dialogue over
SSH exactly as an administrator would (import or overwrite the profile, answer the FQDN questions,
supply the passphrase), commits, cleans up the uploaded bundle and finally checks what the
appliance actually serves on its TLS and STARTTLS endpoints. A `--reconcile` mode, run from a
systemd timer, repeats that check daily and redeploys if an appliance is ever found serving a
different certificate than the local lineage, so a single failed renewal run cannot silently turn
into an expired certificate.

Version 2 is a complete rewrite of the original single-target, environment-variable driven hook:
fail-fast configuration from a TOML file, multiple appliances, hardened SSH, secrets kept out of
command lines and logs, exact prompt matching with informative timeouts, verification,
reconciliation and a test suite that drives the whole dialogue against a fake AsyncOS CLI.

- **Technology stack:** Python 3.9+ standard library plus [`pexpect`](https://pexpect.readthedocs.io/)
  (and `tomli` on Python < 3.11), OpenSSL and the OpenSSH client. Standalone script, no daemon,
  no third-party service. Talks to the appliance over SSH/SCP only; the AsyncOS REST API is not
  involved because it does not offer certificate import.
- **Status:** 2.0.0. Tested against AsyncOS 16.0.3 on a standalone Cisco Secure Email Gateway
  (virtual appliance) and, in the automated test suite, against a fake CLI that reproduces the
  dialogue including overwrite, FQDN and cluster prompts. Clustered appliances are supported on a
  best-effort basis, see [Known issues](#known-issues).
- **Sample run** (certbot hook mode, INFO level; timestamps removed):

```text
Renewed lineage /etc/letsencrypt/live/mail.example.com covers: mail.example.com
[esa1] Deploying /etc/letsencrypt/live/mail.example.com to esa1.example.com (profile 'lets_encrypt_mail')
Building PKCS#12 bundle from /etc/letsencrypt/live/mail.example.com
[esa1] Certificate SHA-256 fingerprint: 5634082e1545fac3e8f97de10720458ed981ca7b016bdb9142f35b12350f0022
[esa1] Uploading esacert.pfx to /configuration/esacertpfx
[esa1] Opening SSH session: ssh -p 22 -o ConnectTimeout=20 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/esa-deploy/known_hosts -o BatchMode=yes -i /etc/esa-deploy/esa_admin -o IdentitiesOnly=yes admin@esa1.example.com
[esa1] Logged in; prompt is 'esa1.example.com>'
[esa1] Importing esacertpfx into certificate profile 'lets_encrypt_mail'
[esa1] Profile 'lets_encrypt_mail' exists; overwriting.
[esa1] FQDN check question before import; answering N.
[esa1] Certificate profile 'lets_encrypt_mail' imported.
[esa1] Committing configuration.
[esa1] Changes committed: Tue Sep 22 09:05:00 2026 CEST
[esa1] Logged out.
[esa1] Uploading empty to /configuration/esacertpfx
[esa1] Overwrote /configuration/esacertpfx on the appliance with an empty file.
[esa1] verify esa1.example.com:443 (TLS): ok (5634082e1545fac3)
[esa1] verify mail.example.com:25 (STARTTLS): ok (5634082e1545fac3)
[esa1] Verification succeeded: appliance serves the new certificate.
[esa1] Deployment completed successfully.
```

# Use Case

**Problem.** Organisations that run Cisco Secure Email Gateway want the SMTP listeners (inbound
MTA-STS/DANE-aware peers, outbound TLS) and the HTTPS management interface on publicly trusted
certificates. Let's Encrypt makes that free, but only if renewal *and deployment* are automated.
The gateway offers no certificate API, so the deployment half is usually still a manual GUI task
performed by an administrator every 60 days, per appliance, and it is the step that gets missed.
An expired listener certificate degrades TLS delivery from strict peers and triggers monitoring
alerts; an expired management certificate trains administrators to click through browser warnings.

**Solution.** A certbot deploy-hook that behaves like a careful administrator at the CLI:

- reads its targets from a root-only configuration file (no credentials in shell profiles or
  cron environments),
- deploys only to appliances whose configured domains are covered by the renewed certificate
  (wildcards included), so one certbot host can serve several gateways, a Secure Email and Web
  Manager (SMA), or a cluster,
- keeps the private key exposure minimal: the PKCS#12 is built in a private temporary directory,
  its password never appears on a command line or in a log, and the uploaded bundle is
  overwritten with an empty file once the import has been committed,
- treats every unexpected prompt, timeout or authentication problem as a hard error with a
  message that quotes the last output from the appliance, so certbot's exit status and log
  reflect reality,
- verifies the result by connecting to the appliance's TLS/STARTTLS endpoints and comparing the
  presented certificate with the lineage, and can reconcile on a timer.

**Outcome.** Certificate deployment to the gateway becomes an unattended, observable step of the
renewal pipeline: zero manual GUI imports, deployment failures are visible immediately (non-zero
exit, stderr, optional transcript), and a missed deployment is corrected automatically by the
daily reconciliation run instead of surfacing as an expired certificate weeks later.

## Installation

The script runs on the host where certbot manages the certificate (typically a small Linux VM in
the DMZ or the mail relay itself). It needs Python 3.9 or newer, `pexpect`, OpenSSL and the
OpenSSH client, plus SSH/SCP reachability to each appliance (TCP 22 by default) and, for
verification, reachability to the endpoints you list (TCP 443, 25, ...).

Clone the repo

```bash
git clone https://github.com/magnusfrodell/CiscoESA-Cert-Automation.git
cd CiscoESA-Cert-Automation
```

Install the dependencies. On Debian/Ubuntu the distribution packages are all that is needed
(`python3-tomli` only on Python 3.9/3.10, i.e. Debian 11 and Ubuntu 20.04/22.04):

```bash
sudo apt-get install -y python3-pexpect python3-tomli openssl openssh-client
```

On other distributions, or if you prefer pip:

```bash
sudo python3 -m pip install -r requirements.txt
```

Install the script and create the configuration directory (root-only; it will hold secrets):

```bash
sudo install -o root -g root -m 0750 esa_deploy.py /usr/local/sbin/esa_deploy.py
sudo install -d -o root -g root -m 0700 /etc/esa-deploy
sudo install -o root -g root -m 0600 config.example.toml /etc/esa-deploy/config.toml
```

Create the PKCS#12 password (it only protects the bundle in transit and is never needed by a
human) and a dedicated SSH key pair for the appliance:

```bash
sudo sh -c 'umask 077; openssl rand -hex 16 > /etc/esa-deploy/pfx.pass'
sudo ssh-keygen -t ed25519 -N "" -C esa-deploy -f /etc/esa-deploy/esa_admin
sudo cat /etc/esa-deploy/esa_admin.pub
```

Load the public key on each appliance: log in to the CLI as `admin` (or a dedicated operator
account with administrator rights) and run `sshconfig` > `USERKEY` > `NEW`, paste the public key,
leave `sshconfig` and `commit`. Then record the appliance host keys, checking the fingerprints
against what the appliance reports before trusting them:

```bash
ssh-keyscan -p 22 esa1.example.com | sudo tee -a /etc/esa-deploy/known_hosts
ssh-keygen -l -f /etc/esa-deploy/known_hosts
sudo ssh -i /etc/esa-deploy/esa_admin -o UserKnownHostsFile=/etc/esa-deploy/known_hosts admin@esa1.example.com
```

The last command must land on the AsyncOS prompt without asking for a password; type `exit`.
Now edit `/etc/esa-deploy/config.toml` (next section), then walk through the test sequence in
[Usage](#usage) before wiring the hook into certbot.

Hook it into certbot. Certbot runs every executable found in
`/etc/letsencrypt/renewal-hooks/deploy/` after each successful renewal, with `RENEWED_LINEAGE`
and `RENEWED_DOMAINS` set, so a symlink is enough and no environment variables have to be
plumbed into `certbot.timer` or cron:

```bash
sudo ln -s /usr/local/sbin/esa_deploy.py /etc/letsencrypt/renewal-hooks/deploy/esa_deploy
```

If you prefer to attach the hook to one lineage only, set `deploy_hook = /usr/local/sbin/esa_deploy.py`
in the `[renewalparams]` section of `/etc/letsencrypt/renewal/<lineage>.conf` (or pass
`--deploy-hook /usr/local/sbin/esa_deploy.py` when issuing the certificate) instead.

Optionally enable the daily reconciliation timer, which redeploys if an appliance is found
serving something other than the local lineage (requires `verify` endpoints per target):

```bash
sudo cp systemd/esa-deploy-reconcile.service systemd/esa-deploy-reconcile.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now esa-deploy-reconcile.timer
sudo systemctl start esa-deploy-reconcile.service     # run once now and check the result
sudo journalctl -u esa-deploy-reconcile.service -n 50
```

The script also runs on any other Linux/BSD host with the same dependencies; only the paths in
the examples are Debian/Ubuntu specific. It is not intended for Windows (pexpect needs a POSIX pty).

## Configuration

All configuration lives in one TOML file, `/etc/esa-deploy/config.toml` by default (override with
`--config PATH` or the `ESA_DEPLOY_CONFIG` environment variable). The file must be readable by
root only; the script warns if it, or a secret file, is readable by others. A fully commented
example is in [`config.example.toml`](./config.example.toml).

The file has one `[defaults]` table and any number of `[[targets]]` tables. Every key can be set
in either place; a target overrides the defaults. A secret can be given inline (`pfx_password`,
`password`) or through a file containing just the value (`pfx_password_file`, `password_file`);
whichever form the target uses wins over the other form in `[defaults]`.

```toml
[defaults]
user = "admin"
identity_file = "/etc/esa-deploy/esa_admin"
known_hosts_file = "/etc/esa-deploy/known_hosts"
pfx_password_file = "/etc/esa-deploy/pfx.pass"
profile_name = "lets_encrypt_mail"

[[targets]]
name = "esa1"
host = "esa1.example.com"
target_domains = ["mail.example.com"]
lineage = "/etc/letsencrypt/live/mail.example.com"
verify = ["esa1.example.com:443", "mail.example.com:25"]

[[targets]]
name = "esa2"
host = "esa2.example.com"
target_domains = ["mail.example.com"]
lineage = "/etc/letsencrypt/live/mail.example.com"
verify = ["esa2.example.com:443", "esa2.example.com:25"]
```

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | value of `host` | Label used in log lines and by `--target`. Must be unique. |
| `host` | required | Appliance hostname or IP address for SSH/SCP. |
| `target_domains` / `target_domain` | required | Domain(s) whose certificate belongs on this appliance. In hook mode the target is deployed when any of them is covered by the renewed certificate; `*.example.com` covers `mail.example.com`. |
| `lineage` | `/etc/letsencrypt/live/<first target domain>` | Lineage directory used by `--reconcile`, `--verify-only` and `--force`. Hook mode always uses certbot's `RENEWED_LINEAGE`. |
| `user` | `admin` | SSH user. Needs administrator rights on the appliance. |
| `port` | `22` | SSH port. |
| `auth` | `key` | `key` (recommended: `BatchMode=yes`, never prompts) or `password` (ssh and scp are driven through pexpect and answer the password prompt). |
| `password` / `password_file` | | SSH password, only with `auth = "password"`. |
| `identity_file` | | Private key for `auth = "key"`; used with `IdentitiesOnly=yes` so agent keys or `~/.ssh` keys are never offered. |
| `known_hosts_file` | ssh default | Dedicated `known_hosts` for the appliance host keys, independent of root's `~/.ssh`. |
| `strict_host_key` | `true` | `true` -> `StrictHostKeyChecking=yes` (host key must already be known). `false` -> `accept-new`: trusts the key on first contact, then pins it. |
| `ssh_extra_options` | `[]` | Extra `-o` options for ssh and scp, e.g. `["HostKeyAlgorithms=+ssh-rsa", "PubkeyAcceptedAlgorithms=+ssh-rsa"]` for older AsyncOS releases with modern OpenSSH clients. |
| `scp_legacy` | `auto` | Whether to pass `scp -O` (legacy SCP protocol; AsyncOS has no SFTP). `auto` adds it when the local OpenSSH is 8.7 or newer; `yes` / `no` force it. |
| `connect_timeout` | `20` | Seconds for SSH connection establishment. |
| `cli_timeout` | `90` | Seconds to wait for each expected prompt in the CLI dialogue. |
| `commit_timeout` | `180` | Seconds to wait for `Changes committed`. |
| `profile_name` | `lets_encrypt_mail` | Certificate profile name in `certconfig`. Letters, digits, `_` and `-` only (AsyncOS rejects symbols). Created on the first run, overwritten afterwards. |
| `remote_pfx_path` | `/configuration/esacertpfx` | Upload path on the appliance; its basename is what `certconfig` is asked to import. |
| `pfx_password` / `pfx_password_file` | required | Passphrase for the PKCS#12 bundle. Passed to OpenSSL via the environment, typed into the appliance, redacted from all logs. |
| `pfx_legacy` | `false` | Add `-legacy` to `openssl pkcs12 -export` (OpenSSL 3 legacy provider) for AsyncOS releases that cannot read AES-256/PBKDF2 bundles. |
| `cleanup_remote_pfx` | `true` | After the commit, overwrite the uploaded bundle (which contains the private key) with an empty file. AsyncOS has no `rm`, so this is the best available cleanup. |
| `commit_comment` | `esa_deploy <version>: imported <profile> sha256 <fp>` | Text given at the `commit` comments prompt. |
| `verify` | `[]` | Endpoints to check after deployment, as `host:port[:tls|starttls]`. Ports 25 and 587 default to STARTTLS, everything else to plain TLS. The presented leaf certificate must match the lineage's `cert.pem`. |
| `verify_strict` | `false` | `true` -> a deployment counts as failed (exit 1) when verification does not succeed on every endpoint. Leave `false` until the profile is bound to the services (see below). |
| `verify_timeout`, `verify_retries`, `verify_retry_delay` | `15`, `3`, `10` | Per-connection timeout, number of verification rounds after a deployment, and the delay between rounds (gives the appliance time to switch). `--verify-only` and `--reconcile` use a single round. |
| `cluster_mode` | `""` | Empty for standalone appliances or for changes at the cluster level. `cluster`, `group` or `machine` runs `clustermode <mode> [<name>]` before `certconfig` (numbered-menu fallback included). |
| `cluster_name` | `""` (`host` for `machine`) | Group or machine name for `cluster_mode`. |
| `cluster_level_answer` | `""` | If the appliance asks a `... cluster level ... [C]>` style question when entering `certconfig` or on `commit`, this answer is sent. When unset the script stops with an error that quotes the question, so you can decide deliberately. |

**Binding the profile.** Importing a certificate profile does not by itself put it in use. The
first time the profile exists on an appliance, bind it in the GUI (Network > Certificates) or CLI
to the HTTPS interface (`interfaceconfig` / Network > IP Interfaces), the inbound listener
(`listenerconfig` / Mail Policies > Mail Flow Policies > TLS) and outbound delivery
(`sslconfig`, Destination Controls) as needed, and commit. Subsequent renewals overwrite the
profile in place and those bindings keep pointing at it. Once the bindings exist, `verify`
endpoints reflect the profile and you can consider `verify_strict = true`.

**Legacy environment mode.** If no configuration file exists and `ESA_HOST` is set, the v1
environment variables (`ESA_HOST`, `ESA_TARGET_DOMAIN`, `ESA_PFX_PASSWORD` required; `ESA_SSH_PORT`,
`ESA_USER`, `ESA_USE_PASSWORD`, `ESA_PASSWORD`, `ESA_CERT_PROFILE_NAME`, `ESA_REMOTE_PFX_PATH`
optional) are used for a single target, with a warning. Unlike v1, missing required values are an
error rather than a silent no-op.

## Usage

Synopsis:

```text
esa_deploy.py [--config PATH] [--target NAME ...]
              [--force | --reconcile | --verify-only | --print-config]
              [--lineage DIR --domains "a b"] [--dry-run] [--transcript FILE]
              [--log-file FILE] [-v | -q] [--version]
```

Without a mode flag the script is in **hook mode**: it reads `RENEWED_LINEAGE` and
`RENEWED_DOMAINS` from the environment (certbot sets them), deploys to every target whose
`target_domains` are covered and exits 0 when all of them succeeded, 1 when any of them failed
and 2 on configuration errors. Targets that are not covered are skipped with an INFO message; if
none is covered the run is a no-op with exit 0, which is what you want when certbot renews an
unrelated certificate on the same host.

Recommended first-run sequence after installing and editing the configuration:

```bash
# 1. Does the configuration load, and does it say what you meant? (secrets are masked)
sudo /usr/local/sbin/esa_deploy.py --print-config

# 2. Build the PKCS#12 from the lineage without touching any appliance
sudo /usr/local/sbin/esa_deploy.py --force --dry-run

# 3. Real deployment to one appliance, keeping a redacted transcript of the CLI session
sudo /usr/local/sbin/esa_deploy.py --force --target esa1 --transcript /var/log/esa-deploy-transcript.log -v

# 4. Bind the new profile to the interface/listeners on the appliance (first time only), then:
sudo /usr/local/sbin/esa_deploy.py --verify-only
```

Other modes and switches:

- `--force` deploys each selected target's `lineage` right now, regardless of certbot. Use it
  for the first deployment and after configuration changes.
- `--reconcile` probes the `verify` endpoints of each target and deploys only if at least one of
  them presents a certificate different from the lineage. Endpoints that cannot be reached are
  reported and never trigger a deployment (the script refuses to guess). This is what the
  systemd timer runs.
- `--verify-only` reports the served certificate per endpoint without changing anything; exit 1
  on any mismatch or error, which makes it usable from a monitoring check.
- `--lineage DIR --domains "d1 d2"` simulates a certbot invocation for a given lineage, which is
  handy to test the domain matching (`--dry-run` recommended). Note that `certbot renew --dry-run`
  does not execute deploy hooks, and newer certbot versions' `--run-deploy-hooks` would push the
  *staging* certificate to your appliances, so test with `--force`/`--lineage` instead.
- `--target NAME` (repeatable) restricts any mode to the named targets.
- `--dry-run` builds the PKCS#12 and evaluates the domain match but never connects to an appliance.
- `--transcript FILE` appends the appliance's CLI output (redacted, mode 0600) to a file; attach
  it when reporting a problem with the dialogue.
- `--log-file FILE` writes the log there as well (mode 0600). `-v` adds DEBUG lines (every command
  sent, every prompt learned), `-q` suppresses INFO output.
- `--print-config` prints the effective, merged configuration with secrets masked.

Logging: INFO goes to stdout and WARNING/ERROR to stderr. Certbot records a hook's stderr as an
error in its own log, so with this split `/var/log/letsencrypt/letsencrypt.log` and the
`certbot.service` journal only carry real problems while the full story is available at INFO
level. Every timeout error quotes the last output received from the appliance, and every log line,
error message and transcript passes through a redactor that masks the configured passwords.

Exit codes: `0` success or nothing to do, `1` at least one target failed (deployment, strict
verification, reconcile unable to determine state), `2` configuration or usage error (also for a
missing configuration file, so a misconfigured hook is visible in certbot's log instead of
passing silently).

## How it works

```text
certbot renew
   |  RENEWED_LINEAGE=/etc/letsencrypt/live/mail.example.com
   |  RENEWED_DOMAINS="mail.example.com"
   v
esa_deploy.py (hook mode)
   |  load /etc/esa-deploy/config.toml, select covered targets
   |
   |-- per target -------------------------------------------------------------
   |  1. openssl pkcs12 -export  (leaf + chain + key -> esacert.pfx in a 0700 tmpdir,
   |     passphrase via environment)
   |  2. scp [-O] esacert.pfx admin@esa:/configuration/esacertpfx
   |  3. ssh admin@esa   (pexpect; prompt learned at login, matched exactly afterwards)
   |        [clustermode ...]              only when cluster_mode is set
   |        certconfig > certificate > import
   |          profile name, "already exists ... overwrite? [N]>" -> Y
   |          file name, "FQDN ... ? [N]>" -> N, passphrase, "FQDN ... ? [N]>" -> N
   |        ENTER, ENTER                   back to the main prompt
   |        commit -> comment -> "rollback? [Y]>" -> Y -> "Changes committed"
   |        exit
   |  4. scp an empty file over /configuration/esacertpfx   (cleanup_remote_pfx)
   |  5. TLS / STARTTLS probe of each verify endpoint, compare SHA-256 of the leaf
   ---------------------------------------------------------------------------
   v
exit 0 / 1 / 2
```

The dialogue is driven with explicit expectations at every step: a pattern list per prompt
(including known error messages such as an invalid passphrase or a missing file), a timeout per
wait, and the main prompt learned from the login banner so that `esa1.example.com>`,
`esa1.example.com (Cluster c1)>` and `esa1.example.com (Machine esa1.example.com)>` are all
matched literally rather than by a generic `> ` pattern that also occurs inside `certconfig`.

## Security notes

- The private key leaves the certbot host only inside the password-protected PKCS#12, over SSH,
  to an appliance you have explicitly listed. The bundle is created in a private temporary
  directory (mode 0700) that is removed afterwards, and the copy on the appliance is overwritten
  with an empty file after the commit.
- The PKCS#12 passphrase is handed to OpenSSL through an environment variable of that one child
  process (not on its command line, where `ps` would show it) and typed into the appliance's
  passphrase prompt, which does not echo. All log output, error messages and transcripts are
  filtered through a redactor that masks every configured secret.
- SSH runs with `BatchMode=yes`, `StrictHostKeyChecking=yes`, a dedicated identity with
  `IdentitiesOnly=yes` and, if configured, a dedicated `known_hosts` file. A changed host key,
  a rejected key or a rejected password is a hard error that names the cause.
- Prefer key authentication and a dedicated administrator account on the appliance. Password
  authentication is supported for environments that cannot load user keys, but the password then
  has to be stored on the certbot host (use `password_file`, mode 0600).
- The configuration directory must be root-only. The script warns when the configuration or a
  secret file is readable by group or others.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `Configuration error: config file not found` | Create `/etc/esa-deploy/config.toml` (see `config.example.toml`) or pass `--config`. |
| `scp failed ... Permission denied (publickey,...)` | The public key is not loaded for that user on the appliance (`sshconfig` > `USERKEY`), or `identity_file` points at the wrong key. Test with the plain `ssh -i ...` command from the installation steps. |
| `scp failed ... Host key verification failed` | The appliance host key is not in `known_hosts_file` (or has changed). Re-run `ssh-keyscan`, verify the fingerprint, and replace the entry. |
| `appliance rejected the password` | Wrong `password`/`password_file`, or the account is locked. |
| `scp: unknown option -- O` | Old OpenSSH client; set `scp_legacy = "no"`. |
| `no matching host key type found` / `no matching key exchange method` | Older AsyncOS with a modern OpenSSH client: add the required algorithms via `ssh_extra_options`. |
| `timed out after 90s waiting for <step>. Last output from appliance: ...` | The appliance printed something the script did not expect. The quoted output shows where it diverged; run again with `-v --transcript FILE` and open an issue with the transcript and AsyncOS version. Increase `cli_timeout`/`commit_timeout` only if the appliance is genuinely slow. |
| `appliance asked a cluster-level question ...` | The appliance is clustered. Decide at which level the profile should live, set `cluster_mode` (and `cluster_name`) or `cluster_level_answer`, and re-run. |
| `import failed: Invalid pass phrase or corrupt PKCS#12 file` | The appliance could not read the bundle. Try `pfx_legacy = true` (OpenSSL 3 default encryption is not accepted by every AsyncOS release). |
| Verification reports `mismatch` although the import succeeded | The profile is not bound to the service behind that endpoint (see *Binding the profile*), or a load balancer/other appliance answers on that name. |
| Verification reports `error (... Connection refused / timed out)` | The certbot host cannot reach the endpoint; adjust `verify` or firewall rules. Unreachable endpoints never trigger a `--reconcile` deployment. |

## Upgrading from v1

1. Install the new script and create `/etc/esa-deploy/config.toml` with the values you had in
   `ESA_*` variables (`ESA_HOST` -> `host`, `ESA_TARGET_DOMAIN` -> `target_domains`,
   `ESA_PFX_PASSWORD` -> `pfx_password_file`, `ESA_CERT_PROFILE_NAME` -> `profile_name`, and so on).
2. Remove the `ESA_*` variables from wherever they were exported. They are no longer needed and,
   if they stay while the config file exists, they are ignored.
3. Make sure the appliance host key is in the configured `known_hosts_file` (v1 relied on an
   existing entry in root's `~/.ssh/known_hosts` or on ssh's interactive prompt, which cannot be
   answered from a hook).
4. Run `--print-config`, `--force --dry-run` and `--force --target <name>` as described in
   [Usage](#usage). The existing `lets_encrypt_mail` profile is overwritten in place, so bindings
   on the appliance stay valid.
5. Behavioural change to be aware of: a missing or incomplete configuration is now an error
   (exit 2), not a silent exit 0, and the uploaded PKCS#12 is overwritten on the appliance after
   the commit (`cleanup_remote_pfx = false` restores the old behaviour).

## Known issues

- Only AsyncOS 16.0.3 on a standalone Secure Email Gateway has been exercised against a real
  appliance. The prompts the script expects are listed in the `EsaSession` docstring; other
  releases may word a question differently, which surfaces as a timeout error quoting the
  appliance output. Please report such cases (see [Getting help](#getting-help)).
- Cluster support is best effort: the `clustermode` command (inline and numbered-menu forms), the
  `host (Cluster name)>` prompt style and a cluster-level question at `certconfig`/`commit` are
  handled, but none of it has been validated on a real cluster. Note that at the cluster level
  `certconfig` reads the uploaded file from the appliance you are logged in to, so one target per
  cluster may be sufficient; at the machine level you need one target per member.
- AsyncOS has no `rm`; the uploaded PKCS#12 is overwritten with an empty file rather than deleted.
- Verification requires network reachability from the certbot host to the endpoints and only
  reflects reality once the profile is bound to the corresponding service. Verify endpoints are
  hostnames or IPv4 literals; bracketed IPv6 literals are not supported in the `host:port` syntax.
- Wildcard matching covers one label only (`*.example.com` matches `mail.example.com`, not
  `a.mail.example.com`), the same rule the certificate itself follows.
- `openssl pkcs12 -legacy` requires OpenSSL 3 with the legacy provider; on OpenSSL 1.1 hosts leave
  `pfx_legacy = false` (those bundles are already in the older format).
- Password authentication assumes the appliance offers `keyboard-interactive` or `password`
  authentication and a `Password:` prompt; two-factor or other interactive schemes are not
  supported.
- Issues are tracked with [GitHub Issues](https://github.com/magnusfrodell/CiscoESA-Cert-Automation/issues).
  For dialogue problems please include the AsyncOS version, whether the appliance is clustered,
  and the output of a run with `-v --transcript <file>` (secrets are redacted automatically).

## Getting help

Open an issue at <https://github.com/magnusfrodell/CiscoESA-Cert-Automation/issues>. This is
sample code and is not supported by Cisco TAC. For questions about the appliance side
(`certconfig`, `sshconfig`, certificate bindings, clustering) the
[Cisco Secure Email Gateway user guide](https://www.cisco.com/c/en/us/support/security/email-security-appliance/products-user-guide-list.html)
and the AsyncOS CLI reference guide are the authoritative sources.

## Getting involved

Feedback that helps most right now:

- Transcripts from other AsyncOS releases and from clustered appliances, so the expected prompts
  can be confirmed or extended.
- Reports from Secure Email and Web Manager (SMA) deployments (`certconfig` is the same, the
  bindings differ).
- Ideas for the reconcile loop (e.g. alerting hooks) and for hardening.

Development setup:

```bash
git clone https://github.com/magnusfrodell/CiscoESA-Cert-Automation.git
cd CiscoESA-Cert-Automation
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python3 -m pytest -q
```

The test suite needs no appliance: `tests/fake_esa.py` imitates the AsyncOS CLI (login, optional
password prompt, `clustermode`, `certconfig` with overwrite/FQDN/error paths, `commit`, `exit`)
and the tests drive the real `EsaSession` and `deploy_target` code against it through a pty. New
prompt variants should be added there as scenario flags together with a test. See
[CONTRIBUTING](./CONTRIBUTING.md) for the general contribution process.

## Credits and references

1. [Let's Encrypt](https://letsencrypt.org/) and [certbot](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates),
   in particular the deploy-hook contract (`RENEWED_LINEAGE`, `RENEWED_DOMAINS`, `renewal-hooks/deploy`).
2. [pexpect](https://pexpect.readthedocs.io/), which makes driving an interactive CLI from Python
   reliable.
3. Cisco Secure Email Gateway documentation: the user guide's *Managing Certificates* and
   *Centralized Management Using Clusters* chapters and the CLI reference for `certconfig`,
   `sshconfig`, `clustermode` and `commit`.
4. Version 1 of this project, which established the SCP + `certconfig` approach that v2 hardens.
5. Documentation structure from the [Cisco DevNet Code Exchange repo template](https://github.com/CiscoDevNet/code-exchange-repo-template).

## Licensing info

This code is licensed under the Cisco Sample Code License, Version 1.1. See [LICENSE](./LICENSE)
for details and <https://developer.cisco.com/site/license/cisco-sample-code-license/> for the
current text of the license.
