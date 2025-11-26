# Automatic Let's Encrypt Certificate Deployment to Cisco ESA

**Author:** Magnus Frödell  
**Script:** `esa_deploy.py`  
**Target platform:** Cisco Email Security Appliance (ESA), AsyncOS (tested on 16.0.3)  
**Purpose:** Automatically push renewed Let's Encrypt certificates from a Linux host (Certbot) to a Cisco ESA, using PKCS#12 and `certconfig`.

---

## 1. Overview

This document describes how to automatically deploy Let's Encrypt TLS certificates
from a Certbot-enabled Linux host to a Cisco Email Security Appliance (ESA) using
the `esa_deploy.py` deploy-hook script.

The automation:

1. Builds a PKCS#12 (.pfx) bundle from a Let's Encrypt lineage.
2. Copies the PFX file to the ESA over SSH/SCP.
3. Logs into the ESA via SSH and automates `certconfig` using `pexpect` to:
   - create or overwrite a certificate profile (e.g. `lets_encrypt_mail`),
   - handle overwrite confirmations,
   - handle FQDN validation prompts,
   - supply the PFX passphrase.
4. Exits back to the main ESA prompt and runs `commit` (or detects if there is nothing to commit).

The result is a **fully automated, non-interactive** certificate deployment workflow
whenever Certbot successfully renews a certificate.

---

## 2. Requirements

### 2.1 Certbot Host (Linux)

- Python 3.x
- `pexpect` Python module
- OpenSSL CLI tools
- Certbot installed and working
- SSH access to the ESA

**Install `pexpect` on Debian/Ubuntu (example):**

```bash
apt-get update
apt-get install -y python3-pexpect
```

### 2.2 Cisco ESA

- Admin-level access (CLI)
- SSH access enabled
- Ability to add SSH public keys for the user

---

## 3. Script Installation

1. Create the deploy-hook directory (if it does not already exist):

   ```bash
   sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy
   ```

2. Copy or create the `esa_deploy.py` script in that directory:

   ```bash
   sudo vim /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py
   ```

   Paste the full contents of `esa_deploy.py` (the script from this repository).

3. Make the script executable:

   ```bash
   sudo chmod 750 /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py
   ```

---

## 4. SSH Key-Based Authentication to ESA (Recommended)

Although the script can use password authentication, **SSH key-based authentication**
is strongly recommended for unattended operation.

### 4.1 Generate SSH Key on the Certbot Host

As `root` (or the user running Certbot):

```bash
sudo -s   # if not already root

ssh-keygen -t ed25519 -f /root/.ssh/esa_admin -C "esa-admin"
```

- Leave the passphrase empty for a fully unattended setup,
  or manage the passphrase via `ssh-agent` if preferred.
- This creates:
  - Private key: `/root/.ssh/esa_admin`
  - Public key:  `/root/.ssh/esa_admin.pub`

### 4.2 Add the Public Key to the ESA Admin User

Log into the ESA manually:

```bash
ssh admin@<esa-hostname-or-ip>
```

In the ESA CLI, enter `sshconfig` (exact prompts may vary slightly by AsyncOS version):

```text
> sshconfig

[]> USERKEY
[]> NEW

Please enter the public SSH key for authorization.
Press enter on a blank line to finish.

Enter twice to exit to main prompt

> commit
> Ctrl+D

```

Alternatively, if supported by your AsyncOS version, add the SSH public key through
the ESA Web GUI under SSH / Access configuration for the user.

### 4.3 Configure SSH on the Certbot Host

Create or edit `/root/.ssh/config`:

```bash
cat << 'EOF' > /root/.ssh/config
Host <esa-hostname-or-ip>
    HostName <esa-hostname-or-ip>
    User admin
    Port 22
    IdentityFile /root/.ssh/esa_admin
    IdentitiesOnly yes
EOF

chmod 600 /root/.ssh/config
```

Replace <esa-hostname-or-ip> with your ESA hostname or IP.

Verify that SSH and SCP work non-interactively:

```bash
ssh <esa-hostname-or-ip>
scp -O /tmp/testfile <esa-hostname-or-ip>:/configuration/testfile
```

You should not be prompted for a password.

---

## 5. Environment Configuration (ESA_* Variables)

The script reads its ESA-specific configuration primarily from environment variables:

- `ESA_HOST`  
  ESA hostname/FQDN (e.g. `example.test.com`).

- `ESA_SSH_PORT`  
  SSH port on the ESA (default: `22`).

- `ESA_USER`  
  ESA username (default: `admin`).

- `ESA_USE_PASSWORD`  
  `"true"` or `"false"` (default: `"false"`).  
  If `"true"`, the script expects `ESA_PASSWORD` and uses interactive
  password-based SSH auth. If `"false"`, it assumes key-based/agent-based auth.

- `ESA_PASSWORD`  
  ESA admin password, used only if `ESA_USE_PASSWORD="true"`.

- `ESA_CERT_PROFILE_NAME`  
  Certificate profile name on the ESA (default: `lets_encrypt_mail`).

- `ESA_REMOTE_PFX_PATH`  
  Full path on ESA where the PFX will be copied (default: `/configuration/esacertpfx`).  
  Only the basename is used in `certconfig`, to avoid symbol restrictions.

- `ESA_PFX_PASSWORD`  
  PKCS#12 password (for both OpenSSL export and ESA import).  
  Recommended to use only `[A-Za-z0-9_-]` to avoid AsyncOS quirks.

- `ESA_TARGET_DOMAIN`  
  FQDN that must appear in the renewed certificate’s domain list for this
  deploy-hook to take action (e.g. `example.test.com`).

### 5.1 Example Environment for Manual Test

```bash
sudo ESA_HOST="<esa-hostname-or-ip>"      ESA_TARGET_DOMAIN="example.test.com"      ESA_PFX_PASSWORD="Cisco12345"      /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py        --lineage /etc/letsencrypt/live/example.test.com        --domains "example.test.com"        --verbose
```

If the domain check passes and everything is configured correctly, the script will:

1. Build `esacert.pfx` from the Let’s Encrypt lineage.
2. Copy it to `/configuration/esacertpfx` on the ESA.
3. Import/overwrite the `lets_encrypt_mail` certificate profile.
4. Handle FQDN prompts and PFX passphrase.
5. Run `commit` (or log that there is nothing to commit).
6. Exit with:

   ```text
   [INFO] esa_deploy - ESA certificate deployment completed successfully.
   ```

---

## 6. Integrating with Certbot

You can configure Certbot to invoke `esa_deploy.py` automatically whenever
a renewal succeeds.

### 6.1 Option A: Global Deploy-Hook via `cli.ini`

Edit `/etc/letsencrypt/cli.ini`:

```ini
deploy-hook = /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py
```

This will run the script after every successful renewal. The script itself will
only act when the renewed certificate contains `ESA_TARGET_DOMAIN`.

### 6.2 Option B: Per-Certificate Deploy-Hook

Edit the renewal configuration for your ESA certificate, e.g.:

```bash
sudo vi /etc/letsencrypt/renewal/example.test.com.conf
```

Add or update:

```ini
deploy_hook = /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py
```

This limits the deploy-hook to the specific lineage.

---

## 7. Verifying on the ESA

After a successful run of the script:

1. Log into the ESA CLI.

2. Verify the certificate profile:

   ```text
   > certconfig
   []> certificate
   []> print
   ```

   Check that your profile name (e.g. `lets_encrypt_mail`) is present
   and references the correct certificate.

3. Bind the certificate profile to the relevant services, such as:

   - HTTPS GUI / management interface
   - SMTP listeners using TLS

   This is done via ESA configuration menus (`sslconfig`, `interfaceconfig`,
   `listenerconfig`, etc.) depending on your AsyncOS version and design.

4. Optionally verify the external TLS endpoint with OpenSSL from an external host:

   ```bash
   echo | openssl s_client -connect example.test.com:443 -servername example.test.com 2>/dev/null      | openssl x509 -noout -subject -issuer -dates
   ```

---

## 8. Logging and Diagnostics

- By default, the script logs to stderr using `INFO` level.
- Use `--verbose` to enable `DEBUG` level logging:

  ```bash
  /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py --verbose ...
  ```

When Certbot invokes the script, logs can be found under:

- `/var/log/letsencrypt/letsencrypt.log`
- `/var/log/letsencrypt/letsencrypt.log.N`

If you need to see the exact interactive CLI conversation with ESA, you can
temporarily enable `pexpect` session logging inside the script by uncommenting:

```python
# child.logfile = sys.stdout
```

in `EsaCertImporter.import_pfx_and_commit()`.

---

## 9. Troubleshooting

### 9.1 SSH / SCP Issues

Symptoms:

- Script hangs at “Copying PFX to ESA” or “Opening SSH session to ESA”.
- Error messages about host keys or authentication.

Checks:

1. Confirm manual SSH:

   ```bash
   ssh example.test.com
   ```

2. Confirm manual SCP:

   ```bash
   scp -O /tmp/testfile example.test.com:/configuration/testfile
   ```

3. Verify `/root/.ssh/config`:
   - Correct `Host` alias
   - Correct `IdentityFile`
   - Correct `Port`

### 9.2 Certconfig Prompt Mismatches

If AsyncOS versions change prompts, `pexpect` regexes may fail.

Diagnosis steps:

1. Uncomment `child.logfile = sys.stdout` in the script.
2. Run a manual test with `--verbose`.
3. Observe the exact prompts from ESA.
4. Update the regex patterns in `_run_certconfig_import()` and `_commit_changes()`
   accordingly (e.g. overwrite prompt, FQDN prompt, commit messages).

### 9.3 “There is no data to commit.”

The script explicitly handles this message:

```text
There is no data to commit.
```

In such cases, the script treats it as a successful no-op commit, returns to the
main prompt, and exits. This is normal when ESA does not consider the recent
operations to be pending configuration changes.

---

## 10. Security Considerations

- **SSH Keys:**  
  Use dedicated SSH keys for ESA automation. Restrict them to specific hosts
  and users as appropriate.

- **PFX Password (ESA_PFX_PASSWORD):**  
  Provide this via secure mechanisms (e.g. systemd environment, root-only shell
  scripts). Avoid world-readable files or environment exposure.

- **File Permissions:**  
  Ensure:
  - `esa_deploy.py` is owned by root and not writable by unprivileged users and is executable.
  - `/etc/letsencrypt` and `/root/.ssh` have appropriate restrictive permissions.

---

## 11. Minimal Working Example

Assuming:

- ESA hostname: `dexample.test.com`
- Let’s Encrypt lineage: `/etc/letsencrypt/live/example.test.com`
- Target domain: `example.test.com`
- ESA cert profile name: `lets_encrypt_mail`
- PFX password: `Cisco12345`

Manual test command:

```bash
sudo ESA_HOST="example.test.com"      ESA_TARGET_DOMAIN="example.test.com"      ESA_PFX_PASSWORD="Cisco12345"      /etc/letsencrypt/renewal-hooks/deploy/esa_deploy.py        --lineage /etc/letsencrypt/live/example.test.com        --domains "example.test.com"        --verbose
```

Expected final log line:

```text
[INFO] esa_deploy - ESA certificate deployment completed successfully.
```

Once that is working, wire it into Certbot as a deploy-hook (global or per-certificate)
to make the entire process fully automatic.
