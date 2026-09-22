# Changelog

All notable changes to this project are documented in this file.

## [2.0.0] - 2026-09-22

### Added
- TOML configuration file (`/etc/esa-deploy/config.toml`) with `[defaults]` and any number of
  `[[targets]]`, so one certbot host can serve several appliances (cluster members, SMA).
- `--reconcile` mode plus systemd service/timer: compares the certificate an appliance serves with
  the local lineage and deploys only when they differ, so a failed hook run is self-healing.
- `--verify-only`, `--force`, `--dry-run`, `--print-config`, `--target`, `--transcript`, `--log-file`,
  `-v/--verbose`, `-q/--quiet`, `--version`.
- Post-deployment verification over TLS or STARTTLS with retries (`verify`, `verify_strict`).
- Wildcard certificates: `*.example.com` covers `mail.example.com`.
- Cluster support (best effort): `cluster_mode` runs `clustermode ...`, prompts of the form
  `host (Cluster name)>` are handled, and a cluster-level question is answered with
  `cluster_level_answer` or reported as a clear error.
- Test suite (`python3 -m pytest`) that drives the complete dialogue against a fake AsyncOS CLI.
- `ssh_extra_options` for appliances that need legacy SSH algorithms.

### Changed
- Fail-fast: missing configuration is now an error (exit code 2) instead of a silent no-op with
  exit code 0. The `ESA_*` environment variables from v1 still work as a legacy fallback when no
  configuration file exists, but `ESA_HOST`, `ESA_TARGET_DOMAIN` and `ESA_PFX_PASSWORD` are required.
- The PKCS#12 password is passed to OpenSSL through the environment instead of the command line and
  every log line, error message and transcript is redacted.
- SSH is hardened: `BatchMode=yes`, `StrictHostKeyChecking=yes` (configurable `known_hosts_file`),
  `ConnectTimeout`, dedicated `identity_file` with `IdentitiesOnly=yes`.
- The appliance prompt is learned at login and matched exactly; every wait has a timeout and a
  timeout error includes the last output received from the appliance.
- Password authentication now works for the SCP upload as well (both ssh and scp are driven through
  pexpect).
- `scp -O` is only added when the local OpenSSH supports it (`scp_legacy = "auto"`).
- A missing `chain.pem` is derived into a private temporary directory, never into certbot's
  lineage directory.
- INFO messages go to stdout, warnings and errors to stderr, so certbot's own log only records
  real problems.
- After the import the uploaded PKCS#12 (which contains the private key) is overwritten with an
  empty file on the appliance (`cleanup_remote_pfx`).
- Documentation restructured according to the Cisco DevNet Code Exchange template.
- License changed to the Cisco Sample Code License, Version 1.1.

## [1.0.0] - 2025-11-27

- Initial release: certbot deploy-hook driving `certconfig` over SSH with pexpect, configured through
  environment variables.
