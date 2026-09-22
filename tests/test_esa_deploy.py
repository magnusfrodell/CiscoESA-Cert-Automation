"""
Tests for esa_deploy.py. Run with:  python3 -m pytest -q

Copyright (c) 2026 Cisco and/or its affiliates.
Licensed under the Cisco Sample Code License, Version 1.1 - see LICENSE.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import esa_deploy as ed  # noqa: E402

pexpect = pytest.importorskip("pexpect")
FAKE = os.path.join(HERE, "fake_esa.py")


# --------------------------------------------------------------------------- helpers

@pytest.fixture(autouse=True)
def fresh_redactor(monkeypatch):
    """Secrets registered by one test must not leak into (or mask) another."""
    monkeypatch.setattr(ed, "REDACTOR", ed.SecretRedactor())

def fake_spawn(*flags: str):
    def spawn():
        return pexpect.spawn(sys.executable, ["-u", FAKE, *flags], encoding="utf-8",
                             codec_errors="replace", timeout=10)
    return spawn


def make_target(**overrides) -> ed.TargetConfig:
    values = dict(name="esa1", host="esa.test", target_domains=["mail.example.com"],
                  pfx_password="pfxsecret", cli_timeout=8, commit_timeout=8, connect_timeout=2)
    values.update(overrides)
    return ed.TargetConfig(**values)


@pytest.fixture
def lineage(tmp_path):
    """A certbot-like lineage with a self-signed leaf and a fake intermediate."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    live = tmp_path / "live" / "mail.example.com"
    live.mkdir(parents=True)

    def gen(name: str, subject: str):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-subj", subject, "-keyout", str(tmp_path / f"{name}.key"),
                        "-out", str(tmp_path / f"{name}.pem")], check=True, capture_output=True)

    gen("leaf", "/CN=mail.example.com")
    gen("ca", "/CN=Fake Intermediate")
    shutil.copy(tmp_path / "leaf.pem", live / "cert.pem")
    shutil.copy(tmp_path / "leaf.key", live / "privkey.pem")
    shutil.copy(tmp_path / "ca.pem", live / "chain.pem")
    (live / "fullchain.pem").write_text((live / "cert.pem").read_text() + (live / "chain.pem").read_text())
    return live


class RecordingTransport:
    """Stands in for SshTransport: records uploads, spawns the fake appliance."""

    uploads: list = []

    def __init__(self, target, flags=()):
        self.target = target
        self.flags = flags

    def upload(self, local_path, remote_path):
        RecordingTransport.uploads.append((os.path.basename(local_path), remote_path, os.path.getsize(local_path)))

    def spawn_shell(self):
        return fake_spawn(*self.flags)()


# --------------------------------------------------------------------------- pure functions

def test_split_pem_and_ensure_chain(tmp_path):
    block = lambda n: f"-----BEGIN CERTIFICATE-----\nAAA{n}\n-----END CERTIFICATE-----\n"  # noqa: E731
    lineage_dir = tmp_path / "lineage"
    lineage_dir.mkdir()
    (lineage_dir / "fullchain.pem").write_text(block(1) + block(2) + block(3))
    chain = ed.ensure_chain(str(lineage_dir), str(tmp_path))
    assert chain == str(tmp_path / "chain.pem")          # derived into the work dir, not the lineage
    assert not (lineage_dir / "chain.pem").exists()
    derived = ed.split_pem_certificates((tmp_path / "chain.pem").read_text())
    assert derived == [block(2), block(3)]


def test_ensure_chain_prefers_existing(tmp_path):
    (tmp_path / "chain.pem").write_text("x")
    assert ed.ensure_chain(str(tmp_path), str(tmp_path / "work")) == str(tmp_path / "chain.pem")


def test_ensure_chain_without_intermediates(tmp_path):
    (tmp_path / "fullchain.pem").write_text("-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n")
    with pytest.raises(ed.DeployError):
        ed.ensure_chain(str(tmp_path), str(tmp_path))


@pytest.mark.parametrize("targets, renewed, expected", [
    (["mail.example.com"], ["mail.example.com"], True),
    (["mail.example.com"], ["www.example.com", "MAIL.example.com."], True),
    (["mail.example.com"], ["*.example.com"], True),
    (["sub.mail.example.com"], ["*.example.com"], False),   # wildcard covers one label only
    (["mail.example.com"], ["example.com"], False),
    (["mail.example.com"], [], False),
])
def test_domain_covered(targets, renewed, expected):
    assert ed.domain_covered(targets, renewed) is expected


def test_redactor_masks_longest_first_and_ignores_tiny_secrets():
    r = ed.SecretRedactor()
    r.add("secret")
    r.add("secret-longer")
    r.add("ab")
    assert r.redact("x secret-longer y secret z ab") == "x ****** y ****** z ab"
    assert r.redact("nothing") == "nothing"


@pytest.mark.parametrize("spec, host, port, starttls", [
    ("mail.example.com:443", "mail.example.com", 443, False),
    ("mail.example.com:25", "mail.example.com", 25, True),
    ("mail.example.com:587", "mail.example.com", 587, True),
    ("mail.example.com:8443:tls", "mail.example.com", 8443, False),
    ("mail.example.com:2525:starttls", "mail.example.com", 2525, True),
])
def test_parse_verify_endpoint(spec, host, port, starttls):
    ep = ed.parse_verify_endpoint(spec)
    assert (ep.host, ep.port, ep.starttls) == (host, port, starttls)


@pytest.mark.parametrize("spec", ["nohost", ":443", "h:abc", "h:443:ssl"])
def test_parse_verify_endpoint_invalid(spec):
    with pytest.raises(ed.ConfigError):
        ed.parse_verify_endpoint(spec)


# --------------------------------------------------------------------------- configuration

def write_config(tmp_path, body: str) -> str:
    path = tmp_path / "config.toml"
    path.write_text(textwrap.dedent(body))
    os.chmod(path, 0o600)
    return str(path)


def test_load_config_merges_defaults(tmp_path):
    secret = tmp_path / "pfx.pass"
    secret.write_text("filesecret\n")
    os.chmod(secret, 0o600)
    path = write_config(tmp_path, f"""
        [defaults]
        user = "automation"
        pfx_password_file = "{secret}"
        verify_strict = true
        ssh_extra_options = ["HostKeyAlgorithms=+ssh-rsa"]

        [[targets]]
        name = "esa1"
        host = "esa1.example.com"
        target_domains = ["mail.example.com", "MX.Example.com."]
        verify = ["mail.example.com:443", "esa1.example.com:25"]

        [[targets]]
        host = "esa2.example.com"
        target_domain = "mail.example.com"
        user = "admin"
        pfx_password = "inline"
        cluster_mode = "machine"
        """)
    targets = ed.load_config_file(path)
    assert [t.name for t in targets] == ["esa1", "esa2.example.com"]
    esa1, esa2 = targets
    assert esa1.user == "automation" and esa2.user == "admin"
    assert esa1.pfx_password == "filesecret" and esa2.pfx_password == "inline"
    assert esa1.target_domains == ["mail.example.com", "mx.example.com"]
    assert esa1.verify_strict is True and esa2.verify_strict is True
    assert esa1.ssh_extra_options == ["HostKeyAlgorithms=+ssh-rsa"]
    assert esa2.cluster_mode == "machine"
    assert esa2.lineage_path() == "/etc/letsencrypt/live/mail.example.com"
    assert "filesecret" not in ed.describe_targets(targets)


@pytest.mark.parametrize("body, message", [
    ("[[targets]]\nhost = 'h'\npfx_password = 'p'\n", "target_domains is required"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\n", "pfx_password is required"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\nbogus = 1\n", "unknown key"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\nauth = 'password'\n", "requires password"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\nport = 'x'\n", "must be an integer"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\nprofile_name = 'bad name'\n", "profile_name"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\nverify = ['h:x']\n", "invalid port"),
    ("[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\n"
     "[[targets]]\nhost = 'h'\ntarget_domain = 'd'\npfx_password = 'p'\n", "duplicate"),
    ("[defaults]\nx = 1\n", "at least one"),
    ("this is not toml", "invalid TOML"),
])
def test_load_config_errors(tmp_path, body, message):
    path = write_config(tmp_path, body)
    with pytest.raises(ed.ConfigError, match=message):
        ed.load_config_file(path)


def test_load_targets_missing_file_and_legacy_env(tmp_path, monkeypatch):
    monkeypatch.delenv("ESA_HOST", raising=False)
    monkeypatch.delenv(ed.CONFIG_ENV_VAR, raising=False)
    with pytest.raises(ed.ConfigError, match="config file not found"):
        ed.load_targets(str(tmp_path / "missing.toml"))

    monkeypatch.setattr(ed, "DEFAULT_CONFIG_PATH", str(tmp_path / "nope.toml"))
    monkeypatch.setenv("ESA_HOST", "esa.example.com")
    with pytest.raises(ed.ConfigError, match="ESA_TARGET_DOMAIN, ESA_PFX_PASSWORD"):
        ed.load_targets(None)

    monkeypatch.setenv("ESA_TARGET_DOMAIN", "mail.example.com")
    monkeypatch.setenv("ESA_PFX_PASSWORD", "legacy")
    monkeypatch.setenv("ESA_USE_PASSWORD", "true")
    monkeypatch.setenv("ESA_PASSWORD", "adminpw")
    (target,) = ed.load_targets(None)
    assert target.host == "esa.example.com" and target.auth == "password" and target.password == "adminpw"


def test_select_targets():
    a, b = make_target(name="a"), make_target(name="b")
    assert ed.select_targets([a, b], ["b"]) == [b]
    with pytest.raises(ed.ConfigError, match="unknown target"):
        ed.select_targets([a, b], ["c"])


# --------------------------------------------------------------------------- PKI

def test_build_pfx_and_fingerprint(tmp_path, lineage):
    work = tmp_path / "work"
    work.mkdir()
    pfx = ed.build_pfx(str(lineage), "pfxsecret", str(work))
    assert os.stat(pfx).st_mode & 0o777 == 0o600
    proc = subprocess.run(["openssl", "pkcs12", "-in", pfx, "-passin", "pass:pfxsecret", "-nokeys"],
                          capture_output=True, text=True, check=True)
    assert proc.stdout.count("BEGIN CERTIFICATE") == 2          # leaf + intermediate
    fp = ed.local_cert_fingerprint(str(lineage / "cert.pem"))
    expected = subprocess.run(["openssl", "x509", "-in", str(lineage / "cert.pem"), "-noout",
                               "-fingerprint", "-sha256"], capture_output=True, text=True, check=True).stdout
    assert fp == expected.split("=")[1].strip().replace(":", "").lower()


def test_build_pfx_wrong_password_is_rejected(tmp_path, lineage):
    pfx = ed.build_pfx(str(lineage), "pfxsecret", str(tmp_path))
    proc = subprocess.run(["openssl", "pkcs12", "-in", pfx, "-passin", "pass:wrong", "-nokeys"],
                          capture_output=True, text=True)
    assert proc.returncode != 0


# --------------------------------------------------------------------------- SSH command lines

def test_ssh_argv_key_mode():
    t = make_target(identity_file="/root/.ssh/esa", known_hosts_file="/etc/esa-deploy/known_hosts",
                    ssh_extra_options=["KexAlgorithms=+diffie-hellman-group14-sha1"], port=2222, scp_legacy="yes")
    tr = ed.SshTransport(t)
    ssh = tr.ssh_argv()
    assert ssh[:3] == ["ssh", "-p", "2222"] and ssh[-1] == "admin@esa.test"
    assert "BatchMode=yes" in ssh and "StrictHostKeyChecking=yes" in ssh
    assert ssh[ssh.index("-i") + 1] == "/root/.ssh/esa" and "IdentitiesOnly=yes" in ssh
    assert "UserKnownHostsFile=/etc/esa-deploy/known_hosts" in ssh
    assert "KexAlgorithms=+diffie-hellman-group14-sha1" in ssh
    scp = tr.scp_argv("/tmp/x.pfx", "/configuration/esacertpfx")
    assert scp[:2] == ["scp", "-O"] and scp[-2:] == ["/tmp/x.pfx", "admin@esa.test:/configuration/esacertpfx"]
    assert "-P" in scp and scp[scp.index("-P") + 1] == "2222"


def test_ssh_argv_password_mode_and_no_legacy():
    t = make_target(auth="password", password="pw", scp_legacy="no", strict_host_key=False)
    tr = ed.SshTransport(t)
    ssh = tr.ssh_argv()
    assert "BatchMode=no" in ssh and "PubkeyAuthentication=no" in ssh and "StrictHostKeyChecking=accept-new" in ssh
    assert "-O" not in tr.scp_argv("a", "b")


# --------------------------------------------------------------------------- CLI dialogue (fake appliance)

def run_session(target, *flags, expect_commit=True):
    with ed.EsaSession(target, spawn_fn=fake_spawn(*flags)) as session:
        session.set_cluster_mode()
        session.import_pfx("esacertpfx")
        session.leave_certconfig()
        committed = session.commit("test commit")
        session.logout()
    assert committed is expect_commit
    return session


def test_dialogue_new_profile():
    session = run_session(make_target())
    assert session.prompt_text == "esa.test"


def test_dialogue_existing_profile_with_fqdn_questions():
    run_session(make_target(), "--existing-profile", "--fqdn-before", "--fqdn-after")


def test_dialogue_no_data_to_commit():
    run_session(make_target(), "--no-data-commit", expect_commit=False)


def test_dialogue_no_rollback_question_and_exit_question():
    run_session(make_target(), "--no-rollback-question", "--exit-question")


def test_dialogue_password_login():
    run_session(make_target(auth="password", password="adminpw"), "--password-login")


def test_dialogue_wrong_login_password():
    t = make_target(auth="password", password="wrong")
    with pytest.raises(ed.DeployError, match="rejected the password"):
        with ed.EsaSession(t, spawn_fn=fake_spawn("--password-login")):
            pass


def test_dialogue_wrong_pfx_password_reports_appliance_message():
    t = make_target(pfx_password="wrong")
    with pytest.raises(ed.DeployError, match="Invalid pass phrase"):
        run_session(t)


def test_dialogue_missing_remote_file():
    with pytest.raises(ed.DeployError, match="does not exist"):
        run_session(make_target(), "--missing-file")


def test_dialogue_bad_profile_name_reported():
    t = make_target(profile_name="bad+name")  # bypasses config validation on purpose
    with pytest.raises(ed.DeployError, match="Symbols are not allowed"):
        run_session(t)


def test_dialogue_cluster_prompt_and_inline_clustermode():
    t = make_target(cluster_mode="machine")
    session = run_session(t, "--cluster")
    assert session.prompt_text == "esa.test (Machine esa.test)"


def test_dialogue_cluster_menu_fallback_selects_machine_by_name():
    t = make_target(cluster_mode="machine", cluster_name="esa2.test")
    session = run_session(t, "--cluster", "--clustermode-menu")
    assert session.prompt_text == "esa.test (Machine esa2.test)"


def test_dialogue_cluster_level_question_requires_answer():
    with pytest.raises(ed.DeployError, match="cluster_level_answer"):
        run_session(make_target(), "--cluster", "--cluster-level-question")
    run_session(make_target(cluster_level_answer="C"), "--cluster", "--cluster-level-question")


def test_timeout_reports_last_output():
    """An appliance that never shows the CERTIFICATE menu -> DeployError with the last output."""
    t = make_target(cli_timeout=2, profile_name="lets_encrypt_mail")

    class Stuck(ed.EsaSession):
        CERTCONFIG_MENU = ed._rx(r"NEVER-MATCHES")

    with pytest.raises(ed.DeployError, match="timed out after 2s waiting for certconfig menu") as info:
        with Stuck(t, spawn_fn=fake_spawn()) as session:
            session.import_pfx("esacertpfx")
    assert "CERTAUTHORITY" in str(info.value)     # the last output is included for troubleshooting


def test_transcript_is_redacted(tmp_path):
    transcript = tmp_path / "session.log"
    t = make_target(auth="password", password="adminpw")
    ed.REDACTOR.add("adminpw")
    ed.REDACTOR.add("pfxsecret")
    with ed.EsaSession(t, spawn_fn=fake_spawn("--password-login"), transcript=str(transcript)) as session:
        session.import_pfx("esacertpfx")
        session.leave_certconfig()
        session.commit("c")
        session.logout()
    text = transcript.read_text()
    assert "certconfig" in text and "Changes committed" in text
    assert "adminpw" not in text and "pfxsecret" not in text
    assert os.stat(transcript).st_mode & 0o777 == 0o600


# --------------------------------------------------------------------------- end to end (minus the network)

def test_deploy_target_end_to_end(tmp_path, lineage, monkeypatch):
    RecordingTransport.uploads.clear()
    t = make_target(remote_pfx_path="/configuration/esacertpfx", cleanup_remote_pfx=True)
    ed.deploy_target(t, str(lineage), transcript=str(tmp_path / "t.log"),
                     transport_factory=lambda target: RecordingTransport(target, ("--existing-profile",)))
    names = [(name, remote) for name, remote, _ in RecordingTransport.uploads]
    assert names == [("esacert.pfx", "/configuration/esacertpfx"), ("empty", "/configuration/esacertpfx")]
    assert RecordingTransport.uploads[0][2] > 0 and RecordingTransport.uploads[1][2] == 0


def test_deploy_target_dry_run_does_not_connect(lineage):
    RecordingTransport.uploads.clear()
    t = make_target()
    ed.deploy_target(t, str(lineage), dry_run=True,
                     transport_factory=lambda target: RecordingTransport(target))
    assert RecordingTransport.uploads == []


def test_run_hook_skips_uncovered_and_reports_failures(lineage, monkeypatch, caplog):
    calls = []

    def fake_deploy(target, lineage_dir, **_kwargs):
        calls.append(target.name)
        if target.name == "bad":
            raise ed.DeployError("boom")

    monkeypatch.setattr(ed, "deploy_target", fake_deploy)
    targets = [make_target(name="good"), make_target(name="bad"),
               make_target(name="other", target_domains=["other.example.net"])]
    context = ed.CertbotContext(str(lineage), ["mail.example.com"])
    args = ed.parse_args(["--dry-run"])
    assert ed.run_hook(targets, context, args) == ed.EXIT_FAILED
    assert calls == ["good", "bad"]


def test_main_exit_codes(tmp_path, monkeypatch):
    monkeypatch.delenv("ESA_HOST", raising=False)
    assert ed.main(["--config", str(tmp_path / "missing.toml")]) == ed.EXIT_CONFIG
    path = write_config(tmp_path, "[[targets]]\nhost='h'\ntarget_domain='d'\npfx_password='p'\n")
    monkeypatch.delenv("RENEWED_LINEAGE", raising=False)
    monkeypatch.delenv("RENEWED_DOMAINS", raising=False)
    assert ed.main(["--config", path]) == ed.EXIT_CONFIG          # no certbot environment
    assert ed.main(["--config", path, "--print-config"]) == ed.EXIT_OK
    assert ed.main(["--config", path, "--lineage", "/nonexistent", "--domains", "d"]) == ed.EXIT_FAILED


def test_lineage_and_domains_must_go_together():
    with pytest.raises(SystemExit):
        ed.parse_args(["--lineage", "/x"])
