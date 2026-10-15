"""Plain-text secrets: the detectors, the file walk (collect.secrets_report), container environments, the rows they
become, and the paths through `sieve secrets`, `sieve host` and `sieve remote`. Every token here is built at test time
from a seeded generator, so no secret-shaped string sits in the source."""
import base64
import io
import json
import os
import random
import struct
import sys
import tarfile

import pytest

from sieve import cli, collect, exposure, intel, sources

R = random.Random(7)
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def rnd(n, alphabet=ALNUM):
    return "".join(R.choice(alphabet) for _ in range(n))


GH = "gh" + "p_" + rnd(36)
OPENAI = "sk-" + "proj-" + rnd(48)
AWS = "AK" + "IA" + rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
PW = "Tr0ub4dor" + rnd(6)
HDR = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
FTR = "-----END " + "OPENSSH PRIVATE KEY-----"


def openssh_key(cipher):
    blob = b"openssh-key-v1\0" + struct.pack(">I", len(cipher)) + cipher + b"\0" * 64
    return f"{HDR}\n{base64.b64encode(blob).decode()}\n{FTR}\n"


def kinds(text, strict=False):
    return sorted(k for k, _ in collect.find_secrets(text, strict))


# ── detectors ────────────────────────────────────────────────────────────────
def test_token_shapes():
    assert kinds(f"export GITHUB_TOKEN={GH}") == ["GitHub token"]
    assert kinds(f'{{"key": "{OPENAI}"}}') == ["OpenAI key"]
    assert kinds(f"aws_access_key_id = {AWS}") == ["AWS access key"]
    assert kinds(f"DATABASE_URL=postgres://app:{PW}@db:5432/app") == ["password in URL"]
    assert kinds(openssh_key(b"none")) == ["private key"]
    assert kinds(json.dumps({"text": openssh_key(b"none")})) == ["private key"]            # inside a transcript
    assert kinds(f"regex: '{HDR}[\\s\\S]*?'") == []                                    # a scanner's pattern


def test_keyword_values_and_command_lines():
    assert kinds(f"password={PW}") == ["password"]
    assert kinds(f"  db_pass: '{PW}'") == ["password"]
    assert kinds(f"curl -u admin:{PW} https://nas.example/api") == ["password on a command line"]
    assert kinds(f"mysql -uroot -p{PW} app") == ["password on a command line"]


@pytest.mark.parametrize("line", [
    "password=${DB_PASSWORD}", "password: <your password here>", "api_key = os.environ.get('API_KEY')",
    "token: GITHUB_TOKEN", "password_file=/run/secrets/db", "max_tokens: 4096", "password = get_password()",
    "SECRET_KEY=changeme-please-1234", "postgres://postgres:postgres@localhost/db", "https://user:pass@host/x",
    "the weekly social pass: brand-new-things", "values must not be secrets: secret-values", "token= OTHER_VAR=1",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "client_secret: xxxxxxxxxxxxxxxx",
])
def test_references_placeholders_and_prose_are_not_secrets(line):
    assert kinds(line) == []


def test_transcripts_are_stricter():
    short = "pw=" + rnd(9)
    assert kinds(short) == ["password"] or kinds(short) == []
    assert kinds("password: Ab1" + "cd", strict=True) == []


def test_private_key_state():
    assert collect.private_key_state(openssh_key(b"none")) == "unencrypted"
    assert collect.private_key_state(openssh_key(b"aes256-ctr")) == "encrypted"
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----"
    assert collect.private_key_state(pem) == "encrypted"
    assert collect.private_key_state("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----") == ""


# ── the walk ─────────────────────────────────────────────────────────────────
def make_root(tmp_path):
    def w(rel, text, mode=0o600):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(p, mode)
        return p
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/passwd").write_text("root:x:0:0::/root:/bin/bash\nana:x:1000:1000::/home/ana:/bin/bash\n")
    (tmp_path / "etc/group").write_text("root:x:0:\nana:x:1000:\nops:x:2000:ana\n")
    w("root/.bash_history", f"ls\ncurl -u admin:{PW} https://nas.example/api\n")
    w("root/.claude/projects/p/s.jsonl", '{"type":"user"}\n' + json.dumps({"text": f"use {OPENAI} for it"}) + "\n")
    w("root/.claude/.credentials.json", json.dumps({"token": OPENAI}))           # its own login store, 0600
    w("root/.ssh/id_ed25519", openssh_key(b"none"))
    w("root/.ssh/id_rsa_locked", openssh_key(b"aes256-ctr"))
    w("root/.ssh/id_ed25519.pub", "ssh-ed25519 AAAA")
    w("home/ana/app/.env", f"GITHUB_TOKEN={GH}\n", 0o644)
    w("home/ana/app/.env.example", f"GITHUB_TOKEN={GH}\n", 0o644)
    w("home/ana/app/.mcp.json", json.dumps({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}}), 0o640)
    w("home/ana/app/node_modules/x/.env", f"GITHUB_TOKEN={GH}\n", 0o644)
    w("etc/app/app.conf", f"[db]\npassword = {PW}\n", 0o644)
    w("etc/ssl/private/site.key", openssh_key(b"none"))                       # a service's key, 0600: fine
    os.chmod(tmp_path / "root", 0o700)
    for d in (tmp_path, tmp_path / "home", tmp_path / "etc", tmp_path / "etc/app"):    # pytest makes tmp dirs 0700
        os.chmod(d, 0o755)
    os.chmod(tmp_path / "home/ana", 0o755)
    os.chmod(tmp_path / "home/ana/app", 0o755)
    return str(tmp_path)


def by_path(rep):
    return {f["path"]: f for f in rep["files"]}


def test_secrets_report(tmp_path):
    root = make_root(tmp_path)
    rep = collect.secrets_report(root, "k" * 64)
    got = by_path(rep)
    assert set(got) == {"/root/.bash_history", "/root/.claude/projects/p/s.jsonl", "/root/.ssh/id_ed25519",
                        "/home/ana/app/.env", "/home/ana/app/.mcp.json", "/etc/app/app.conf"}
    assert got["/root/.bash_history"]["where"] == "history" and got["/root/.bash_history"]["line"] == 2
    chat = got["/root/.claude/projects/p/s.jsonl"]
    assert chat["where"] == "agent-chat" and chat["agent"] == "Claude Code" and chat["kinds"] == ["OpenAI key"]
    assert got["/home/ana/app/.env"]["reach"] == "world" and got["/home/ana/app/.env"]["mode"] == "0644"
    assert got["/etc/app/app.conf"]["reach"] == "world"
    assert got["/root/.ssh/id_ed25519"]["reach"] == "owner"
    assert got["/home/ana/app/.mcp.json"]["where"] == "agent-config"
    assert got["/home/ana/app/.mcp.json"]["reach"] == "owner"           # group ana is ana's own group
    blob = json.dumps(rep)
    for secret in (GH, OPENAI, PW, AWS):
        assert secret not in blob                                       # never the value
    assert all(len(f["fp"]) == 8 for f in rep["files"])


def test_a_closed_directory_keeps_a_readable_file_private(tmp_path):
    root = make_root(tmp_path)
    p = tmp_path / "root/.env"
    p.write_text(f"TOKEN={GH}\n")
    os.chmod(p, 0o644)
    assert by_path(collect.secrets_report(root))["/root/.env"]["reach"] == "owner"     # /root is 0700


def test_group_reach(tmp_path):
    root = make_root(tmp_path)
    p = tmp_path / "home/ana/app/.env"
    os.chown(p, os.getuid(), 2000) if os.geteuid() == 0 else pytest.skip("chown needs root")
    os.chmod(p, 0o640)
    assert by_path(collect.secrets_report(root))["/home/ana/app/.env"]["reach"] == "group:ops"


def test_fingerprints(tmp_path):
    root = make_root(tmp_path)
    a = by_path(collect.secrets_report(root, "a" * 64))
    b = by_path(collect.secrets_report(root, "a" * 64))
    c = by_path(collect.secrets_report(root, "b" * 64))
    assert a["/home/ana/app/.env"]["fp"] == b["/home/ana/app/.env"]["fp"] != c["/home/ana/app/.env"]["fp"]
    assert by_path(collect.secrets_report(root))["/home/ana/app/.env"]["fp"] == ""


def test_world_readable_login_store_is_reported(tmp_path):
    root = make_root(tmp_path)
    os.chmod(tmp_path / "root", 0o755)
    os.chmod(tmp_path / "root/.claude", 0o755)
    os.chmod(tmp_path / "root/.claude/.credentials.json", 0o644)
    f = by_path(collect.secrets_report(root))["/root/.claude/.credentials.json"]
    assert f["where"] == "agent-config" and f["login_store"] and f["reach"] == "world"


def test_dirs_only(tmp_path):
    root = make_root(tmp_path)
    rep = collect.secrets_report(root, dirs=[str(tmp_path / "home/ana/app")])
    assert {os.path.basename(f["path"]) for f in rep["files"]} == {".env", ".mcp.json"}


# ── rows ─────────────────────────────────────────────────────────────────────
def test_rows(tmp_path):
    rep = collect.secrets_report(make_root(tmp_path), "k" * 64)
    rows, note = exposure.secrets(rep, "host")
    sev = {r["package"]: (r["id"], r["severity"]) for r in rows}
    assert sev["/home/ana/app/.env"] == ("SIEVE-SECRET-IN-FILE", "HIGH")
    assert sev["/root/.bash_history"] == ("SIEVE-SECRET-IN-HISTORY", "MEDIUM")
    assert sev["/root/.claude/projects/p/s.jsonl"] == ("SIEVE-SECRET-IN-AGENT-CHAT", "MEDIUM")
    assert sev["/root/.ssh/id_ed25519"] == ("SIEVE-SECRET-PRIVATE-KEY", "LOW")
    env = next(r for r in rows if r["package"] == "/home/ana/app/.env")
    assert env["fixed"].startswith("chmod 600 /home/ana/app/.env") and "readable by every user" in env["summary"]
    assert all(r["status"] == "exposure" and r["url"].endswith(r["id"].lower()) for r in rows)
    assert exposure.secrets({"checked": False, "note": "x"}, "host") == ([], "x")


def test_container_env():
    env = [f"GITHUB_TOKEN={GH}", "DB_PASSWORD_FILE=/run/secrets/db", "PATH=/usr/bin", "GPG_KEY=ABCDEF0123456789",
           f"DATABASE_URL=postgres://app:{PW}@db/app", "REDIS_PASSWORD=", "MODE=prod", f"API_KEY={PW}",
           "ADMIN_PASSWORD=changeme"]
    found, fp = collect.env_secrets(env, baked=["GPG_KEY=ABCDEF0123456789"], salt="s" * 64)
    assert [v["var"] for v in found] == ["GITHUB_TOKEN", "DATABASE_URL", "API_KEY"]
    assert len(fp) == 8 and GH not in json.dumps(found)
    rows = exposure.container_env([{"container": "app", "vars": found, "fp": fp}], "example/app:1")
    assert rows[0]["id"] == "SIEVE-SECRET-IN-CONTAINER-ENV" and rows[0]["package"] == "container:app"
    assert "GITHUB_TOKEN, DATABASE_URL, API_KEY" in rows[0]["installed"]


def test_image_target_reads_container_env():
    entry = [{"container": "app", "vars": [{"var": "API_KEY", "kinds": ["secret"]}], "fp": "abcd1234"}]
    t = sources.image_target("example/app:1", {"secrets": json.dumps(entry).encode()})
    assert [f["id"] for f in t.exposures] == ["SIEVE-SECRET-IN-CONTAINER-ENV"]
    assert sources.image_target("example/app:1", {"secrets": json.dumps(entry).encode()}, secrets=False).exposures == []


# ── the key, the collector, the CLI ──────────────────────────────────────────
def test_secret_key(tmp_path):
    cache = str(tmp_path / "c/sieve.db")
    k = sources.secret_key(cache)
    assert len(k) == 64 and sources.secret_key(cache) == k
    assert os.stat(tmp_path / "c/secrets.key").st_mode & 0o777 == 0o600


def test_salted_collector_sees_its_key():
    g = {"__name__": "not_main"}
    exec(compile(sources.salted(sources.collector_source(), "f" * 64), "collect", "exec"), g)
    assert g["SALT"] == "f" * 64
    g = {"__name__": "not_main"}
    exec(compile(sources.salted(sources.collector_source(), None), "collect", "exec"), g)
    assert g["SALT"] is None


def test_remote_host_mode_carries_secrets(tmp_path, monkeypatch):
    root = make_root(tmp_path)
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", type("Out", (), {"buffer": buf})())
    collect.host_main(root)
    monkeypatch.undo()
    names = tarfile.open(fileobj=io.BytesIO(buf.getvalue())).getnames()
    assert "secrets" in names
    assert GH.encode() not in buf.getvalue() and PW.encode() not in tarfile.open(
        fileobj=io.BytesIO(buf.getvalue())).extractfile("secrets").read()
    t = sources.read_host(io.BytesIO(buf.getvalue()), "nas")
    assert {f["id"] for f in t.exposures} >= {"SIEVE-SECRET-IN-FILE", "SIEVE-SECRET-IN-HISTORY"}
    buf2 = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", type("Out", (), {"buffer": buf2})())
    collect.host_main(root, secrets=False)
    monkeypatch.undo()
    assert "secrets" not in tarfile.open(fileobj=io.BytesIO(buf2.getvalue())).getnames()


def test_cli_secrets_dir_never_goes_online(tmp_path, monkeypatch, capsys):
    root = make_root(tmp_path)
    monkeypatch.setattr(intel, "epss_scores", lambda *a, **k: pytest.fail("EPSS fetched for a secrets scan"))
    monkeypatch.setattr(intel, "kev_set", lambda *a, **k: pytest.fail("KEV fetched for a secrets scan"))
    rc = cli.main(["secrets", os.path.join(root, "home/ana/app"), "--cache", str(tmp_path / "c/sieve.db"), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and {f["id"] for f in out["findings"]} == {"SIEVE-SECRET-IN-FILE", "SIEVE-SECRET-IN-AGENT-CONFIG"}
    assert GH not in json.dumps(out)


def test_cli_table_keeps_the_file_name(tmp_path, monkeypatch, capsys):
    deep = tmp_path / "a/very/long/directory/name/that/goes/on"
    deep.mkdir(parents=True)
    (deep / ".env").write_text(f"GITHUB_TOKEN={GH}\n")
    cli.main(["secrets", str(tmp_path), "--cache", str(tmp_path / "c/sieve.db")])
    out = capsys.readouterr().out
    assert "…" in out and "on/.env" in out and GH not in out


def test_source_trees_translations_and_repos_are_not_read_for_examples(tmp_path):
    root = make_root(tmp_path)

    def w(rel, text, mode=0o644):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        os.chmod(p, mode)
    w("opt/app/locales/es.json", '{"password": "Contraseña"}')
    w("opt/app/locales/de.json", f'{{"password": "{PW}"}}')                  # even a secret-shaped one
    w("opt/repo/.git/HEAD", "ref: refs/heads/main\n")
    w("opt/repo/api.yml", f"password: {PW}\n")
    w("opt/repo/.env", f"API_KEY={PW}\n")
    w("opt/repo/tests/key.pem", openssh_key(b"none"))
    w("home/ana/.hermes/backups/full.json", f'{{"password": "{PW}"}}', 0o600)
    w("home/ana/.hermes/auth.json", f'{{"secret": "{PW}"}}', 0o600)
    w("home/ana/.hermes/youtube-token.json", f'{{"access_token": "{PW}"}}', 0o600)
    w("home/ana/notes/app.yml", f"password: {PW}\n", 0o600)                # not under a dot-dir: not read
    got = by_path(collect.secrets_report(root))
    assert "/opt/repo/.env" in got and "/opt/repo/api.yml" not in got and "/opt/repo/tests/key.pem" not in got
    assert not any("/locales/" in p for p in got)
    assert got["/home/ana/.hermes/backups/full.json"]["where"] == "file"
    assert got["/home/ana/.hermes/youtube-token.json"]["where"] == "file"
    assert "/home/ana/.hermes/auth.json" not in got                          # Hermes' own login store, 0600
    assert "/home/ana/notes/app.yml" not in got
