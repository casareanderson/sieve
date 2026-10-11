"""Project scanning (lockfiles, node_modules, Python envs), global npm on the host, and the malicious-package tier."""
import json
import os
from pathlib import Path

import pytest

from sieve import cli, osv, projects, rank, sarif, sources

FIX = Path(__file__).resolve().parent / "fixtures"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def pkgjson(d, name, version):
    write(d / "package.json", json.dumps({"name": name, "version": version}))


# ── npm lockfiles ───────────────────────────────────────────────────────────
def test_package_lock_v3():
    lock = {"lockfileVersion": 3, "packages": {
        "": {"name": "app", "version": "1.0.0"},
        "node_modules/left-pad": {"version": "1.3.0"},
        "node_modules/@scope/thing": {"version": "2.0.0"},
        "node_modules/a/node_modules/b": {"version": "0.1.0"},
        "node_modules/local": {"link": True, "resolved": "packages/local"},
        "node_modules/gitdep": {"version": "git+ssh://git@example.com/x.git#abc"},
        "packages/local": {"version": "0.0.1"}}}
    assert sorted(projects.parse_package_lock(json.dumps(lock))) == [
        ("@scope/thing", "2.0.0"), ("b", "0.1.0"), ("left-pad", "1.3.0")]


def test_package_lock_v1_nested():
    lock = {"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
        "c": {"version": "file:../c"}}}
    assert sorted(projects.parse_package_lock(json.dumps(lock))) == [("a", "1.0.0"), ("b", "2.0.0")]


def test_package_lock_not_a_lockfile():
    with pytest.raises(ValueError):
        projects.parse_package_lock("{not json")
    with pytest.raises(ValueError):
        projects.parse_package_lock(json.dumps({"name": "x"}))


def test_yarn_classic_and_berry():
    classic = '''# yarn lockfile v1

"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.22.13"
  resolved "https://registry.yarnpkg.com/x"

lodash@^4.17.20:
  version "4.17.21"
'''
    assert projects.parse_yarn_lock(classic) == [("@babel/code-frame", "7.22.13"), ("lodash", "4.17.21")]
    berry = '''__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.20, lodash@npm:^4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"

"myapp@workspace:.":
  version: 0.0.0-use.local
'''
    assert projects.parse_yarn_lock(berry) == [("lodash", "4.17.21")]


def test_pnpm_versions():
    v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /left-pad/1.3.0:\n    resolution: {integrity: x}\n" \
         "  /@scope/thing/2.0.0_react@18.2.0:\n    resolution: {integrity: y}\n"
    v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: x}\n" \
         "  /@scope/thing@2.0.0(react@18.2.0):\n    dev: false\n"
    v9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n" \
         "packages:\n\n  left-pad@1.3.0:\n    resolution: {integrity: x}\n" \
         "  '@scope/thing@2.0.0':\n    resolution: {integrity: y}\n\nsnapshots:\n\n  left-pad@1.3.0: {}\n"
    want = [("left-pad", "1.3.0"), ("@scope/thing", "2.0.0")]
    for text in (v5, v6, v9):
        assert projects.parse_pnpm_lock(text) == want


def test_pnpm_unknown_version_is_loud():
    with pytest.raises(projects.Unreadable):
        projects.parse_pnpm_lock("lockfileVersion: '10.0'\npackages:\n  x@1.0.0:\n")
    with pytest.raises(projects.Unreadable):
        projects.parse_pnpm_lock("packages:\n  x@1.0.0:\n")


def test_node_modules_tree(tmp_path):
    nm = tmp_path / "node_modules"
    pkgjson(nm / "a", "a", "1.0.0")
    pkgjson(nm / "a" / "node_modules" / "b", "b", "2.0.0")
    pkgjson(nm / "@scope" / "c", "@scope/c", "3.0.0")
    write(nm / ".package-lock.json", "{}")
    assert sorted(projects.node_modules(str(nm))) == [("@scope/c", "3.0.0"), ("a", "1.0.0"), ("b", "2.0.0")]


# ── Python ───────────────────────────────────────────────────────────────────
def test_requirements_pins_only():
    text = """# comment
Django==4.2.1
requests[socks] == 2.31.0 ; python_version >= "3.8"
flask>=2.0
-r other.txt
-e git+https://example.com/x.git#egg=x
urllib3==1.26.5 --hash=sha256:abc
"""
    assert projects.parse_requirements(text) == [("django", "4.2.1"), ("requests", "2.31.0"), ("urllib3", "1.26.5")]


def test_poetry_and_uv_lock():
    poetry = '[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n\n[[package]]\nname = "idna"\nversion = "3.4"\n\n' \
             '[metadata]\nlock-version = "2.0"\n'
    assert projects.parse_toml_packages(poetry) == [("jinja2", "3.1.2"), ("idna", "3.4")]
    uv = '[[package]]\nname = "myapp"\nversion = "0.1.0"\nsource = { editable = "." }\n\n' \
         '[[package]]\nname = "certifi"\nversion = "2023.7.22"\nsource = { registry = "https://pypi.org/simple" }\n'
    assert projects.parse_toml_packages(uv) == [("certifi", "2023.7.22")]


# ── the walk ─────────────────────────────────────────────────────────────────
def test_scan_path_dedup_skip_and_loud_failures(tmp_path):
    app = tmp_path / "app"
    write(app / "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/left-pad": {"version": "1.3.0"}}}))
    pkgjson(app / "node_modules" / "left-pad", "left-pad", "1.3.0")           # same package twice: asked once
    write(app / "requirements.txt", "Django==4.2.1\n")
    sp = app / ".venv" / "lib" / "python3.12" / "site-packages"
    write(sp / "idna-3.4.dist-info" / "METADATA", "Metadata-Version: 2.1\nName: idna\nVersion: 3.4\n\n")
    write(app / ".git" / "package-lock.json", "{broken")                     # .git is never read
    write(app / "web" / "pnpm-lock.yaml", "lockfileVersion: '11.0'\npackages:\n  x@1.0.0:\n")
    t = projects.scan_path(str(app))
    assert t.pkgs == [("PyPI", "django", "4.2.1", "django", "4.2.1"), ("PyPI", "idna", "3.4", "idna", "3.4"),
                      ("npm", "left-pad", "1.3.0", "left-pad", "1.3.0")]
    assert t.status == "partial" and any("pnpm-lock.yaml: not read (lockfileVersion 11.0" in n for n in t.notes)
    assert t.name == f"path:{app}"


def test_scan_path_missing_dir(tmp_path):
    t = projects.scan_path(str(tmp_path / "nope"))
    assert t.status == "error"


# ── global npm on the host ───────────────────────────────────────────────────
def test_host_reads_global_npm_but_not_dpkg_owned(tmp_path):
    root = tmp_path
    write(root / "etc" / "os-release", "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
    write(root / "var" / "lib" / "dpkg" / "status", "")
    pkgjson(root / "usr" / "local" / "lib" / "node_modules" / "pm2", "pm2", "5.3.0")
    pkgjson(root / "usr" / "local" / "lib" / "node_modules" / "pm2" / "node_modules" / "debug", "debug", "4.3.4")
    pkgjson(root / "usr" / "lib" / "node_modules" / "npm", "npm", "9.2.0")      # shipped by Debian's npm package
    write(root / "var" / "lib" / "dpkg" / "info" / "npm.list", "/usr/lib/node_modules/npm\n")
    pkgjson(root / "opt" / "node" / "lib" / "node_modules" / "zx", "zx", "7.2.3")
    write(root / "etc" / "npmrc", "prefix = /opt/node\n")
    t = sources.host(root=str(root))
    npm = sorted((n, v) for e, n, v, _, _ in t.pkgs if e == "npm")
    assert npm == [("debug", "4.3.4"), ("pm2", "5.3.0"), ("zx", "7.2.3")]
    assert "3 global npm packages" in t.notes


# ── known-malicious packages ─────────────────────────────────────────────────
def mal_session(fake):
    d = json.loads((FIX / "osv_malicious_flatmap_stream.json").read_text())
    q = d["query"]
    return fake(hits={(q["ecosystem"], q["name"], q["version"]): d["hits"]}, vulns=d["vulns"])


def test_malicious_one_row_ranked_first(fake):
    pkgs = [("npm", "flatmap-stream", "0.1.1", "flatmap-stream", "0.1.1")]
    rows = osv.match(osv.OSV(":memory:", session=mal_session(fake)), pkgs, set(), target="path:/app")
    assert len(rows) == 1                                   # MAL + two GHSA records → one row
    r = rows[0]
    assert r["id"] == "MAL-2025-20690" and r["malicious"] is True
    assert sorted(r["related"]) == ["GHSA-9x64-5r7x-2q53", "GHSA-mh6f-8j2x-4483"]
    assert r["severity"] == "CRITICAL" and r["fixed"] == "" and r["status"] == "malicious: remove it"
    other = {"id": "CVE-2024-1", "severity": "CRITICAL", "fixed": "1.1", "kev": True, "epss": 0.9, "package": "x",
             "target": "host", "status": "fixed"}
    ranked = rank.rank([other, r])
    assert ranked[0]["id"] == "MAL-2025-20690" and ranked[0]["tier"] == 0 and ranked[1]["tier"] == 1


def test_malicious_never_filtered_and_counted():
    m = {"id": "MAL-1", "severity": "CRITICAL", "fixed": "", "kev": False, "malicious": True, "package": "p",
         "target": "host", "status": "malicious: remove it"}
    for kw in ({"min_severity": "critical"}, {"kev_only": True}, {"fixable_only": True}):
        assert rank.apply_filters([m], **kw) == [m]
    assert rank.summary([m])["malicious"] == 1


def test_is_malicious_cwe506_and_slim_keeps_it():
    assert osv.is_malicious({"id": "MAL-2025-1"})
    assert osv.is_malicious({"id": "GHSA-x", "database_specific": {"cwe_ids": ["CWE-506"]}})
    assert not osv.is_malicious({"id": "GHSA-y", "database_specific": {"cwe_ids": ["CWE-79"]}})
    assert osv.slim({"id": "MAL-2025-1"})["malicious"] is True


def test_malicious_sarif_and_cli(monkeypatch, capsys, tmp_path):
    m = {"id": "MAL-2025-20690", "package": "flatmap-stream", "installed": "0.1.1", "fixed": "", "severity": "CRITICAL",
         "summary": "Malicious code in flatmap-stream (npm)", "kev": False, "malicious": True,
         "status": "malicious: remove it", "target": "path:/app", "details": "", "url": "", "epss": None,
         "epss_percentile": None, "tier": 0}
    doc = sarif.build([], [m], [])
    res, rule = doc["runs"][0]["results"][0], doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert res["level"] == "error" and rule["properties"]["security-severity"] == "10.0"
    assert "malicious" in rule["properties"]["tags"] and "rotate" in res["message"]["text"]
    t = sources.Target("path:/app", "path")
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [dict(m)], []))
    assert cli.main(["path", str(tmp_path), "--cache", str(tmp_path / "c.db")]) == 1
    out = capsys.readouterr().out
    assert "☠ MALWARE" in out and "1 MALICIOUS PACKAGE (remove it" in out and "ALERT" in out


def test_malicious_works_for_os_packages_too(fake):
    """Not npm-only: a MAL- record on an OS package (rare, but OSV allows it) is ranked and folded the same way."""
    eco = ("AlmaLinux:9", "evil-tool", "1.0-1.el9", "evil-tool", "1.0-1.el9")
    s = fake(hits={eco[:3]: ["MAL-2099-1"]}, vulns={"MAL-2099-1": {
        "id": "MAL-2099-1", "modified": "m", "summary": "Malicious code in evil-tool",
        "affected": [{"package": {"ecosystem": "AlmaLinux:9", "name": "evil-tool"},
                      "ranges": [{"events": [{"introduced": "0"}]}]}]}})
    rows = osv.match(osv.OSV(":memory:", session=s), [eco], set(), target="host")
    assert len(rows) == 1 and rows[0]["malicious"] and rank.tier(rows[0]) == 0
