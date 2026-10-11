"""`sieve remote`: the ssh command, the collector's host mode, and the CLI path with ssh faked (no network)."""
import io
import json
import sys
import tarfile

from sieve import cli, collect, intel, inuse, osv, projects, sources

from test_rpm import PKGS, sqlite_db  # noqa: E402 — the rpm fixtures, so the remote path reads the same databases

STATUS = ("Package: bash\nStatus: install ok installed\nVersion: 5.2.37-1\n\n"
          "Package: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.12.1-1\n\n"
          "Package: python3-requests\nStatus: install ok installed\nSource: requests\nVersion: 2.32.3+dfsg-1\n")


def tgz(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|gz") as tf:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


HOST_TAR = tgz([("os/etc_os-release", b'ID=debian\nVERSION_ID="13"\n'),
                ("os/var_lib_dpkg_status", STATUS.encode()),
                ("owned", b"/usr/lib/python3/dist-packages/requests-2.32.3.dist-info"),
                ("py/1", b"/usr/lib/python3/dist-packages/requests-2.32.3.dist-info\nrequests\n2.32.3"),
                ("py/2", b"/usr/local/lib/python3.13/dist-packages/flask-2.0.0.dist-info\nFlask\n2.0.0")])
CTR_TAR = tgz([("1/IMAGE", b"example/app:1"), ("1/os/etc_alpine-release", b"3.18.0\n"),
               ("1/os/etc_os-release", b"ID=alpine\nVERSION_ID=3.18.0\n"),
               ("1/os/lib_apk_db_installed", b"P:busybox\nV:1.36.0-r9\no:busybox\n\n"), ("ERRORS", b"")])


def host_mode_tar(monkeypatch, root):
    """Run the collector's host mode against a fixture root, as `python3 - host` would on the remote machine."""
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", type("Out", (), {"buffer": buf})())
    collect.host_main(str(root))
    monkeypatch.undo()
    return buf.getvalue()


def test_ssh_command():
    c = sources.ssh_command("me@nas.example.com", port=2222, identity="/k", opts=["ProxyJump=bastion"], mode="host")
    assert c[:5] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    assert c[c.index("-p") + 1] == "2222" and c[c.index("-i") + 1] == "/k" and "ProxyJump=bastion" in c
    assert c[-3:] == ["--", "me@nas.example.com", "python3 -I - host"]
    assert sources.ssh_command("me@h", sudo=True)[-1] == "sudo -n python3 -I -"


def test_one_file_list_for_local_and_remote():
    assert sources.PY_DIRS is collect.PY_DIRS and sources.HOST_FILES is collect.HOST_FILES
    assert sources.NPM_DIRS is collect.NPM_DIRS and sources.NPMRC is collect.NPMRC
    assert projects.node_modules is collect.node_modules
    assert set(collect.HOST_FILES) <= set(sources.NAMED.values())


def test_read_host_matches_local_rules():
    t = sources.read_host(io.BytesIO(HOST_TAR), "nas")
    assert t.name == "nas" and t.kind == "host" and t.os == "debian 13"
    assert ("Debian:13", "bash", "5.2.37-1", "bash", "5.2.37-1") in t.pkgs
    assert ("PyPI", "Flask", "2.0.0", "Flask", "2.0.0") in t.pkgs
    assert not any(p[0] == "PyPI" and p[1] == "requests" for p in t.pkgs)   # dpkg-owned: distro advisories cover it
    assert not any(p[1] == "linux" for p in t.pkgs) and any("kernel" in n for n in t.notes)


def test_remote_rpm_host_same_as_local(monkeypatch, tmp_path):
    """An rpm machine over `sieve remote` reads the same packages, and skips the same rpm-owned Python, as `sieve host`
    on that machine."""
    r = tmp_path
    (r / "etc").mkdir()
    (r / "etc/os-release").write_text('ID="almalinux"\nVERSION_ID="9.3"\n')
    sqlite_db(str(r / "usr/lib/sysimage/rpm/rpmdb.sqlite"))
    for d, name in (("usr/lib/python3.9/site-packages", "dnf"), ("usr/local/lib/python3.9/site-packages", "flask")):
        p = r / d / f"{name}-1.0.dist-info"
        p.mkdir(parents=True)
        (p / "METADATA").write_text(f"Name: {name}\nVersion: 1.0\n")
    remote = sources.read_host(io.BytesIO(host_mode_tar(monkeypatch, r)), "alma")
    local = sources.host(root=str(r))
    assert remote.pkgs == local.pkgs and remote.packages == local.packages == 3 and remote.status == "ok"
    assert ("AlmaLinux:9", "openssl-libs", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9") in remote.pkgs
    assert ("PyPI", "flask", "1.0", "flask", "1.0") in remote.pkgs
    assert not any(p[1] == "dnf" for p in remote.pkgs)                      # came with an rpm
    assert len(PKGS) == 3                                                   # gpg-pubkey is not a package


def test_remote_unreadable_rpmdb_is_partial_never_empty(monkeypatch, tmp_path):
    r = tmp_path
    (r / "etc").mkdir()
    (r / "etc/os-release").write_text('ID="rocky"\nVERSION_ID="8.9"\n')
    (r / "var/lib/rpm").mkdir(parents=True)
    (r / "var/lib/rpm/Packages").write_bytes(b"\0" * 4096)                  # neither ndb nor BerkeleyDB
    t = sources.read_host(io.BytesIO(host_mode_tar(monkeypatch, r)), "rocky")
    assert t.status == "partial" and t.pkgs == []
    assert any("unsupported or unreadable rpm database" in n for n in t.notes)
    assert not any("no dpkg, apk or rpm" in n for n in t.notes)


def test_remote_global_npm_same_as_local(monkeypatch, tmp_path):
    """Global npm over `sieve remote` covers what `sieve host` reads: both global prefixes, an npmrc prefix, and the
    packages dpkg installed left to Debian's advisories."""
    r = tmp_path
    (r / "etc").mkdir()
    (r / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (r / "var/lib/dpkg/info").mkdir(parents=True)
    (r / "var/lib/dpkg/status").write_text(STATUS)
    (r / "var/lib/dpkg/info/node-semver.list").write_text("/usr/lib/node_modules/semver\n")
    (r / "etc/npmrc").write_text("prefix = /opt/npm\n")

    def pkg(where, name, ver):
        d = r / where / name
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": name, "version": ver}))
    pkg("usr/lib/node_modules", "semver", "7.6.0")                     # dpkg-owned
    pkg("usr/local/lib/node_modules", "npm", "10.8.2")
    pkg("usr/local/lib/node_modules/npm/node_modules", "tar", "6.2.0")  # nested
    pkg("opt/npm/lib/node_modules", "@scope/cli", "1.2.3")             # npmrc prefix
    remote = sources.read_host(io.BytesIO(host_mode_tar(monkeypatch, r)), "box")
    local = sources.host(root=str(r))
    assert remote.pkgs == local.pkgs and remote.packages == local.packages and remote.notes == local.notes
    npm = sorted(p[1] for p in remote.pkgs if p[0] == "npm")
    assert npm == ["@scope/cli", "npm", "tar"] and "3 global npm packages" in remote.notes


REPORT = {"seen": 40, "total": 40, "loaded": {"os:bash": False, "os:libssl3t64": True}, "native": ["bash", "zlib1g"]}


def test_remote_inuse_read_on_the_remote_machine(monkeypatch, tmp_path):
    """In use comes from /proc on the scanned machine, so the host mode runs inuse_report there and ships it."""
    r = tmp_path
    (r / "etc").mkdir()
    (r / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
    (r / "var/lib/dpkg").mkdir(parents=True)
    (r / "var/lib/dpkg/status").write_text(STATUS)
    seen = {}

    def report(root, pids, proc="/proc", rpm_files=None):
        seen.update(root=root, pids=pids)
        return REPORT
    real = collect.os.path.realpath
    monkeypatch.setattr(collect, "inuse_report", report)
    monkeypatch.setattr(collect, "host_pids", lambda proc="/proc": ["1", "77"])
    monkeypatch.setattr(collect.os.path, "realpath", lambda p: "/" if p == str(r) else real(p))  # as if root were /
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", type("Out", (), {"buffer": buf})())
    collect.host_main(str(r))
    monkeypatch.undo()
    t = sources.read_host(io.BytesIO(buf.getvalue()), "nas")
    assert seen == {"root": str(r), "pids": ["1", "77"]} and t.inuse == REPORT
    assert t.as_dict()["in_use"] == {"processes_read": 40, "processes": 40}
    assert not any("in-use" in n for n in t.notes)


def test_remote_inuse_partial_view_is_unknown_never_not_loaded():
    """A non-root remote user can't read every process: like a local scan, nothing becomes "not loaded"."""
    tar = tgz([("os/etc_os-release", b'ID=debian\nVERSION_ID="13"\n'), ("os/var_lib_dpkg_status", STATUS.encode()),
               ("inuse", json.dumps(dict(REPORT, seen=12, loaded={})).encode())])
    t = sources.read_host(io.BytesIO(tar), "nas")
    assert inuse.state(t.inuse, "os", "zlib1g") == (inuse.UNKNOWN, False)
    assert "read 12 of 40 processes" in inuse.coverage_note(t.inuse)
    bad = sources.read_host(io.BytesIO(tgz([("inuse_note", b"in-use check failed: OSError: x")])), "nas")
    assert bad.inuse is None and "in-use check failed: OSError: x" in bad.notes


class Proc:
    def __init__(self, out=b"", rc=0, err=b""):
        self.out, self.err = out, err
        self.stdout, self.stderr, self.rc = io.BytesIO(out), io.BytesIO(err), rc

    def wait(self):
        return self.rc


def fake_ssh(monkeypatch, answers):
    """answers: "host" / "ctr" → Proc. Records every ssh argv."""
    calls = []

    def run_remote(cmd, script):
        which = "host" if cmd[-1].endswith(" host") else "ctr"
        calls.append((which, cmd))
        a = answers[which]
        p = Proc(a.out, a.rc, a.err)                                    # fresh streams for every run
        return p, p.stdout
    monkeypatch.setattr(sources, "run_remote", run_remote)
    monkeypatch.setattr(intel, "kev_set", lambda d: set())
    monkeypatch.setattr(osv, "match", lambda client, pkgs, kev, target: [])
    return calls


def test_remote_host_and_containers(monkeypatch, capsys, tmp_path):
    calls = fake_ssh(monkeypatch, {"host": Proc(HOST_TAR), "ctr": Proc(CTR_TAR)})
    rc = cli.main(["remote", "me@nas.example.com", "--sudo", "--json", "--no-epss", "--cache", str(tmp_path / "c.db")])
    assert rc == 0
    d = json.loads(capsys.readouterr().out)
    assert [t["name"] for t in d["targets"]] == ["nas.example.com", "example/app:1"]
    assert d["targets"][1]["os"].startswith("alpine") and d["errors"] == []
    (w1, host_cmd), (w2, ctr_cmd) = calls
    assert (w1, w2) == ("host", "ctr")
    assert host_cmd[-1] == "sudo -n python3 -I - host"              # root reads every process for in-use
    assert ctr_cmd[-1] == "sudo -n python3 -I -"


def test_remote_in_use_column_and_filter(monkeypatch, capsys, tmp_path):
    tar = tgz([("os/etc_os-release", b'ID=debian\nVERSION_ID="13"\n'), ("os/var_lib_dpkg_status", STATUS.encode()),
               ("inuse", json.dumps(REPORT).encode())])
    fake_ssh(monkeypatch, {"host": Proc(tar), "ctr": Proc(tgz([("ERRORS", b"")]))})
    found = {"id": "CVE-2024-1", "package": "bash", "installed": "5.2.37-1", "fixed": "5.2.37-2", "severity": "HIGH",
             "summary": "", "kev": False, "status": "fixed", "target": "nas", "details": "", "url": ""}
    monkeypatch.setattr(osv, "match", lambda client, pkgs, kev, target: [dict(found)])
    assert cli.main(["remote", "me@nas", "--in-use-only", "--json", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 0
    d = json.loads(capsys.readouterr().out)
    assert [f["package"] for f in d["findings"]] == ["bash"] and d["findings"][0]["in_use"] == inuse.LOADED
    assert d["targets"][0]["in_use"] == {"processes_read": 40, "processes": 40}


def test_remote_sarif(monkeypatch, capsys, tmp_path):
    fake_ssh(monkeypatch, {"host": Proc(HOST_TAR), "ctr": Proc(CTR_TAR)})
    assert cli.main(["remote", "me@nas", "--sarif", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["version"] == "2.1.0" and d["runs"][0]["tool"]["driver"]["name"] == "sieve"


def test_remote_no_containers_and_note(monkeypatch, capsys, tmp_path):
    calls = fake_ssh(monkeypatch, {"host": Proc(HOST_TAR), "ctr": Proc(tgz([("ERRORS", b"")]))})
    assert cli.main(["remote", "root@nas", "--sudo", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 0
    out = capsys.readouterr().out
    assert "# nas: debian 13" in out and "no running containers seen" in out
    assert calls[0][1][-1] == "python3 -I - host" and calls[1][1][-1] == "python3 -I -"   # root@ needs no sudo
    calls.clear()
    assert cli.main(["remote", "root@nas", "--no-containers", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 0
    assert [w for w, _ in calls] == ["host"]


def test_remote_ssh_failure_explained(monkeypatch, capsys, tmp_path):
    fake_ssh(monkeypatch, {"host": Proc(b"", 255, b"ssh: connect to host nas port 22: Connection refused\n")})
    assert cli.main(["remote", "me@nas", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 2
    err = capsys.readouterr().err
    assert "remote host nas: exited 255" in err and "key auth" in err


def test_remote_sudo_without_password_explained(monkeypatch, capsys, tmp_path):
    fake_ssh(monkeypatch, {"host": Proc(HOST_TAR), "ctr": Proc(b"", 1, b"sudo: a password is required\n")})
    assert cli.main(["remote", "me@nas", "--sudo", "--no-epss", "--cache", str(tmp_path / "c.db")]) == 2
    assert "passwordless sudo" in capsys.readouterr().err


def test_remote_refuses_option_like_destination(monkeypatch, tmp_path):
    calls = fake_ssh(monkeypatch, {})
    # argparse reads a leading "-" as an option, so check the guard itself with a destination that slipped through
    args = cli.parser().parse_args(["remote", "me@nas", "--cache", str(tmp_path / "c.db")])
    for bad in ("-oProxyCommand=touch_x", "me@nas;reboot"):
        args.dest = bad
        errors = []
        cli.remote(args, lambda t: None, errors)
        assert calls == [] and "not an ssh destination" in errors[0]
