"""In use: /proc maps → owning package (dpkg, apk, Python RECORD), the three states, coverage, ranking and output."""
import json
import os

from sieve import cli, collect, inuse, rank, sarif, sources

ELF = b"\x7fELF" + b"\0" * 60
LIB = "/usr/lib/x86_64-linux-gnu"
SITE = "/usr/local/lib/python3.12/site-packages"


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def fake_root(tmp_path):
    """A Debian-ish filesystem: libssl3 (listed under /lib, usrmerge), zlib1g, openssl (an ELF executable that isn't
    running), a script-only package, and a pip-installed wheel with a compiled extension."""
    root = str(tmp_path / "root")
    info = f"{root}/var/lib/dpkg/info"
    write(f"{info}/libssl3:amd64.list", "/.\n/lib\n/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu/libssl.so.3\n")
    write(f"{info}/zlib1g:amd64.list", f"/.\n{LIB}/libz.so.1.3\n")
    write(f"{info}/openssl.list", "/.\n/usr/bin/openssl\n/usr/share/doc/openssl/copyright\n")
    write(f"{info}/scripts.list", "/.\n/usr/bin/tool\n")
    write(f"{root}/usr/bin/openssl", ELF)
    write(f"{root}/usr/bin/tool", "#!/bin/sh\necho hi\n")
    write(f"{root}{SITE}/fastlib-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: fastlib\nVersion: 1.0\n\n")
    write(f"{root}{SITE}/fastlib-1.0.dist-info/RECORD",
          "fastlib/__init__.py,sha256=x,10\nfastlib/_core.cpython-312-x86_64-linux-gnu.so,sha256=y,99\n")
    return root


def maps(*paths):
    return "".join(f"7f00-7f01 r-xp 00000000 08:01 1 {p}\n" for p in paths)


def data_maps(*paths):
    return "".join(f"7f00-7f01 r--p 00000000 08:01 1 {p}\n" for p in paths)


def fake_proc(tmp_path, procs):
    """procs: {pid: (cmdline, maps text or None for unreadable)}."""
    proc = str(tmp_path / "proc")
    for pid, (cmd, m) in procs.items():
        write(f"{proc}/{pid}/cmdline", cmd)
        if m is not None:
            write(f"{proc}/{pid}/maps", m)
    return proc


def everything_read(tmp_path):
    return fake_proc(tmp_path, {
        "1": (b"init\0", maps(f"{LIB}/libssl.so.3", "/usr/sbin/init") + data_maps("/usr/bin/openssl")),
        "2": (b"", ""),                                              # kernel thread: not counted
        "3": (b"app\0", maps(f"{LIB}/libz.so.1.3 (deleted)", f"{SITE}/fastlib/_core.cpython-312-x86_64-linux-gnu.so",
                             "[heap]"))})


def test_report_maps_paths_to_packages(tmp_path):
    root, proc = fake_root(tmp_path), everything_read(tmp_path)
    r = collect.inuse_report(root, ["1", "2", "3"], proc=proc)
    assert (r["seen"], r["total"]) == (2, 2)
    assert r["loaded"] == {"os:libssl3": False, "os:zlib1g": True, "py:fastlib": False}
    assert set(r["native"]) == {"libssl3", "zlib1g", "openssl"}          # the shell script ships no native code
    assert "os:openssl" not in r["loaded"]                               # a read-only (data) mapping is not code


def test_three_states(tmp_path):
    rep = collect.inuse_report(fake_root(tmp_path), ["1", "2", "3"], proc=everything_read(tmp_path))
    assert inuse.state(rep, "os", "libssl3") == (inuse.LOADED, False)
    assert inuse.state(rep, "os", "zlib1g") == (inuse.LOADED, True)      # upgraded on disk, old copy running
    assert inuse.state(rep, "os", "openssl") == (inuse.NOT_LOADED, False)
    assert inuse.state(rep, "os", "scripts") == (inuse.UNKNOWN, False)   # a script runs inside an interpreter
    assert inuse.state(rep, "py", "fastlib") == (inuse.LOADED, False)
    assert inuse.state(rep, "py", "purepy") == (inuse.UNKNOWN, False)    # never "not loaded" for Python
    assert inuse.state(rep, "other", "lodash") == (inuse.UNKNOWN, False)
    assert inuse.state(None, "os", "libssl3") == (inuse.UNKNOWN, False)


def test_partial_coverage_never_says_not_loaded(tmp_path):
    proc = fake_proc(tmp_path, {"1": (b"init\0", maps(f"{LIB}/libssl.so.3")),
                                "9": (b"someone-elses\0", None)})       # maps unreadable without root
    rep = collect.inuse_report(fake_root(tmp_path), ["1", "9"], proc=proc)
    assert (rep["seen"], rep["total"]) == (1, 2)
    assert inuse.state(rep, "os", "libssl3")[0] == inuse.LOADED          # what was seen still counts
    assert inuse.state(rep, "os", "openssl")[0] == inuse.UNKNOWN
    assert "read 1 of 2 processes" in inuse.coverage_note(rep)
    assert inuse.coverage_note(dict(rep, seen=2)) is None
    assert inuse.state(dict(rep, seen=2, main_only=True), "os", "openssl")[0] == inuse.UNKNOWN


def test_apk_file_list(tmp_path):
    root = str(tmp_path / "alp")
    write(f"{root}/lib/apk/db/installed", "P:libcrypto3\nV:3.1.4-r5\nF:usr/lib\nR:libcrypto.so.3\n\n"
                                          "P:busybox\nV:1.36\nF:bin\nR:busybox\n\n")
    write(f"{root}/bin/busybox", ELF)
    proc = fake_proc(tmp_path, {"1": (b"sh\0", maps("/usr/lib/libcrypto.so.3", "/bin/busybox"))})
    rep = collect.inuse_report(root, ["1"], proc=proc)
    assert rep["loaded"] == {"os:libcrypto3": False, "os:busybox": False}


def test_host_pids_keeps_own_mount_namespace(tmp_path):
    proc = str(tmp_path / "proc")
    for pid, ns in (("1", "mnt:[1]"), ("50", "mnt:[1]"), ("77", "mnt:[9]")):   # 77 lives in a container
        os.makedirs(f"{proc}/{pid}/ns")
        os.symlink(ns, f"{proc}/{pid}/ns/mnt")
    assert sorted(collect.host_pids(proc), key=int) == ["1", "50"]


def test_container_pids_from_cgroup(tmp_path):
    cid = "a" * 64
    proc = fake_proc(tmp_path, {"5": (b"x\0", None), "6": (b"y\0", None), "7": (b"z\0", None)})
    write(f"{proc}/5/cgroup", f"0::/system.slice/docker-{cid}.scope\n")
    write(f"{proc}/6/cgroup", f"12:pids:/docker/{cid}\n")
    write(f"{proc}/7/cgroup", "0::/user.slice\n")
    assert {k: sorted(v) for k, v in collect.container_pids(proc).items()} == {cid: ["5", "6"]}


class T:
    def __init__(self, inuse_rep, pkgs):
        self.inuse, self.pkgs = inuse_rep, pkgs


def test_annotate_uses_each_package_kind():
    rep = {"seen": 1, "total": 1, "loaded": {"os:libssl3": True, "py:fastlib": False}, "native": ["openssl"]}
    t = T(rep, [("Debian:12", "openssl", "3.0", "libssl3", "3.0"), ("Debian:12", "openssl", "3.0", "openssl", "3.0"),
                ("PyPI", "fastlib", "1.0", "fastlib", "1.0"), ("npm", "lodash", "4", "lodash", "4")])
    fs = [{"package": p} for p in ("libssl3", "openssl", "fastlib", "lodash")]
    inuse.annotate(fs, t)
    assert [(f["in_use"], f["restart_needed"]) for f in fs] == [
        ("loaded", True), ("not loaded", False), ("loaded", False), ("unknown", False)]


def f(id, use, kev=False, fixed="1.1", sev="HIGH", restart=False):
    return {"id": id, "severity": sev, "fixed": fixed, "kev": kev, "epss": None, "package": "p", "target": "host",
            "status": "fixed" if fixed else "affected", "installed": "1.0", "summary": "", "details": "", "url": "",
            "in_use": use, "restart_needed": restart}


def test_rank_in_use_first_within_a_tier_only():
    rows = [f("off", "not loaded"), f("maybe", "unknown"), f("on", "loaded"), f("kev-off", "not loaded", kev=True)]
    assert [r["id"] for r in rank.rank(rows)] == ["kev-off", "on", "maybe", "off"]
    assert [r["id"] for r in rank.apply_filters(rows, in_use_only=True)] == ["on"]
    s = rank.summary(rows + [f("old", "loaded", restart=True)])
    assert (s["in_use"], s["restart_needed"]) == (2, 1)


def test_table_and_sarif_show_it():
    rows = rank.rank([f("CVE-1", "loaded", restart=True), f("CVE-2", "not loaded"), f("CVE-3", "unknown")])
    out = cli.table(rows, 0)
    assert "IN USE" in out and "yes ↻" in out and " no " in out
    doc = sarif.build([], rows, [])
    props = [r["properties"] for r in doc["runs"][0]["results"]]
    assert [(p["inUse"], p["restartNeeded"]) for p in props] == [("loaded", True), ("unknown", False),
                                                                 ("not loaded", False)]
    assert "restart it" in doc["runs"][0]["results"][0]["message"]["text"]


def test_image_target_reads_collector_inuse():
    rep = {"seen": 3, "total": 3, "loaded": {"os:libssl3": False}, "native": ["libssl3"], "main_only": False}
    t = sources.image_target("img", {"os/var_lib_dpkg_status": b"", "inuse": json.dumps(rep).encode()})
    assert t.inuse == rep and t.as_dict()["in_use"] == {"processes_read": 3, "processes": 3}


# ── rpm: file lists come from the same rpmdb read as the package list ─────────────────────────────────────────────
RPM_HDR = os.path.join(os.path.dirname(__file__), "fixtures", "rpm", "libnghttp2.hdr")   # real, from AlmaLinux 9.3


def test_rpm_header_file_list_only_when_asked():
    blob = open(RPM_HDR, "rb").read()
    h = collect.rpm_header(blob, files=True)
    assert "/usr/lib64/libnghttp2.so.14.20.1" in h["files"] and "/usr/share/licenses/libnghttp2/COPYING" in h["files"]
    assert "files" not in collect.rpm_header(blob)


def test_rpm_ownership_end_to_end(tmp_path):
    import sqlite3
    root = str(tmp_path / "alma")
    db = f"{root}/usr/lib/sysimage/rpm/rpmdb.sqlite"
    os.makedirs(os.path.dirname(db))
    con = sqlite3.connect(db)
    con.execute("create table Packages (hnum integer primary key autoincrement, blob blob not null)")
    con.execute("insert into Packages(blob) values(?)", (open(RPM_HDR, "rb").read(),))
    con.commit()
    con.close()
    files = {}
    fmt, rows, err = collect.rpm_packages(root, files)
    assert (fmt, err) == ("sqlite", None) and rows[0].startswith("libnghttp2\t")
    assert files["/usr/lib64/libnghttp2.so.14.20.1"] == "libnghttp2"
    proc = fake_proc(tmp_path, {"1": (b"curl\0", maps("/usr/lib64/libnghttp2.so.14.20.1 (deleted)"))})
    rep = collect.inuse_report(root, ["1"], proc=proc, rpm_files=files)
    assert rep["loaded"] == {"os:libnghttp2": True} and "libnghttp2" in rep["native"]
    assert inuse.state(rep, "os", "libnghttp2") == (inuse.LOADED, True)


def test_elf_check_follows_symlinks_inside_the_root(tmp_path):
    """In a container an absolute symlink must resolve inside its root, not on the host (where /opt/real is absent)."""
    root = str(tmp_path / "ctr")
    write(f"{root}/opt/real/tool", ELF)
    os.makedirs(f"{root}/usr/bin")
    os.symlink("/opt/real/tool", f"{root}/usr/bin/tool")
    write(f"{root}/var/lib/dpkg/info/tool.list", "/.\n/usr/bin/tool\n")
    own, native = collect.owners(root, set())
    assert "tool" in native


def test_malicious_stays_first_and_unfiltered():
    mal = dict(f("MAL-2026-1", "not loaded", fixed=""), malicious=True)
    rows = rank.rank([f("on", "loaded", kev=True), mal])
    assert [r["id"] for r in rows] == ["MAL-2026-1", "on"]                 # tier 0 beats a loaded KEV
    assert [r["id"] for r in rank.apply_filters(rows, in_use_only=True)] == ["MAL-2026-1", "on"]
    head = cli.table(rows, 0).splitlines()[0].split()
    assert head[:5] == ["ALERT", "EPSS", "SEVERITY", "IN", "USE"]
