"""rpm support: the database readers (SQLite, ndb, BerkeleyDB), rpm version ordering, ecosystems and matching.
Formats and cases come from real images read on 2026-10-11 (AlmaLinux 8/9, Rocky 9, UBI 9, openSUSE Leap 15.5 and
Tumbleweed, Fedora 39); the header fixture is a real one from AlmaLinux 9.3's rpmdb."""
import importlib.util
import os
import sqlite3
import struct

from sieve import osv, sources

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "rpm")


def collector():
    spec = importlib.util.spec_from_file_location("collect", sources.COLLECTOR)
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    return c


def header(**tags):
    """A minimal rpm header blob: STRING tags, epoch as INT32."""
    ids = {"name": 1000, "version": 1001, "release": 1002, "epoch": 1003, "arch": 1022, "sourcerpm": 1044}
    index, store = b"", b""
    for k, v in tags.items():
        if k == "epoch":
            while len(store) % 4:
                store += b"\0"
            index += struct.pack(">IIII", ids[k], 4, len(store), 1)
            store += struct.pack(">i", int(v))
        else:
            index += struct.pack(">IIII", ids[k], 6, len(store), 1)
            store += v.encode() + b"\0"
    return struct.pack(">II", len(tags), len(store)) + index + store


PKGS = [header(name="openssl-libs", epoch=1, version="3.0.7", release="24.el9", arch="x86_64",
               sourcerpm="openssl-3.0.7-24.el9.src.rpm"),
        header(name="bash", version="5.1.8", release="6.el9_1", arch="x86_64", sourcerpm="bash-5.1.8-6.el9_1.src.rpm"),
        header(name="gpg-pubkey", version="b86b3716", release="61e69f29", sourcerpm="")]
WANT = ["bash\t\t5.1.8\t6.el9_1\tx86_64\tbash-5.1.8-6.el9_1.src.rpm",
        "openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm"]


def sqlite_db(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table Packages (hnum integer primary key autoincrement, blob blob not null)")
    con.executemany("insert into Packages(blob) values(?)", [(b,) for b in PKGS])
    con.commit()
    con.close()


def ndb_file(path):
    """openSUSE ndb: 'RpmP' header, one slot page, 16-byte blocks; a freed slot (pkgidx 0) must be skipped."""
    blobs, slots, data = [], b"", bytearray(4096)
    off = 4096
    for i, b in enumerate(PKGS + [header(name="deleted", version="1")], 1):
        blob = struct.pack("<4sIII", b"BlbS", i, 1, len(b)) + b
        blob += b"\0" * (-len(blob) % 16)
        data += blob
        slots += struct.pack("<4sIII", b"Slot", i if i <= len(PKGS) else 0, off // 16, len(blob) // 16)
        off += len(blob)
    data[0:16] = struct.pack("<4sIII", b"RpmP", 0, 1, 1)
    data[32:32 + len(slots)] = slots
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(bytes(data))


def bdb_file(path, psize=512):
    """BerkeleyDB hash: meta page, one P_HASH page with an inline item and an H_OFFPAGE item, overflow pages."""
    small, big = PKGS[1], PKGS[0] + b"\0" * 900          # the big one spans three 512-byte overflow pages
    pages = [bytearray(psize) for _ in range(6)]
    struct.pack_into("<I", pages[0], 12, 0x061561)
    struct.pack_into("<I", pages[0], 20, psize)
    hp = pages[1]
    hp[25] = 13
    items = [b"\x01" + struct.pack("<I", 1), b"\x01" + small, b"\x01" + struct.pack("<I", 2),
             b"\x03\0\0\0" + struct.pack("<II", 2, len(big))]
    end, offs = psize, []
    for it in items:
        end -= len(it)
        hp[end:end + len(it)] = it
        offs.append(end)
    struct.pack_into("<H", hp, 20, len(items))
    for i, o in enumerate(offs):
        struct.pack_into("<H", hp, 26 + 2 * i, o)
    chunk = psize - 26
    for k, n in enumerate((2, 3, 4)):
        part = big[k * chunk:(k + 1) * chunk]
        p = pages[n]
        p[25] = 7
        struct.pack_into("<I", p, 16, n + 1 if n < 4 else 0)
        struct.pack_into("<H", p, 22, len(part))
        p[26:26 + len(part)] = part
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(b"".join(bytes(p) for p in pages))


def test_real_header_fixture():
    c = collector()
    h = c.rpm_header(open(os.path.join(FIX, "libnghttp2.hdr"), "rb").read())
    assert h == {"name": "libnghttp2", "version": "1.43.0", "release": "5.el9_3.1", "arch": "x86_64",
                 "sourcerpm": "nghttp2-1.43.0-5.el9_3.1.src.rpm"}


def test_reads_all_three_formats(tmp_path):
    c = collector()
    sqlite_db(str(tmp_path / "a/usr/lib/sysimage/rpm/rpmdb.sqlite"))
    ndb_file(str(tmp_path / "b/usr/lib/sysimage/rpm/Packages.db"))
    bdb_file(str(tmp_path / "c/var/lib/rpm/Packages"))
    for sub, fmt in (("a", "sqlite"), ("b", "ndb"), ("c", "bdb")):
        got = c.rpm_packages(str(tmp_path / sub))
        assert got == (fmt, WANT, None), sub                  # gpg-pubkey and the freed ndb slot left out


def test_no_rpm_database_and_unreadable_one(tmp_path):
    c = collector()
    assert c.rpm_packages(str(tmp_path)) == (None, [], None)
    p = tmp_path / "var/lib/rpm/Packages"
    p.parent.mkdir(parents=True)
    p.write_bytes(b"\0" * 4096)                               # neither ndb nor BerkeleyDB: an error, never "empty"
    fmt, rows, err = c.rpm_packages(str(tmp_path))
    assert rows == [] and err and "unsupported or unreadable" in err


def test_symlinks_stay_inside_the_root(tmp_path):
    """/var/lib/rpm -> /usr/lib/sysimage/rpm (absolute) must resolve inside the container, not on the host."""
    c = collector()
    sqlite_db(str(tmp_path / "usr/lib/sysimage/rpm/rpmdb.sqlite"))
    (tmp_path / "var/lib").mkdir(parents=True)
    os.symlink("/usr/lib/sysimage/rpm", tmp_path / "var/lib/rpm")
    assert c.in_root(str(tmp_path), "var/lib/rpm/rpmdb.sqlite") == str(tmp_path / "usr/lib/sysimage/rpm/rpmdb.sqlite")
    os.symlink("../../../../../../etc", tmp_path / "escape")
    assert c.in_root(str(tmp_path), "escape/passwd") == str(tmp_path / "etc/passwd")


def test_live_wal_is_replayed(tmp_path):
    c = collector()
    db = str(tmp_path / "usr/lib/sysimage/rpm/rpmdb.sqlite")
    sqlite_db(db)
    con = sqlite3.connect(db)
    con.execute("pragma journal_mode=wal")
    con.execute("pragma wal_autocheckpoint=0")
    con.execute("insert into Packages(blob) values(?)", (header(name="curl", version="7.76.1", release="26.el9"),))
    con.commit()
    assert os.path.getsize(db + "-wal") > 0
    names = [r.split("\t")[0] for r in c.rpm_packages(str(tmp_path))[1]]
    con.close()
    assert "curl" in names


def test_rpmvercmp():
    # cases from rpm's own test suite (tests/rpmvercmp.at)
    for a, b, want in [("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0.1", "2.0.1a", -1), ("5.5p1", "5.5p2", -1),
                       ("5.5p10", "5.5p1", 1), ("10xyz", "10.1xyz", -1), ("xyz10", "xyz10.1", -1),
                       ("1.0aa", "1.0a", 1), ("10.0001", "10.1", 0), ("2a", "2.0", -1), ("1.0", "1.0a", -1),
                       ("1.0~rc1", "1.0", -1), ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc1~git123", "1.0~rc1", -1),
                       ("1.0^", "1.0", 1), ("1.0^git1", "1.0^git2", -1), ("1.0^git1", "1.01", -1),
                       ("1.0^20160101", "1.0.1", -1), ("1.0~rc1^git1", "1.0~rc1", 1), ("1.0^git1~pre", "1.0^git1", -1),
                       ("+1.0", "1.0", 0), ("1.0.", "1.0", 0)]:
        assert osv.rpmvercmp(a, b) == want, (a, b)
        assert osv.rpmvercmp(b, a) == -want, (b, a)


def test_rpm_evr_order():
    assert osv.rpm_cmp("1:3.0.7-24.el9", "1:3.0.7-28.el9_4") == -1
    assert osv.rpm_cmp("0:11.5.0-5.el9_5", "11.4.1-2.1.el9") == 1          # OSV writes "0:", the rpmdb doesn't
    assert osv.rpm_cmp("1:1.0-1", "2.0-1") == 1                             # epoch wins
    assert osv.rpm_cmp("3.0.8-150500.5.11.1", "3.0.8-150500.5.8.1") == 1
    assert osv.vcmp("Rocky Linux:9", "1:3.0.7-28.el9_4", "1:3.0.7-24.el9") == 1


def test_parse_rpm_maps_source_package():
    text = "#format sqlite\n" + "\n".join(WANT) + "\nlibnghttp2\t\t1.43.0\t5.el9_3.1\tx86_64\tnghttp2-1.43.0-5.el9_3.1.src.rpm"
    assert osv.parse_rpm(text) == [("bash", "5.1.8-6.el9_1", "bash", "5.1.8-6.el9_1"),
                                   ("nghttp2", "1.43.0-5.el9_3.1", "libnghttp2", "1.43.0-5.el9_3.1"),
                                   ("openssl", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9")]


def test_ecosystems():
    e = lambda **k: osv.ecosystem(k)[0]  # noqa: E731
    assert e(ID="almalinux", VERSION_ID="9.3") == "AlmaLinux:9"
    assert e(ID="rocky", VERSION_ID="8.9") == "Rocky Linux:8"
    assert e(ID="rhel", VERSION_ID="9.3") == "Red Hat:enterprise_linux:9"
    assert e(ID="opensuse-leap", VERSION_ID="15.5") == "openSUSE:Leap 15.5"
    assert e(ID="opensuse-tumbleweed", VERSION_ID="20261010") == "openSUSE:Tumbleweed"
    for ident, ver in (("fedora", "39"), ("centos", "9"), ("ol", "9.4"), ("amzn", "2023")):
        assert e(ID=ident, VERSION_ID=ver) is None                         # no OSV feed: said so, not guessed


def test_os_packages_asks_both_names_and_both_rhel_streams():
    ent = [("openssl", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9")]
    assert osv.os_packages("Rocky Linux:9", ent) == [
        ("Rocky Linux:9", "openssl-libs", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9"),
        ("Rocky Linux:9", "openssl", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9")]
    ecos = {p[0] for p in osv.os_packages("Red Hat:enterprise_linux:9", ent)}
    assert ecos == {"Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream"}


def test_kernel_rpms_skipped():
    for n in ("kernel", "kernel-core", "kernel-modules", "kernel-headers", "kernel-default"):
        assert osv.KERNEL_PKG.match(n), n
    assert not osv.KERNEL_PKG.match("kernelshark")


def test_match_expands_rpm_errata(fake):
    """ALSA errata carry their CVEs in `related` and Red Hat's rating in the summary; the row is the CVE."""
    alsa = {"id": "ALSA-2024:6783", "modified": "m", "summary": "Moderate: openssl security update",
            "related": ["CVE-2024-6119"],
            "affected": [{"package": {"ecosystem": "AlmaLinux:9", "name": "openssl-libs"},
                          "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1:3.0.7-28.el9_4"}]}]}]}
    ga = {"id": "openSUSE-SU-2024:10106-1", "modified": "m", "summary": "bash-4.4-92.1 on GA media",
          "upstream": ["CVE-2014-6271"],
          "affected": [{"package": {"ecosystem": "openSUSE:Tumbleweed", "name": "bash"},
                        "ranges": [{"events": [{"introduced": "0"}, {"fixed": "7.0-92.1"}]}]}]}
    s = fake(hits={("AlmaLinux:9", "openssl-libs", "1:3.0.7-24.el9"): ["ALSA-2024:6783"],
                   ("openSUSE:Tumbleweed", "bash", "5.3.20-9.1"): ["openSUSE-SU-2024:10106-1"]},
             vulns={"ALSA-2024:6783": alsa, "openSUSE-SU-2024:10106-1": ga})
    o = osv.OSV(":memory:", session=s)
    pkgs = osv.os_packages("AlmaLinux:9", [("openssl", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9")])
    pkgs += osv.os_packages("openSUSE:Tumbleweed", [("bash", "5.3.20-9.1", "bash", "5.3.20-9.1")])
    rows = osv.match(o, pkgs, kev={"CVE-2014-6271"}, target="t")
    assert [(r["id"], r["package"], r["fixed"], r["severity"], r["status"]) for r in rows] == [
        ("CVE-2024-6119", "openssl-libs", "1:3.0.7-28.el9_4", "MEDIUM", "fixed")]
    # Shellshock was fixed in Tumbleweed long ago: the record's own title says bash-4.4-92.1, its fixed event is wrong


def test_image_target_rpm(tmp_path):
    text = "#format sqlite\n" + "\n".join(WANT)
    files = {"os/etc_os-release": b'ID="rocky"\nVERSION_ID="9.3"\n', "os/rpm_packages": text.encode(),
             "py/1": b"/usr/lib/python3.9/site-packages/six-1.15.0.dist-info/METADATA\nsix\n1.15.0",
             "py/2": b"/usr/local/lib/python3.9/site-packages/flask-2.0.0.dist-info/METADATA\nFlask\n2.0.0"}
    t = sources.image_target("rockylinux:9.3-minimal", files)
    assert t.os == "rocky 9.3" and t.packages == 3                       # 2 rpms + Flask, not 4 queries + 2
    assert ("Rocky Linux:9", "openssl", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9") in t.pkgs
    assert ("PyPI", "Flask", "2.0.0", "Flask", "2.0.0") in t.pkgs
    assert not any(p[1] == "six" for p in t.pkgs)                        # came with an rpm
    bad = sources.image_target("x", {"os/etc_os-release": b"ID=rocky\nVERSION_ID=8\n",
                                     "os/rpm_packages": b"#error unsupported or unreadable rpm database var/lib/rpm/Packages"})
    assert bad.status == "partial" and "unsupported" in bad.notes[0]


def test_host_reads_rpm_root(tmp_path):
    r = tmp_path
    (r / "etc").mkdir()
    (r / "etc/os-release").write_text('ID="almalinux"\nVERSION_ID="9.3"\n')
    sqlite_db(str(r / "usr/lib/sysimage/rpm/rpmdb.sqlite"))
    t = sources.host(root=str(r))
    assert t.os == "almalinux 9.3" and t.packages == 2 and t.status == "ok"
    assert ("AlmaLinux:9", "openssl-libs", "1:3.0.7-24.el9", "openssl-libs", "1:3.0.7-24.el9") in t.pkgs
