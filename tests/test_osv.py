"""Parsers, version ordering, ecosystem mapping and severity. Cases come from real misorders found 2026-10-10."""
import json
import struct
import zlib

from sieve import osv


def test_apk_order():
    for a, b, want in [("3.6.7-r10", "3.6.7-r9", 1), ("3.6.7-r0", "3.6.6-r0", 1), ("1.0_rc1-r0", "1.0-r0", -1),
                       ("1.0_p1-r0", "1.0-r0", 1), ("1.2-r0", "1.2.1-r0", -1), ("8.21.0-r0", "8.20.0-r1", 1),
                       ("1.2a-r0", "1.2-r0", 1)]:
        assert osv.apk_cmp(a, b) == want, (a, b)


def test_semver_pep440_order():
    for a, b, want in [("2.0.0rc1", "2.0.0", -1), ("1.0.post1", "1.0", 1), ("v1.2.3", "1.2.10", -1), ("1.0", "1.0.0", 0),
                       ("1.0.0-beta.2", "1.0.0-beta.10", -1), ("1.0.0a1", "1.0.0b1", -1), ("2.0.0.dev1", "2.0.0a1", -1),
                       ("1.0.0-rc.1", "1.0.0", -1), ("1.26.0-rc.3", "1.25.7", 1)]:
        assert osv.gen_cmp(a, b) == want, (a, b)


def test_deb_order():
    assert osv.deb_cmp("1:10.0p1-7+deb13u4", "1:10.0p1-7+deb13u3") == 1
    assert osv.deb_cmp("8.21.0~rc2-1", "8.21.0-1") == -1
    assert osv.deb_cmp("1:1.0-1", "2.0-1") == 1                 # epoch wins
    assert osv.deb_cmp("1.0-1", "1.0-1") == 0
    assert osv.deb_cmp("1.0-1ubuntu0.2", "1.0-1ubuntu0.10") == -1


def test_vcmp_dispatch():
    assert osv.vcmp("Debian:13", "1.0~rc1-1", "1.0-1") == -1
    assert osv.vcmp("Alpine:v3.20", "1.0-r10", "1.0-r9") == 1
    assert osv.vcmp("PyPI", "2.0.0rc1", "2.0.0") == -1


def test_fixed_uses_exact_release():
    v = {"affected": [{"package": {"ecosystem": "Debian:13", "name": "curl"}, "ranges": [{"events": []}]},
                      {"package": {"ecosystem": "Debian", "name": "curl"},
                       "ranges": [{"events": [{"fixed": "8.21.0~rc2-1"}]}]}]}
    assert osv._fixed(v, "Debian:13", "curl", "8.14.1-2+deb13u5") == ""


def test_fixed_picks_lowest_above_installed():
    v = {"affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                       "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.11.3"}, {"introduced": "3.0"},
                                              {"fixed": "3.1.5"}, {"fixed": "3.1.4"}]}]}]}
    assert osv._fixed(v, "PyPI", "jinja2", "3.1.2") == "3.1.4"


def test_dpkg_source_mapping():
    st = "Package: libcurl4t64\nStatus: install ok installed\nSource: curl (8.14.1-2)\nVersion: 8.14.1-2+b1\n\n"
    assert osv.parse_dpkg(st) == [("curl", "8.14.1-2", "libcurl4t64", "8.14.1-2+b1")]


def test_dpkg_skips_removed_and_continuations():
    st = ("Package: gone\nStatus: deinstall ok config-files\nVersion: 1.0\n\n"
          "Package: bash\nStatus: install ok installed\nVersion: 5.2.37-2\nDescription: shell\n a long\n line\n\n"
          "Package: zlib1g\nStatus: install ok installed\nSource: zlib\nVersion: 1:1.3.dfsg-3.1\n")
    assert osv.parse_dpkg(st) == [("bash", "5.2.37-2", "bash", "5.2.37-2"),
                                  ("zlib", "1:1.3.dfsg-3.1", "zlib1g", "1:1.3.dfsg-3.1")]


def test_apk_origin():
    db = "P:libcrypto3\nV:3.3.2-r0\no:openssl\n\nP:busybox\nV:1.36.1-r29\n"
    assert osv.parse_apk(db) == [("openssl", "3.3.2-r0", "libcrypto3", "3.3.2-r0"),
                                 ("busybox", "1.36.1-r29", "busybox", "1.36.1-r29")]


def test_pymeta_and_npm():
    assert osv.parse_pymeta("Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n\nVersion: 9\n") == \
        ("requests", "2.31.0")
    assert osv.parse_pymeta("Name: x\n") is None
    assert osv.parse_npm('{"name": "lodash", "version": "4.17.20"}') == ("lodash", "4.17.20")
    assert osv.parse_npm("not json") is None
    assert osv.parse_npm('{"name": "x"}') is None


def _go_blob(gover, mod):
    head = b"\xff Go buildinf:" + bytes([8, 2])
    head += b"\0" * (32 - len(head))

    def uv(n):
        out = b""
        while n >= 0x80:
            out += bytes([n & 0x7F | 0x80])
            n >>= 7
        return out + bytes([n])
    modb = b"S" * 16 + mod.encode() + b"E" * 16
    return b"junk" + head + uv(len(gover)) + gover.encode() + uv(len(modb)) + modb


def test_gobuild():
    mod = ("path\texample.com/cmd\nmod\texample.com/cmd\t(devel)\t\n"
           "dep\tgolang.org/x/net\tv0.20.0\th1:abc=\n"
           "dep\tgithub.com/old/lib\tv1.0.0\th1:def=\n=>\tgithub.com/new/lib\tv1.1.0\th1:ghi=\n")
    gover, deps = osv.parse_gobuild(_go_blob("go1.22.1", mod))
    assert gover == "go1.22.1"
    assert deps == [("github.com/new/lib", "v1.1.0"), ("golang.org/x/net", "v0.20.0")]


def test_gobuild_old_format_is_unread():
    blob = b"\xff Go buildinf:" + bytes([8, 0]) + b"\0" * 40      # pre-1.18: pointers, flag bit 2 clear
    assert osv.parse_gobuild(blob) == (None, [])
    assert osv.parse_gobuild(b"no magic here") == (None, [])


def test_rustdeps():
    d = {"packages": [{"name": "serde", "version": "1.0.200", "source": "crates.io"},
                      {"name": "cc", "version": "1.0.0", "source": "crates.io", "kind": "build"},
                      {"name": "myapp", "version": "0.1.0", "source": "local"}]}
    assert osv.parse_rustdeps(zlib.compress(json.dumps(d).encode())) == [("serde", "1.0.200")]
    assert osv.parse_rustdeps(b"garbage") == []


def test_ecosystem_mapping():
    E = osv.ecosystem
    assert E({"ID": "debian", "VERSION_ID": "12"}) == ("Debian:12", "debian 12")
    assert E({"ID": "debian", "VERSION_ID": ""})[0] is None                      # sid/testing: no release feed
    assert E({"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION": "24.04.1 LTS (Noble Numbat)"})[0] == "Ubuntu:24.04:LTS"
    assert E({"ID": "ubuntu", "VERSION_ID": "22.04"})[0] == "Ubuntu:22.04:LTS"   # even .04 = LTS without VERSION
    assert E({"ID": "ubuntu", "VERSION_ID": "24.10"})[0] == "Ubuntu:24.10"
    eco, label = E({"ID": "pop", "ID_LIKE": "ubuntu debian", "VERSION_ID": "22.04"})
    assert eco == "Ubuntu:22.04:LTS" and "scanned as ubuntu" in label
    assert E({"ID": "alpine", "VERSION_ID": "3.20.3"}, "3.20.3") == ("Alpine:v3.20", "alpine 3.20.3")
    assert E({"ID": "fedora", "VERSION_ID": "40"}) == (None, "fedora 40")
    assert E({}) [0] is None


def test_kv():
    assert osv.kv('ID=debian\nVERSION_ID="13"\n# comment\n') == {"ID": "debian", "VERSION_ID": "13"}


def test_cvss3():
    assert osv.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.cvss3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert osv.level(osv.cvss3("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N")) == "LOW"
    assert osv.cvss3("nonsense") is None


def test_severity_order():
    assert osv.severity({"severity": [{"type": "Ubuntu", "score": "negligible"}]}) == "LOW"
    assert osv.severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert osv.severity({"severity": [{"type": "CVSS_V3",
                                       "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == "CRITICAL"
    assert osv.severity({}) == "UNKNOWN"


def test_slim_drops_bulk():
    big = {"id": "UBUNTU-CVE-2025-1", "modified": "m", "details": "x" * 5000,
           "references": [{"type": "WEB", "url": "a"}, {"type": "ADVISORY", "url": "b"}, {"type": "ADVISORY", "url": "c"}],
           "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "curl"},
                         "versions": ["1.%d" % i for i in range(5000)],
                         "ecosystem_specific": {"binaries": [{"x": "y"}] * 100},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]}
    s = osv.slim(big)
    assert len(json.dumps(s)) < 2000
    assert s["affected"][0]["ranges"] == [{"events": [{"fixed": "2.0"}]}]
    assert "versions" not in s["affected"][0] and s["references"] == [{"type": "ADVISORY", "url": "b"}]


def test_cve_id():
    assert osv._cve({"id": "DEBIAN-CVE-2024-1234"}) == "CVE-2024-1234"
    assert osv._cve({"id": "GHSA-xxxx", "aliases": ["PYSEC-1", "CVE-2023-9"]}) == "CVE-2023-9"
    assert osv._cve({"id": "GO-2024-1"}) is None
