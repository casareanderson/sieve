"""match() against a stubbed OSV session: no network."""
from sieve import osv

CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
DEB = ("Debian:13", "curl", "8.14.1-2+deb13u1", "libcurl4t64", "8.14.1-2+deb13u1+b1")


def deb_vulns():
    return {
        "DEBIAN-CVE-2025-0001": {"id": "DEBIAN-CVE-2025-0001", "modified": "m1", "summary": "heap overflow",
                                 "affected": [{"package": {"ecosystem": "Debian:13", "name": "curl"},
                                               "ranges": [{"events": [{"introduced": "0"},
                                                                      {"fixed": "8.14.1-2+deb13u2"}]}]},
                                              {"package": {"ecosystem": "Debian", "name": "curl"},
                                               "ranges": [{"events": [{"fixed": "8.21.0~rc2-1"}]}]}]},
        "CVE-2025-0001": {"id": "CVE-2025-0001", "modified": "m", "severity": [{"type": "CVSS_V3", "score": CRIT}]},
        "DSA-6000-1": {"id": "DSA-6000-1", "modified": "m", "affected": [
            {"package": {"ecosystem": "Debian:13", "name": "curl"}, "ranges": [{"events": [{"fixed": "9"}]}]}]},
        "DEBIAN-CVE-2025-0002": {"id": "DEBIAN-CVE-2025-0002", "modified": "m", "withdrawn": "2025-01-01"},
        "DEBIAN-CVE-2025-0003": {"id": "DEBIAN-CVE-2025-0003", "modified": "m", "affected": [
            {"package": {"ecosystem": "Debian:13", "name": "curl"}, "ecosystem_specific": {"urgency": "unimportant"},
             "ranges": [{"events": [{"introduced": "0"}]}]}]},
    }


def test_debian_match(fake):
    s = fake(hits={DEB[:3]: ["DEBIAN-CVE-2025-0001", "DSA-6000-1", "DEBIAN-CVE-2025-0002", "DEBIAN-CVE-2025-0003"]},
             vulns=deb_vulns())
    rows = osv.match(osv.OSV(":memory:", session=s), [DEB], {"CVE-2025-0001"}, target="host")
    by = {r["id"]: r for r in rows}
    assert set(by) == {"CVE-2025-0001", "CVE-2025-0003"}            # DSA notice and withdrawn record skipped
    r = by["CVE-2025-0001"]
    assert r["package"] == "libcurl4t64" and r["installed"] == "8.14.1-2+deb13u1+b1"
    assert r["fixed"] == "8.14.1-2+deb13u2"                          # not unstable's 8.21.0~rc2-1
    assert r["severity"] == "CRITICAL"                               # borrowed from the CVE record
    assert r["kev"] is True and r["target"] == "host" and r["status"] == "fixed"
    u = by["CVE-2025-0003"]
    assert u["severity"] == "LOW" and u["status"] == "unimportant (Debian)" and u["fixed"] == ""


def test_cache_skips_unchanged(fake, tmp_path):
    db = str(tmp_path / "c.db")
    s = fake(hits={DEB[:3]: ["DEBIAN-CVE-2025-0001"]}, vulns=deb_vulns())
    osv.match(osv.OSV(db, session=s), [DEB], set())
    first = len([u for u in s.gets if u.endswith("DEBIAN-CVE-2025-0001")])
    s.gets.clear()
    rows = osv.match(osv.OSV(db, session=s), [DEB], set())
    assert first == 1
    assert not [u for u in s.gets if u.endswith("DEBIAN-CVE-2025-0001")]   # same `modified`: served from cache
    assert rows[0]["fixed"] == "8.14.1-2+deb13u2"


def test_partial_fetch_counts_failures(fake):
    s = fake(hits={DEB[:3]: ["DEBIAN-CVE-2025-0001"]}, vulns=deb_vulns(), fail_ids={"DEBIAN-CVE-2025-0001"})
    client = osv.OSV(":memory:", session=s)
    rows = osv.match(client, [DEB], set())
    assert rows == [] and client.failed == 1


def test_ubuntu_esm(fake):
    pkg = ("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15", "libssl3", "3.0.2-0ubuntu1.15")
    v = {"UBUNTU-CVE-2024-9": {"id": "UBUNTU-CVE-2024-9", "modified": "m",
                               "severity": [{"type": "Ubuntu", "score": "medium"}],
                               "affected": [{"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "openssl"},
                                             "ranges": [{"events": [{"fixed": "3.0.2-0ubuntu1.18+esm1"}]}]}]}}
    rows = osv.match(osv.OSV(":memory:", session=fake(hits={pkg[:3]: list(v)}, vulns=v)), [pkg], set())
    assert rows[0]["fixed"] == "" and "ESM" in rows[0]["status"] and rows[0]["severity"] == "MEDIUM"


def test_ghsa_pysec_dedup_keeps_best(fake):
    pkg = ("PyPI", "jinja2", "3.1.2", "jinja2", "3.1.2")
    aff = [{"package": {"ecosystem": "PyPI", "name": "jinja2"}, "ranges": [{"events": [{"fixed": "3.1.3"}]}]}]
    v = {"PYSEC-2024-1": {"id": "PYSEC-2024-1", "modified": "m", "aliases": ["CVE-2024-22195"], "affected": []},
         "GHSA-h5c8-rqwp-cp95": {"id": "GHSA-h5c8-rqwp-cp95", "modified": "m", "aliases": ["CVE-2024-22195"],
                                 "database_specific": {"severity": "MODERATE"}, "affected": aff}}
    rows = osv.match(osv.OSV(":memory:", session=fake(hits={pkg[:3]: list(v)}, vulns=v)), [pkg], set())
    assert len(rows) == 1
    assert rows[0]["id"] == "CVE-2024-22195" and rows[0]["fixed"] == "3.1.3" and rows[0]["severity"] == "MEDIUM"


def test_alpine_secdb_adds_lagging_fix(fake):
    from conftest import Resp
    pkg = ("Alpine:v3.20", "openssl", "3.3.1-r0", "libcrypto3", "3.3.1-r0")
    urls = {"https://secdb.alpinelinux.org/v3.20/main.json": Resp(200, {"packages": [
        {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": ["CVE-2024-9143"], "3.3.0-r0": ["CVE-2024-0001"],
                                                 "0": ["CVE-2000-1"]}}}]}),
            "https://secdb.alpinelinux.org/v3.20/community.json": Resp(404, {})}
    rows = osv.match(osv.OSV(":memory:", session=fake(urls=urls)), [pkg], {"CVE-2024-9143"})
    assert [(r["id"], r["fixed"], r["kev"]) for r in rows] == [("CVE-2024-9143", "3.3.2-r0", True)]
    assert rows[0]["url"].startswith("https://security.alpinelinux.org/")


def test_query_follows_page_tokens(fake):
    from conftest import Resp

    class Paged(fake):
        def post(self, url, json=None, timeout=None):
            q = json["queries"][0]
            if "page_token" in q:
                return Resp(200, {"results": [{"vulns": [{"id": "B", "modified": "m"}]}]})
            return Resp(200, {"results": [{"vulns": [{"id": "A", "modified": "m"}], "next_page_token": "t"}]})
    out = osv.OSV(":memory:", session=Paged()).query([{"package": {"ecosystem": "PyPI", "name": "x"}, "version": "1"}])
    assert out == [[("A", "m"), ("B", "m")]]


def test_notice_expanded_only_for_uncovered_cves(fake):
    """Debian 10/11 only get DSA/DLA notices in OSV: their CVEs must still be reported, once."""
    pkg = ("Debian:11", "policykit-1", "0.105-31", "libpolkit-gobject-1-0", "0.105-31")
    v = {"DSA-5059-1": {"id": "DSA-5059-1", "modified": "m", "summary": "policykit-1 - security update",
                        "upstream": ["CVE-2021-4034", "DEBIAN-CVE-2021-4034", "CVE-2025-0009"],
                        "affected": [{"package": {"ecosystem": "Debian:11", "name": "policykit-1"},
                                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.105-31+deb11u1"}]}]}]},
         "DEBIAN-CVE-2025-0009": {"id": "DEBIAN-CVE-2025-0009", "modified": "m",
                                  "affected": [{"package": {"ecosystem": "Debian:11", "name": "policykit-1"},
                                                "ranges": [{"events": [{"fixed": "0.105-31+deb11u2"}]}]}]},
         "CVE-2021-4034": {"id": "CVE-2021-4034", "modified": "m", "severity": [{"type": "CVSS_V3", "score":
                           "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}]}}
    s = fake(hits={pkg[:3]: ["DSA-5059-1", "DEBIAN-CVE-2025-0009"]}, vulns=v)
    rows = {r["id"]: r for r in osv.match(osv.OSV(":memory:", session=s), [pkg], {"CVE-2021-4034"})}
    assert set(rows) == {"CVE-2021-4034", "CVE-2025-0009"}
    pk = rows["CVE-2021-4034"]
    assert pk["kev"] and pk["fixed"] == "0.105-31+deb11u1" and pk["severity"] == "HIGH"
    assert rows["CVE-2025-0009"]["fixed"] == "0.105-31+deb11u2"        # the per-CVE record wins over the notice


def test_cache_schema_upgrade(tmp_path):
    import sqlite3
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("create table osv_vulns(id text primary key, modified text, body text, fetched text)")
    con.execute("insert into osv_vulns values('X','m','{}','now')")
    con.commit()
    con.close()
    c = osv.OSV(db)
    assert c.con.execute("select count(*) from osv_vulns").fetchone()[0] == 0
    assert c.con.execute("pragma user_version").fetchone()[0] == osv.CACHE_SCHEMA
