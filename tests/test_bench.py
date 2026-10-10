"""bench/run.py: id normalisation, the four parsers, the comparison and the report. Offline, fixture-driven."""
import importlib.util
import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "bench")
_spec = importlib.util.spec_from_file_location("bench_run", os.path.join(ROOT, "bench", "run.py"))
bench = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench)

REF = "debian:10.13-slim@sha256:bb3dc79fddbca7e8903248ab916bb775c96ec61014b3d02b4f06043b604726dc"
LOCAL = "sievebench/debian-10.13-slim:pinned"
KEV = {"CVE-2021-3156", "CVE-2022-0847", "CVE-2023-4911", "CVE-2023-44487"}


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def ids(records):
    return {r["id"] for r in records}


@pytest.mark.parametrize("vid,aliases,upstream,related,want", [
    ("CVE-2021-3156", [], [], [], ["CVE-2021-3156"]),
    ("DEBIAN-CVE-2023-0286", [], [], [], ["CVE-2023-0286"]),
    ("UBUNTU-CVE-2022-0847", [], [], [], ["CVE-2022-0847"]),
    ("GHSA-r9hx-vwmv-q579", ["PYSEC-2022-43012", "CVE-2022-40897"], [], [], ["CVE-2022-40897"]),
    ("GO-2023-1234", [], ["CVE-2023-1111"], [], ["CVE-2023-1111"]),
    ("DLA-3325-1", [], ["CVE-2023-0286", "CVE-2022-4304"], [], ["CVE-2022-4304", "CVE-2023-0286"]),
    ("USN-6000-1", [], [], ["UBUNTU-CVE-2023-1", "CVE-2023-0002"], ["CVE-2023-0002"]),
    ("GHSA-aaaa-bbbb-cccc", ["PYSEC-2020-1"], [], [], ["GHSA-aaaa-bbbb-cccc"]),
    # a non-notice record's `related` is not an alias: don't borrow CVEs from it
    ("GHSA-aaaa-bbbb-dddd", [], [], ["CVE-2020-0001"], ["GHSA-aaaa-bbbb-dddd"]),
    ("", None, None, None, []),
])
def test_canon_ids(vid, aliases, upstream, related, want):
    assert bench.canon_ids(vid, aliases, upstream, related) == want


def test_severity_helpers():
    assert bench.sev_from_cvss("9.8") == "CRITICAL" and bench.sev_from_cvss(7.4) == "HIGH"
    assert bench.sev_from_cvss("") == "UNKNOWN" and bench.sev_from_cvss(None) == "UNKNOWN"
    assert bench.norm_sev("Moderate") == "MEDIUM" and bench.norm_sev("Negligible") == "NEGLIGIBLE"
    assert bench.norm_sev("weird") == "UNKNOWN"
    assert bench.worse("LOW", "CRITICAL") == "CRITICAL"


def test_parse_trivy():
    recs = bench.parse_trivy(load("trivy.json"))
    assert ids(recs) == {"CVE-2023-0286", "CVE-2021-3156", "CVE-2022-0847", "CVE-2019-12904", "CVE-2022-40897",
                         "GHSA-xxxx-only-trvy"}
    ssl = next(r for r in recs if r["id"] == "CVE-2023-0286")
    assert (ssl["package"], ssl["type"], ssl["src_name"], ssl["src_version"]) == \
        ("libssl1.1", "os", "openssl", "1.1.1n-0+deb10u3")
    st = next(r for r in recs if r["id"] == "CVE-2022-40897")
    assert (st["type"], st["src_name"], st["severity"]) == ("python", "setuptools", "MEDIUM")
    assert bench.parse_trivy({}) == [] and bench.parse_trivy(None) == []


def test_parse_grype():
    recs = bench.parse_grype(load("grype.json"))
    assert ids(recs) == {"CVE-2023-0286", "CVE-2021-3156", "CVE-2022-40897", "CVE-2023-44487", "CVE-2024-9999"}
    ghsa = next(r for r in recs if r["id"] == "CVE-2022-40897")
    assert ghsa["tool_id"] == "GHSA-r9hx-vwmv-q579" and ghsa["type"] == "python"
    node = next(r for r in recs if r["id"] == "CVE-2023-44487")
    assert node["type"] == "binary" and node["severity"] == "CRITICAL"     # borrowed from the related record
    ssl = next(r for r in recs if r["id"] == "CVE-2023-0286")
    assert ssl["src_name"] == "openssl" and ssl["src_version"] == "1.1.1n-0+deb10u3"


def test_parse_osv_scanner():
    recs = bench.parse_osv_scanner(load("osv-scanner.json"))
    assert ids(recs) == {"CVE-2022-4304", "CVE-2023-0286", "CVE-2023-0215", "CVE-2021-3156", "CVE-2022-40897"}
    ssl = next(r for r in recs if r["id"] == "CVE-2023-0286")
    assert (ssl["package"], ssl["src_name"], ssl["eco"], ssl["severity"]) == \
        ("libssl1.1", "openssl", "Debian:10", "HIGH")
    st = [r for r in recs if r["id"] == "CVE-2022-40897"]
    assert len(st) == 2 and all(r["type"] == "python" for r in st)       # GHSA + PYSEC: same CVE, deduped later
    assert bench.by_cve(st)["CVE-2022-40897"]["severity"] == "MEDIUM"


def test_parse_sieve_maps_targets_and_ignores_others():
    recs, targets = bench.parse_sieve(load("sieve.json"), {LOCAL: REF})
    assert set(recs) == {REF} and set(targets) == {REF}
    assert ids(recs[REF]) == {"CVE-2021-3156", "CVE-2023-0286", "CVE-2022-40897", "CVE-2023-4911"}
    assert targets[REF]["os"] == "debian 10"


@pytest.mark.parametrize("label,want", [
    ("debian 10", "Debian:10"), ("debian 12.0", "Debian:12"), ("ubuntu 22.04", "Ubuntu:22.04:LTS"),
    ("ubuntu 23.10", "Ubuntu:23.10"), ("alpine 3.18.0", "Alpine:v3.18"), ("fedora 40", ""), ("", ""), (None, ""),
])
def test_osv_ecosystem(label, want):
    assert bench.osv_ecosystem(label) == want


def _all_records():
    recs, targets = bench.parse_sieve(load("sieve.json"), {LOCAL: REF})
    per_tool = {"sieve": recs[REF], "trivy": bench.parse_trivy(load("trivy.json")),
                "grype": bench.parse_grype(load("grype.json")),
                "osv-scanner": bench.parse_osv_scanner(load("osv-scanner.json"))}
    return per_tool, targets[REF]


def test_compare_image():
    per_tool, target = _all_records()
    asked = []

    def osv_check(cve, eco, name, version):
        asked.append((cve, eco, name, version))
        return cve == "CVE-2024-9999"
    status = {t: "ok" for t in bench.TOOLS}
    c = bench.compare_image(per_tool, status, KEV, target, osv_check)
    assert c["counts"] == {"sieve": 4, "trivy": 6, "grype": 5, "osv-scanner": 5}
    assert c["vs_sieve"]["trivy"] == {"overlap": 3, "sieve_only": 1, "tool_only": 3}
    assert c["vs_sieve"]["grype"] == {"overlap": 3, "sieve_only": 1, "tool_only": 2}
    assert c["vs_sieve"]["osv-scanner"] == {"overlap": 3, "sieve_only": 1, "tool_only": 2}
    # union of others minus sieve: 0847, 12904, GHSA-x, 44487, 9999, 4304, 0215 → 7; sieve-only: 4911
    assert c["missed_by_sieve"] == 7 and c["sieve_only_all"] == 1
    kev = {k["id"]: k["caught_by"] for k in c["kev"]}
    assert kev == {"CVE-2021-3156": ["sieve", "trivy", "grype", "osv-scanner"], "CVE-2022-0847": ["trivy"],
                   "CVE-2023-4911": ["sieve"], "CVE-2023-44487": ["grype"]}
    miss = {m["id"]: m for m in c["misses"]}
    # HIGH-only misses (CVE-2022-4304, CVE-2023-0215) are counted but not listed
    assert set(miss) == {"CVE-2019-12904", "CVE-2022-0847", "CVE-2023-44487", "CVE-2024-9999"}
    assert miss["CVE-2022-0847"]["reason"].startswith("kernel package") and miss["CVE-2022-0847"]["kev"]
    assert miss["CVE-2023-44487"]["reason"] == "package type sieve does not read (binary)"
    assert miss["CVE-2024-9999"]["osv_listed"] is True and miss["CVE-2024-9999"]["reason"].startswith("unknown")
    assert miss["CVE-2019-12904"]["osv_listed"] is False
    assert miss["CVE-2019-12904"]["reason"].startswith("OSV does not list this CVE for libgcrypt20 1.8.4-5+deb10u1 in Debian:10")
    assert miss["CVE-2019-12904"]["found_by"] == ["trivy"] and miss["CVE-2019-12904"]["sieve_saw_package"] is False
    # OS packages are looked up by source package in the image's own ecosystem; kernel/binary misses aren't asked
    assert ("CVE-2019-12904", "Debian:10", "libgcrypt20", "1.8.4-5+deb10u1") in asked
    assert ("CVE-2024-9999", "Debian:10", "zlib", "1:1.2.11.dfsg-1+deb10u2") in asked
    assert not any(a[0] in ("CVE-2022-0847", "CVE-2023-44487") for a in asked)


def test_compare_without_osv_check_says_unknown():
    per_tool, target = _all_records()
    c = bench.compare_image(per_tool, {t: "ok" for t in bench.TOOLS}, KEV, target)
    miss = {m["id"]: m for m in c["misses"]}
    assert miss["CVE-2019-12904"]["reason"] == "unknown" and miss["CVE-2019-12904"]["osv_listed"] is None


def test_compare_with_failed_tools():
    per_tool, target = _all_records()
    status = {"sieve": "ok", "trivy": "error", "grype": "ok", "osv-scanner": "ok"}
    c = bench.compare_image(per_tool, status, KEV, target)
    assert c["counts"]["trivy"] is None and "trivy" not in c["vs_sieve"]
    assert "CVE-2022-0847" not in {k["id"] for k in c["kev"]}       # only trivy had it, and trivy failed
    c = bench.compare_image(per_tool, {"sieve": "error", "trivy": "ok"}, KEV, None)
    assert c["missed_by_sieve"] is None and c["misses"] == [] and c["vs_sieve"] == {}


def test_classify_partial_target_and_no_target():
    info = {"packages": {"libfoo"}, "types": {"os"}, "srcs": set(), "severity": "CRITICAL"}
    assert bench.classify_miss("CVE-1", [info], None, set())[0] == "sieve did not scan this image"
    r, _ = bench.classify_miss("CVE-1", [info], {"status": "partial"}, set())
    assert r == "possibly: sieve's scan of this image was partial"


class _Resp:
    def __init__(self, body, status=200):
        self.body, self.status = body, status

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(self.status)

    def json(self):
        return self.body


class _Session:
    def __init__(self, pages=None, fail=False):
        self.pages, self.fail, self.calls = pages or [], fail, []

    def post(self, url, json=None, timeout=None):
        self.calls.append(json)
        if self.fail:
            return _Resp({}, 503)
        return _Resp(self.pages[len(self.calls) - 1])


def test_osv_check_paginates_expands_notices_and_caches():
    s = _Session([{"vulns": [{"id": "DLA-1-1", "upstream": ["CVE-2023-0001", "CVE-2023-0002"]}],
                   "next_page_token": "t"},
                  {"vulns": [{"id": "DEBIAN-CVE-2023-0003"}, {"id": "CVE-2023-0004", "withdrawn": "2024"}]}])
    check = bench.make_osv_check(s)
    assert check("CVE-2023-0002", "Debian:10", "openssl", "1.1.1n-0+deb10u3") is True
    assert check("CVE-2023-0003", "Debian:10", "openssl", "1.1.1n-0+deb10u3") is True
    assert check("CVE-2023-0004", "Debian:10", "openssl", "1.1.1n-0+deb10u3") is False   # withdrawn
    assert len(s.calls) == 2 and s.calls[1]["page_token"] == "t"
    assert check("CVE-2023-0001", "Debian:10", "zlib", "1") is None                       # page list exhausted


def test_osv_check_failure_is_unknown_and_budgeted():
    s = _Session(fail=True)
    check = bench.make_osv_check(s, budget=1)
    assert check("CVE-1", "PyPI", "x", "1") is None
    assert check("CVE-1", "PyPI", "y", "1") is None and len(s.calls) == 1


def _results():
    per_tool, target = _all_records()
    status = {t: "ok" for t in bench.TOOLS}
    cmp = bench.compare_image(per_tool, status, KEV, target, lambda *a: None)
    imgs = [{"ref": REF, "slug": "debian-10.13-slim", "status": status, "sieve_target": target, "runs": {},
             "comparison": cmp},
            {"ref": "alpine:3.18.0@sha256:00", "slug": "alpine-3.18.0", "status": {"sieve": "error"},
             "sieve_target": None, "runs": {},
             "comparison": bench.compare_image({}, {"sieve": "error"}, KEV)}]
    return {"generated": "2026-10-10 12:00 UTC", "runner": "test",
            "tools": {"sieve": {"version": "0.1.0", "seconds": 42.0, "peak_kb": 204800},
                      "trivy": {"version": "0.74.0", "seconds": 3.2, "peak_kb": None, "note": "DB download 9.0s"}},
            "kev_version": "2026.10.09", "kev_count": 1500, "images": imgs, "totals": bench.totals(imgs, KEV),
            "errors": ["alpine-3.18.0: docker pull failed: x"]}


def test_totals_and_render():
    res = _results()
    t = res["totals"]
    assert t["found"]["sieve"] == 4 and t["images_ok"]["sieve"] == 1 and t["images_ok"]["trivy"] == 1
    assert t["kev_any"] == 4 and t["kev_caught"]["sieve"] == 2 and t["kev_caught"]["trivy"] == 2
    assert t["missed"] == 7 and t["missed_kev"] == 2 and t["missed_critical"] == 2 and t["sieve_only"] == 1
    md = bench.render(res)
    for want in ("# sieve benchmark results", "## Summary", "## How to read this", "## Tools",
                 "### debian-10.13-slim", "## Where sieve misses", "## Errors", "CVE-2022-0847",
                 "package type sieve does not read (binary)", "| trivy | 0.74.0 | 3.2s | - | DB download 9.0s |",
                 "sieve: not scanned", "| sieve | 4 | | | | 2/4 |", "(1/2 images scanned)", "200 MB"):
        assert want in md, want
    # KEV misses are listed before CRITICAL ones
    assert md.index("CVE-2022-0847 | yes") < md.index("CVE-2019-12904 |")
    json.dumps(res)                                     # everything in results.json must serialise


def test_render_only_round_trip(tmp_path):
    p = tmp_path / "results.json"
    p.write_text(json.dumps(_results()))
    assert bench.main(["--render-only", str(p), "--out", str(tmp_path)]) == 0
    assert (tmp_path / "RESULTS.md").read_text().startswith("# sieve benchmark results")


def test_images_file_is_pinned():
    refs = bench.read_images(os.path.join(ROOT, "bench", "images.txt"))
    assert 6 <= len(refs) <= 9
    assert all("@sha256:" in r and len(r.split("@sha256:")[1]) == 64 for r in refs)
    slugs = [bench.slug_of(r) for r in refs]
    assert len(set(slugs)) == len(slugs) and "debian-10.13-slim" in slugs
    assert bench.slug_of("ghcr.io/org/app:1.2@sha256:ab") == "app-1.2"
    assert bench.slug_of("localhost:5000/app") == "app-latest"
