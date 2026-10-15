"""SBOM export (CycloneDX 1.6 / SPDX 2.3, validated against the official schemas) and import (syft, GitHub)."""
import json
import os
import re

import pytest

from sieve import cli, osv, sbom, sources

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
SCHEMAS = os.path.join(FIX, "sbom-schemas")


def validator(name):
    """The official schema, with its $refs resolved from the vendored copies (no network). Skipped when the schemas
    or jsonschema aren't there (the sdist leaves the schemas out)."""
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    if not os.path.isdir(SCHEMAS):
        pytest.skip("schemas not vendored here")
    files = {}
    for f in os.listdir(SCHEMAS):
        if f.endswith(".json"):
            with open(os.path.join(SCHEMAS, f)) as fh:
                files[f] = json.load(fh)
    reg = referencing.Registry().with_resources(
        (d.get("$id", f), referencing.Resource.from_contents(d, default_specification=referencing.jsonschema.DRAFT7))
        for f, d in files.items())
    return jsonschema.Draft7Validator(files[name], registry=reg)


def targets():
    host = sources.Target("host", "host")
    host.os = "debian 12"
    entries = [("openssl", "3.0.11-1~deb12u2", "libssl3", "3.0.11-1~deb12u2"), ("bash", "5.2.15-2", "bash", "5.2.15-2"),
               ("glibc", "2.36-9", "libc6", "1:2.36-9")]
    host.osinv = ("Debian:12", "debian 12", "deb", entries)
    host.pkgs = osv.os_packages("Debian:12", entries) + [
        ("PyPI", "PyYAML", "6.0.1", "PyYAML", "6.0.1"), ("npm", "@babel/core", "7.24.0", "@babel/core", "7.24.0")]
    img = sources.Target("rocky:9", "container")
    img.os = "rocky 9.3"
    rentries = osv.parse_rpm("openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\n"
                             "bash\t\t5.1.8\t6.el9_1\tx86_64\tbash-5.1.8-6.el9_1.src.rpm\n")
    img.osinv = ("Rocky Linux:9", "rocky 9.3", "rpm", rentries)
    img.pkgs = osv.os_packages("Rocky Linux:9", rentries) + [
        ("Go", "stdlib", "1.21.3", "stdlib", "1.21.3"), ("Go", "golang.org/x/net", "v0.17.0", "golang.org/x/net", "v0.17.0"),
        ("crates.io", "rustls", "0.21.7", "rustls", "0.21.7")]
    alp = sources.Target("alpine", "container")
    alp.os = "alpine 3.18.4"
    aentries = [("openssl", "3.1.4-r0", "libcrypto3", "3.1.4-r0")]
    alp.osinv = ("Alpine:v3.18", "alpine 3.18.4", "apk", aentries)
    alp.pkgs = osv.os_packages("Alpine:v3.18", aentries)
    return [host, img, alp]


def norm(pkgs):
    """PyPI names are compared normalised: the purl spec lowercases them, OSV matches them either way."""
    return {(e, re.sub(r"[-_.]+", "-", n).lower() if e == "PyPI" else n, v) for e, n, v, _, _ in pkgs}


@pytest.mark.parametrize("p", [
    "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl",
    "pkg:npm/%40babel/core@7.24.0", "pkg:golang/golang.org/x/net@v0.17.0",
    "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3&epoch=1"])
def test_purl_round_trip(p):
    typ, ns, name, ver, q = sbom.parse_purl(p)
    assert sbom.purl(typ, ns, name, ver, q) == p


def test_purls_written():
    ps = {c[0] for t in targets() for c in sbom.components(t)}
    assert "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl" in ps
    assert "pkg:deb/debian/libc6@1%3A2.36-9?distro=debian-12&upstream=glibc%402.36-9" in ps
    assert "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-24.el9.src.rpm" in ps
    assert "pkg:npm/%40babel/core@7.24.0" in ps and "pkg:pypi/pyyaml@6.0.1" in ps
    assert "pkg:apk/alpine/libcrypto3@3.1.4-r0?distro=alpine-3.18.4&upstream=openssl" in ps
    assert "pkg:golang/golang.org/x/net@v0.17.0" in ps and "pkg:cargo/rustls@0.21.7" in ps


def test_cyclonedx_valid_and_vulns_linked():
    ts = targets()
    f = {"id": "CVE-2024-1", "package": "libssl3", "installed": "3.0.11-1~deb12u2", "target": "host", "kev": True,
         "malicious": False, "severity": "HIGH", "fixed": "3.0.13-1", "status": "fixed", "summary": "x", "url": "",
         "epss": 0.4, "in_use": "loaded"}
    doc = sbom.build("cyclonedx", ts, [f])
    errs = sorted(validator("bom-1.6.schema.json").iter_errors(doc), key=str)
    assert not errs, errs[0]
    refs = {c["bom-ref"] for t in doc["components"] for c in t["components"]}
    v = doc["vulnerabilities"][0]
    assert v["affects"][0]["ref"] in refs and v["ratings"][0]["severity"] == "high"
    assert {"name": "sieve:kev", "value": "true"} in v["properties"]
    assert [c["type"] for c in doc["components"]] == ["operating-system", "container", "container"]


def test_spdx_valid():
    doc = sbom.build("spdx", targets())
    errs = sorted(validator("spdx-schema.json").iter_errors(doc), key=str)
    assert not errs, errs[0]
    assert sum(r["relationshipType"] == "CONTAINS" for r in doc["relationships"]) == len(doc["packages"]) - 3


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_round_trip_same_packages(tmp_path, fmt):
    ts = targets()
    p = tmp_path / "x.json"
    p.write_text(json.dumps(sbom.build(fmt, ts)))
    back = sbom.read_file(str(p))
    assert back.status == "ok", back.notes
    assert norm(back.pkgs) == norm(p for t in ts for p in t.pkgs)


def test_import_syft_alpine():
    t = sbom.read_file(os.path.join(FIX, "sbom-syft-alpine-3.18.cdx.json"))
    assert t.status == "ok" and t.packages == 15 and t.os.startswith("alpine 3.18")
    assert ("Alpine:v3.18", "alpine-baselayout", "3.4.3-r1", "alpine-baselayout-data", "3.4.3-r1") in t.pkgs


def test_import_syft_debian_python_reports_what_it_skips():
    t = sbom.read_file(os.path.join(FIX, "sbom-syft-python-3.11-slim.cdx.json"))
    ecos = {p[0] for p in t.pkgs}
    assert "Debian:12" in ecos and "PyPI" in ecos and "NuGet" in ecos
    assert t.status == "partial" and "not in OSV" in t.notes[0]          # syft's pkg:generic python binary


def test_import_github_spdx_without_versions():
    t = sbom.read_file(os.path.join(FIX, "sbom-github-depgraph.spdx.json"))
    assert t.status == "partial" and "6 no version" in t.notes[0] and not t.pkgs


def test_import_rejects_other_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"hello": 1}')
    t = sbom.read_file(str(p))
    assert t.status == "error" and "not a CycloneDX or SPDX" in t.notes[0]


def test_export_never_asks_osv(monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("OSV/KEV must not be touched by a plain --sbom export")
    monkeypatch.setattr(cli.osv, "OSV", boom)
    monkeypatch.setattr(cli.intel, "kev_set", boom)
    monkeypatch.setattr(cli.sources, "host", lambda root, kernel, **kw: targets()[0])
    assert cli.main(["host", "--sbom", "cyclonedx"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX" and len(doc["components"][0]["components"]) == 5


def test_sbom_command_scans(monkeypatch, capsys, tmp_path):
    class Client:
        failed = 0
    seen = []

    def match(client, pkgs, kev, target=""):
        seen.extend(pkgs)
        return [{"id": "CVE-2024-9", "package": "libcrypto3", "installed": "3.1.4-r0", "fixed": "3.1.5-r0",
                 "severity": "HIGH", "summary": "", "kev": False, "malicious": False, "status": "fixed",
                 "target": target, "details": "", "url": ""}]
    monkeypatch.setattr(cli.osv, "OSV", lambda cache: Client())
    monkeypatch.setattr(cli.osv, "match", match)
    monkeypatch.setattr(cli.intel, "kev_set", lambda d: set())
    p = tmp_path / "a.cdx.json"
    p.write_text(json.dumps(sbom.build("cyclonedx", [targets()[2]])))
    assert cli.main(["sbom", str(p), "--no-epss", "--cache", str(tmp_path / "c.db")]) == 0
    out = capsys.readouterr().out
    assert "CVE-2024-9" in out and "sbom:a.cdx.json" in out and ("Alpine:v3.18", "openssl") == seen[0][:2]


def test_plain_scan_does_not_import_sbom():
    import subprocess
    import sys
    code = "import sieve.cli, sys; sieve.cli.parser(); print('sieve.sbom' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
    assert out.strip() == "False"
