import gzip
import json
import os
import time

import pytest

from sieve import cli, intel, sources


def finding(id, kev=False, fixed="2.0", sev="HIGH"):
    return {"id": id, "package": "openssl", "installed": "1.0", "fixed": fixed, "severity": sev, "summary": "",
            "kev": kev, "status": "fixed" if fixed else "affected", "target": "host", "details": "", "url": "",
            "epss": 0.25, "epss_percentile": 0.97}


def patch_scan(monkeypatch, findings, errors=()):
    t = sources.Target("host", "host")
    t.os, t.packages = "debian 13", 10
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [dict(x) for x in findings], list(errors)))


def test_exit_code_kev(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-2024-1", kev=True), finding("CVE-2024-2")])
    assert cli.main(["host", "--cache", str(tmp_path / "c.db")]) == 1
    out = capsys.readouterr().out
    assert "2 findings, 1 actively exploited, 2 fixable" in out
    assert "⚠" in out and "25.0%" in out and "1.0 → 2.0" in out


def test_exit_code_clean_and_filters(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-2024-2"), finding("CVE-2024-3", fixed="")])
    assert cli.main(["host", "--fixable-only", "--cache", str(tmp_path / "c.db")]) == 0
    assert "1 findings, 0 actively exploited, 1 fixable (1 hidden by filters)" in capsys.readouterr().out


def test_exit_code_error(monkeypatch, tmp_path):
    patch_scan(monkeypatch, [], errors=["containers: docker CLI not found"])
    assert cli.main(["all", "--cache", str(tmp_path / "c.db")]) == 2


def test_json(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-2024-1", kev=True)])
    assert cli.main(["host", "--json", "--cache", str(tmp_path / "c.db")]) == 1
    d = json.loads(capsys.readouterr().out)
    assert d["summary"]["kev"] == 1 and d["findings"][0]["tier"] == 1 and d["targets"][0]["os"] == "debian 13"


def test_table_limit():
    rows = [finding(f"CVE-2024-{i}") for i in range(5)]
    assert "… 3 more" in cli.table(rows, 2)


def test_collector_command(capsys):
    assert cli.main(["collector"]) == 0
    assert "def main()" in capsys.readouterr().out


class Boom:
    def get(self, *a, **k):
        raise AssertionError("network used")


def test_kev_epss_from_fresh_cache(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, "kev.json"), "w") as f:
        json.dump({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}, f)
    with gzip.open(os.path.join(d, "epss.csv.gz"), "wt") as f:
        f.write("#model_version:v2025.03.14,score_date:2026-10-10T00:00:00Z\ncve,epss,percentile\n"
                "CVE-2021-44228,0.94358,0.99957\nCVE-2020-0001,0.001,0.2\n")
    assert intel.kev_set(d, session=Boom()) == {"CVE-2021-44228"}
    assert intel.epss_scores(d, {"CVE-2021-44228"}, session=Boom()) == {"CVE-2021-44228": (0.94358, 0.99957)}


def test_kev_stale_cache_used_when_fetch_fails(tmp_path, capsys):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2014-0160"}]}))
    old = time.time() - 3 * 86400
    os.utime(p, (old, old))

    class Down:
        def get(self, *a, **k):
            import requests
            raise requests.ConnectionError("offline")
    assert intel.kev_set(str(tmp_path), session=Down()) == {"CVE-2014-0160"}
    assert "KEV refresh failed" in capsys.readouterr().err


def test_root_option_reaches_host_scan(monkeypatch, tmp_path):
    seen = {}

    def fake_host(root="/", kernel=False):
        seen["root"] = root
        return sources.Target("host", "host")
    monkeypatch.setattr(sources, "host", fake_host)
    monkeypatch.setattr(intel, "kev_set", lambda d: set())
    assert cli.main(["host", "--root", str(tmp_path), "--cache", str(tmp_path / "c.db")]) == 0
    assert seen["root"] == str(tmp_path)
    assert cli.main(["host", "--cache", str(tmp_path / "c.db")]) == 0
    assert seen["root"] == "/"


def test_version_matches_package(capsys):
    from sieve import __version__
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"sieve {__version__}" == "sieve 0.2.0"
