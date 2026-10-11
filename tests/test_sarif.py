import json
import os
import re
import subprocess
import sys
from pathlib import Path

from sieve import cli, sarif, sources

ROOT = Path(__file__).resolve().parent.parent
LEVELS = {"none", "note", "warning", "error"}


def finding(id, pkg="openssl", target="host", kev=False, fixed="2.0", sev="HIGH", epss=0.02, installed="1.0"):
    return {"id": id, "package": pkg, "installed": installed, "fixed": fixed, "severity": sev, "summary": f"{id} summary",
            "kev": kev, "status": "fixed" if fixed else "affected", "target": target, "details": "details",
            "url": f"https://example.org/{id}", "epss": epss, "epss_percentile": 0.5, "tier": 4}


def check(doc):
    """The parts of the SARIF 2.1.0 schema GitHub code scanning relies on (no network, no jsonschema)."""
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-schema-2.1.0.json")
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    drv = run["tool"]["driver"]
    assert drv["name"] == "sieve" and drv["version"]
    ids = [r["id"] for r in drv["rules"]]
    assert len(ids) == len(set(ids)), "rule ids must be unique"
    for r in drv["rules"]:
        assert r["shortDescription"]["text"] and r["helpUri"].startswith("http")
        assert r["defaultConfiguration"]["level"] in LEVELS
        assert re.fullmatch(r"\d+\.\d", r["properties"]["security-severity"])
    for res in run["results"]:
        assert res["message"]["text"]
        assert res["level"] in LEVELS
        assert drv["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] and " " not in loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1
        assert all(isinstance(v, str) for v in res["partialFingerprints"].values())
    for inv in run["invocations"]:
        assert isinstance(inv["executionSuccessful"], bool)
    json.dumps(doc)                                  # serialisable as-is
    return run


def test_levels_and_scores():
    assert sarif.level(finding("A", kev=True, sev="LOW")) == "error"
    assert sarif.level(finding("A", sev="MEDIUM", epss=0.4)) == "error"         # hot and fixable
    assert sarif.level(finding("A", sev="MEDIUM", epss=0.4, fixed="")) == "warning"
    assert sarif.level(finding("A", sev="CRITICAL")) == "error"
    assert sarif.level(finding("A", sev="LOW")) == "note"
    assert sarif.score(finding("A", kev=True, sev="LOW")) >= 9.0
    assert sarif.score(finding("A", sev="MEDIUM")) == 5.5


def test_build_structure_rules_and_fingerprints():
    fs = [finding("CVE-2024-1", pkg="openssl"), finding("CVE-2024-1", pkg="libssl3", kev=True, sev="LOW"),
          finding("GHSA-xxxx-yyyy-zzzz", pkg="requests", target="example/app:1", sev="MEDIUM", fixed="")]
    run = check(sarif.build([{"name": "host", "kind": "host", "os": "debian 13", "packages": 10, "status": "ok",
                              "notes": []}], fs, []))
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert set(rules) == {"CVE-2024-1", "GHSA-xxxx-yyyy-zzzz"}
    # one KEV package lifts the shared rule
    assert "kev" in rules["CVE-2024-1"]["properties"]["tags"]
    assert float(rules["CVE-2024-1"]["properties"]["security-severity"]) >= 9.0
    assert rules["CVE-2024-1"]["helpUri"] == "https://example.org/CVE-2024-1"
    assert len(run["results"]) == 3
    assert run["results"][2]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "example/app:1/requests"
    assert "no fix released yet" in run["results"][2]["message"]["text"]
    assert run["invocations"][0]["executionSuccessful"] is True
    # an upgrade that is still affected keeps the same alert; another package is another alert
    fp = lambda f: sarif.build([], [f], [])["runs"][0]["results"][0]["partialFingerprints"]  # noqa: E731
    assert fp(finding("CVE-2024-1", installed="1.0")) == fp(finding("CVE-2024-1", installed="1.1"))
    assert fp(finding("CVE-2024-1")) != fp(finding("CVE-2024-1", pkg="libssl3"))


def test_errors_and_partial_targets_are_notifications():
    run = check(sarif.build([{"name": "c1", "kind": "container", "os": "?", "packages": 0, "status": "partial",
                              "notes": ["2 advisories could not be fetched"]}], [], ["collector exited 1: boom"]))
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is False
    texts = [n["message"]["text"] for n in inv["toolExecutionNotifications"]]
    assert "collector exited 1: boom" in texts and any("c1: partial" in t for t in texts)
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []


def test_cli_sarif(monkeypatch, capsys, tmp_path):
    t = sources.Target("host", "host")
    t.os, t.packages = "debian 13", 10
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [finding("CVE-2024-1", kev=True)], []))
    assert cli.main(["host", "--sarif", "--cache", str(tmp_path / "c.db")]) == 1      # exit codes unchanged
    run = check(json.loads(capsys.readouterr().out))
    assert run["results"][0]["ruleId"] == "CVE-2024-1" and run["results"][0]["level"] == "error"


def test_from_report_matches_cli(monkeypatch, capsys, tmp_path):
    t = sources.Target("host", "host")
    t.os, t.packages = "debian 13", 10
    fs = [finding("CVE-2024-1"), finding("CVE-2024-2", sev="LOW")]
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [dict(f) for f in fs], []))
    cli.main(["host", "--json", "--cache", str(tmp_path / "c.db")])
    report = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [dict(f) for f in fs], []))
    cli.main(["host", "--sarif", "--cache", str(tmp_path / "c.db")])
    direct = json.loads(capsys.readouterr().out)
    assert sarif.from_report(report)["runs"][0]["results"] == direct["runs"][0]["results"]


def test_action_writes_sarif_from_the_report(tmp_path):
    """Run the Python step of action.yml as the runner would, with the sarif input on."""
    text = (ROOT / "action.yml").read_text()
    body = text.split("<<'PY'\n", 1)[1].split("\n        PY\n", 1)[0]
    script = "\n".join(line[8:] for line in body.splitlines())
    report = tmp_path / "sieve-report.json"
    report.write_text(json.dumps({"sieve": "0.1.0", "targets": [{"name": "host", "kind": "host", "os": "debian 13",
                                  "packages": 10, "status": "ok", "notes": []}], "errors": [],
                                  "summary": {"findings": 1, "kev": 0, "fixable": 1},
                                  "findings": [finding("CVE-2024-1")]}))
    out, summ = tmp_path / "out", tmp_path / "summary"
    env = dict(os.environ, GITHUB_OUTPUT=str(out), GITHUB_STEP_SUMMARY=str(summ), RUNNER_TEMP=str(tmp_path),
               SIEVE_SARIF="true", PYTHONPATH=str(ROOT))
    subprocess.run([sys.executable, "-", str(report)], input=script, text=True, env=env, check=True,
                   capture_output=True)
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert outputs["sarif"] == str(tmp_path / "sieve.sarif")
    run = check(json.loads(Path(outputs["sarif"]).read_text()))
    assert run["results"][0]["ruleId"] == "CVE-2024-1"
    env["SIEVE_SARIF"] = "false"
    out.write_text("")
    subprocess.run([sys.executable, "-", str(report)], input=script, text=True, env=env, check=True,
                   capture_output=True)
    assert "sarif=" not in out.read_text()
