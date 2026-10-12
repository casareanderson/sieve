import json

from sieve import cli, diff, sources


def finding(id, kev=False, fixed="2.0", sev="HIGH", package="openssl", installed="1.0", target="host"):
    return {"id": id, "package": package, "installed": installed, "fixed": fixed, "severity": sev, "summary": "",
            "kev": kev, "status": "fixed" if fixed else "affected", "target": target, "details": "", "url": "",
            "epss": 0.25, "epss_percentile": 0.97}


def patch_scan(monkeypatch, findings, errors=(), status="ok"):
    t = sources.Target("host", "host")
    t.os, t.packages, t.status = "debian 13", 10, status
    monkeypatch.setattr(cli, "scan", lambda args, warn: ([t], [dict(x) for x in findings], list(errors)))


def run(capsys, tmp_path, *extra):
    rc = cli.main(["host", "--new", "--cache", str(tmp_path / "c.db"), *extra])
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def test_compare_keys_on_target_package_id():
    old = [finding("CVE-1"), finding("CVE-2")]
    new = [finding("CVE-1", installed="1.1"), finding("CVE-3")]          # a still-vulnerable bump is not new
    added, gone = diff.compare(old, new)
    assert [f["id"] for f in added] == ["CVE-3"] and [f["id"] for f in gone] == ["CVE-2"]


def test_scope_separates_scans(tmp_path):
    p = cli.parser()
    a = p.parse_args(["path", str(tmp_path / "a"), "--new"])
    b = p.parse_args(["path", str(tmp_path / "b"), "--new"])
    h = p.parse_args(["host", "--new"])
    assert len({diff.scope(a), diff.scope(b), diff.scope(h)}) == 3
    assert diff.scope(a) == diff.scope(p.parse_args(["path", str(tmp_path / "a")]))


def test_first_run_everything_new_then_quiet(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1", kev=True), finding("CVE-2")])
    rc, out, err = run(capsys, tmp_path)
    assert rc == 1 and "first --new run" in out and "baseline saved" in err
    rc, out, err = run(capsys, tmp_path)                                  # same findings: nothing new, exit 0
    assert rc == 0 and "0 new findings since" in out


def test_new_and_gone(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1"), finding("CVE-2")])
    run(capsys, tmp_path)
    patch_scan(monkeypatch, [finding("CVE-2"), finding("CVE-9", kev=True)])
    rc, out, _ = run(capsys, tmp_path)
    assert rc == 1                                                        # the NEW finding is known-exploited
    assert "1 new findings since" in out and "CVE-9" in out
    assert "1 gone since" in out and "CVE-1" in out


def test_old_kev_stays_quiet(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1", kev=True)])
    assert run(capsys, tmp_path)[0] == 1
    assert run(capsys, tmp_path)[0] == 0


def test_incomplete_scan_keeps_baseline_and_reports_nothing_gone(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1"), finding("CVE-2")])
    run(capsys, tmp_path)
    patch_scan(monkeypatch, [finding("CVE-2")], status="partial")
    rc, out, err = run(capsys, tmp_path)
    assert "gone since" not in out and "baseline is kept" in err
    patch_scan(monkeypatch, [finding("CVE-1"), finding("CVE-2")])     # complete again: CVE-1 was never gone
    rc, out, _ = run(capsys, tmp_path)
    assert "0 new findings since" in out and "gone since" not in out


def test_json_carries_baseline_and_gone(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1")])
    run(capsys, tmp_path)
    patch_scan(monkeypatch, [finding("CVE-2")])
    _, out, _ = run(capsys, tmp_path, "--json")
    d = json.loads(out)
    assert [f["id"] for f in d["findings"]] == ["CVE-2"]
    assert d["new_since"]["baseline"] and [f["id"] for f in d["new_since"]["gone"]] == ["CVE-1"]


def test_explicit_baseline_file(monkeypatch, capsys, tmp_path):
    patch_scan(monkeypatch, [finding("CVE-1")])
    run(capsys, tmp_path, "--baseline", str(tmp_path / "b.json"))
    assert json.load(open(tmp_path / "b.json"))["findings"][0]["id"] == "CVE-1"


def test_diff_command(capsys, tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps({"generated": "2026-10-01T00:00:00Z", "findings": [finding("CVE-1"), finding("CVE-2")]}))
    b.write_text(json.dumps({"generated": "2026-10-02T00:00:00Z", "findings": [finding("CVE-2"),
                                                                              finding("CVE-3", kev=True)]}))
    assert cli.main(["diff", str(a), str(b)]) == 1
    out = capsys.readouterr().out
    assert "1 new" in out and "CVE-3" in out and "1 gone" in out and "CVE-1" in out
    assert cli.main(["diff", str(a), str(b), "--json"]) == 1
    d = json.loads(capsys.readouterr().out)
    assert [f["id"] for f in d["new_findings"]] == ["CVE-3"] and [f["id"] for f in d["gone"]] == ["CVE-1"]


def test_diff_command_bad_file(capsys, tmp_path):
    (tmp_path / "x.json").write_text("[]")
    assert cli.main(["diff", str(tmp_path / "x.json"), str(tmp_path / "x.json")]) == 2
