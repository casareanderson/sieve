from sieve import rank


def f(id, sev="HIGH", fixed="1.1", kev=False, epss=None, pkg="p", target="host"):
    return {"id": id, "severity": sev, "fixed": fixed, "kev": kev, "epss": epss, "package": pkg, "target": target,
            "status": "fixed" if fixed else "affected"}


def test_order():
    rows = [f("nofix-crit", "CRITICAL", fixed=""), f("crit", "CRITICAL"), f("hot", "LOW", epss=0.4),
            f("kev-nofix", "MEDIUM", fixed="", kev=True), f("high", "HIGH", epss=0.05), f("med", "MEDIUM"),
            f("hot-nofix", "HIGH", fixed="", epss=0.9), f("hotter", "MEDIUM", epss=0.8)]
    assert [r["id"] for r in rank.rank(rows)] == ["kev-nofix", "hotter", "hot", "crit", "high", "med",
                                                  "hot-nofix", "nofix-crit"]


def test_filters():
    rows = [f("a", "LOW", kev=True), f("b", "LOW"), f("c", "CRITICAL", fixed=""), f("d", "HIGH")]
    ids = lambda xs: sorted(r["id"] for r in xs)   # noqa: E731
    assert ids(rank.apply_filters(rows, min_severity="high")) == ["a", "c", "d"]   # KEV never hidden
    assert ids(rank.apply_filters(rows, kev_only=True)) == ["a"]
    assert ids(rank.apply_filters(rows, fixable_only=True)) == ["a", "b", "d"]


def test_summary():
    s = rank.summary([f("a", kev=True), f("b", fixed=""), f("c", "CRITICAL"), f("d", epss=0.5)])
    assert s == {"findings": 4, "kev": 1, "fixable": 3, "epss_hot_fixable": 1, "critical_fixable": 1}
