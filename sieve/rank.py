"""Ranking and filtering.

Most of what a scanner reports is "affected, no fix released yet" (one box: 4,592 CVEs, 0 fixable). The order puts
what you can and should act on first:

  1. known exploited (CISA KEV), fix or not
  2. EPSS >= 10% (a 1-in-10 chance of exploitation in the next 30 days) with a fix available
  3. CRITICAL with a fix available
  4. everything else with a fix
  5. no fix yet

Within a tier: higher EPSS first, then higher severity.
"""
from .osv import SEV_RANK

EPSS_HOT = 0.1


def tier(f):
    if f["kev"]:
        return 1
    if f["fixed"] and (f.get("epss") or 0) >= EPSS_HOT:
        return 2
    if f["fixed"] and f["severity"] == "CRITICAL":
        return 3
    return 4 if f["fixed"] else 5


def rank(findings):
    for f in findings:
        f["tier"] = tier(f)
    return sorted(findings, key=lambda f: (f["tier"], -(f.get("epss") or 0), -SEV_RANK.get(f["severity"], 0),
                                           f["id"], f["package"], f["target"]))


def apply_filters(findings, min_severity=None, kev_only=False, fixable_only=False):
    floor = SEV_RANK[min_severity.upper()] if min_severity else 0
    out = []
    for f in findings:
        if kev_only and not f["kev"]:
            continue
        if fixable_only and not f["fixed"]:
            continue
        # a known-exploited finding is never hidden by its severity label
        if SEV_RANK.get(f["severity"], 0) < floor and not f["kev"]:
            continue
        out.append(f)
    return out


def summary(findings):
    return {"findings": len(findings),
            "kev": sum(1 for f in findings if f["kev"]),
            "fixable": sum(1 for f in findings if f["fixed"]),
            "epss_hot_fixable": sum(1 for f in findings if f["fixed"] and (f.get("epss") or 0) >= EPSS_HOT),
            "critical_fixable": sum(1 for f in findings if f["fixed"] and f["severity"] == "CRITICAL")}
