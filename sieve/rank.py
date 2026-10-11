"""Ranking and filtering.

Most of what a scanner reports is "affected, no fix released yet" (one box: 4,592 CVEs, 0 fixable). The order puts
what you can and should act on first:

  0. a known-malicious package is installed (OpenSSF MAL-*, or an advisory filed as embedded malicious code):
     not a bug to patch but code someone planted; remove it and rotate any secrets the machine had
  1. known exploited (CISA KEV), fix or not
  2. EPSS >= 10% (a 1-in-10 chance of exploitation in the next 30 days) with a fix available
  3. CRITICAL with a fix available
  4. everything else with a fix
  5. no fix yet

Within a tier: code that is loaded in a running process first (then unknown, then not loaded), then higher EPSS,
then higher severity. In-use never moves a finding into another tier: an unloaded KEV still outranks everything.
"""
from .inuse import LOADED, ORDER
from .osv import SEV_RANK

EPSS_HOT = 0.1


def tier(f):
    if f.get("malicious"):
        return 0
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
    return sorted(findings, key=lambda f: (f["tier"], ORDER.get(f.get("in_use"), 1), -(f.get("epss") or 0),
                                           -SEV_RANK.get(f["severity"], 0),
                                           f["id"], f["package"], f["target"]))


def apply_filters(findings, min_severity=None, kev_only=False, fixable_only=False, in_use_only=False):
    floor = SEV_RANK[min_severity.upper()] if min_severity else 0
    out = []
    for f in findings:
        if f.get("malicious"):                       # never filtered away: malware has no fix and no "low" severity
            out.append(f)
            continue
        if kev_only and not f["kev"]:
            continue
        if fixable_only and not f["fixed"]:
            continue
        if in_use_only and f.get("in_use") != LOADED:
            continue
        # a known-exploited finding is never hidden by its severity label
        if SEV_RANK.get(f["severity"], 0) < floor and not f["kev"]:
            continue
        out.append(f)
    return out


def summary(findings):
    return {"findings": len(findings),
            "malicious": sum(1 for f in findings if f.get("malicious")),
            "kev": sum(1 for f in findings if f["kev"]),
            "fixable": sum(1 for f in findings if f["fixed"]),
            "epss_hot_fixable": sum(1 for f in findings if f["fixed"] and (f.get("epss") or 0) >= EPSS_HOT),
            "critical_fixable": sum(1 for f in findings if f["fixed"] and f["severity"] == "CRITICAL"),
            "in_use": sum(1 for f in findings if f.get("in_use") == LOADED),
            "restart_needed": sum(1 for f in findings if f.get("restart_needed"))}
