"""SARIF 2.1.0 output, for GitHub code scanning (and anything else that reads SARIF).

One rule per advisory id, one result per (advisory, package, target). A package finding has no source line, so
each result points at a stable pseudo-path `<target>/<package>` (GitHub needs a physical location to show an
alert) and carries the same pair as a logical location. The level follows sieve's ranking: known-exploited, a
fixable finding with EPSS >= 10%, CRITICAL and HIGH are `error`, MEDIUM is `warning`, the rest `note`. A KEV
finding is scored at least 9.0 in `security-severity`, so GitHub files it as critical whatever its label says.
`partialFingerprints` hash target + package + advisory (not the version), so an alert stays the same alert when
the package is upgraded but still affected, and closes when the finding goes away.
"""
import hashlib
from urllib.parse import quote

from . import __version__
from .rank import EPSS_HOT

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/casareanderson/sieve"
SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 3.0, "UNKNOWN": 0.0}
KEV_FLOOR = 9.0


def level(f):
    if f["kev"] or (f["fixed"] and (f.get("epss") or 0) >= EPSS_HOT) or f["severity"] in ("CRITICAL", "HIGH"):
        return "error"
    return "warning" if f["severity"] == "MEDIUM" else "note"


def score(f):
    s = SCORE.get(f["severity"], 0.0)
    return max(s, KEV_FLOOR) if f["kev"] else s


def _uri(f):
    return quote(f"{f['target'] or 'host'}/{f['package']}", safe="/:@")


def _message(f):
    fix = f"fixed in {f['fixed']}" if f["fixed"] else ("no fix released yet" if f["status"] in ("affected", "fixed")
                                                      else f["status"])
    extra = []
    if f["kev"]:
        extra.append("actively exploited (CISA KEV)")
    if f.get("epss") is not None:
        extra.append(f"EPSS {f['epss'] * 100:.1f}%")
    tail = f" ({', '.join(extra)})" if extra else ""
    return f"{f['package']} {f['installed']} in {f['target'] or 'host'} is affected by {f['id']}; {fix}.{tail}"


def _rule(f):
    url = f["url"] or f"https://osv.dev/vulnerability/{f['id']}"
    short = f["summary"] or f"{f['id']} in {f['package']}"
    full = (f["details"] or short)[:1000]
    tags = ["security", "vulnerability"] + (["kev"] if f["kev"] else [])
    return {"id": f["id"], "name": f["id"].replace("-", ""),
            "shortDescription": {"text": short},
            "fullDescription": {"text": full},
            "helpUri": url,
            "help": {"text": f"{short}\n\n{url}", "markdown": f"**{f['id']}**: {short}\n\n[Advisory]({url})"},
            "defaultConfiguration": {"level": level(f)},
            "properties": {"tags": tags, "precision": "very-high", "security-severity": f"{score(f):.1f}"}}


def build(targets, findings, errors, version=__version__):
    """targets: list of dicts (Target.as_dict()); findings: ranked finding dicts; errors: strings."""
    rules, index = [], {}
    results = []
    for f in findings:
        if f["id"] not in index:
            index[f["id"]] = len(rules)
            rules.append(_rule(f))
        else:                                    # the same advisory can be KEV/critical on one package only
            r = rules[index[f["id"]]]
            if float(r["properties"]["security-severity"]) < score(f):
                r["properties"]["security-severity"] = f"{score(f):.1f}"
                r["defaultConfiguration"]["level"] = level(f)
            if f["kev"] and "kev" not in r["properties"]["tags"]:
                r["properties"]["tags"].append("kev")
        key = f"{f['target']}|{f['package']}|{f['id']}"
        results.append({
            "ruleId": f["id"], "ruleIndex": index[f["id"]], "level": level(f),
            "message": {"text": _message(f)},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": _uri(f)}, "region": {"startLine": 1}},
                "logicalLocations": [{"name": f["package"], "fullyQualifiedName": f"{f['target']}/{f['package']}",
                                      "kind": "package"}]}],
            "partialFingerprints": {"sieveFinding/v1": hashlib.sha256(key.encode()).hexdigest()},
            "properties": {"package": f["package"], "installed": f["installed"], "fixed": f["fixed"],
                           "target": f["target"], "kev": f["kev"], "epss": f.get("epss"), "tier": f.get("tier"),
                           "status": f["status"]}})
    notes = [{"level": "error", "message": {"text": e}} for e in errors]
    notes += [{"level": "warning", "message": {"text": f"{t['name']}: {t['status']}: {'; '.join(t['notes'])}"}}
              for t in targets if t.get("status") != "ok"]
    ok = not errors and not any(t.get("status") == "error" for t in targets)
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "sieve", "version": version, "semanticVersion": version,
                            "informationUri": INFO_URI, "rules": rules}},
        "invocations": [{"executionSuccessful": ok, "toolExecutionNotifications": notes}],
        "results": results,
        "properties": {"targets": [{k: t.get(k) for k in ("name", "kind", "os", "packages", "status")}
                                   for t in targets]}}]}


def from_report(report):
    """The `--json` report → SARIF, so a JSON scan can be converted without scanning again."""
    return build(report.get("targets", []), report.get("findings", []), report.get("errors", []),
                 version=report.get("sieve", __version__))
