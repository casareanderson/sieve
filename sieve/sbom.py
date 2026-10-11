"""SBOMs both ways, standard library only. Imported only by `--sbom` and `sieve sbom FILE`, so a plain scan never
loads it.

  export   CycloneDX 1.6 (default) or SPDX 2.3 JSON from the package lists a scan reads. One component per scanned
           target (the host, each container image, each project directory) with its packages inside it. Nothing is
           asked of OSV unless --with-vulns, which adds the findings as CycloneDX `vulnerabilities`.
  import   a CycloneDX (1.4-1.6) or SPDX (2.2/2.3) JSON SBOM made by another tool (syft, trivy, cdxgen, GitHub's
           dependency graph) → package URLs → the same OSV / KEV / EPSS pipeline as any other scan.

OS packages carry their distro in a `distro=` qualifier (`debian-12`, `alpine-3.20`, `rocky-9.3`) and their source
package in `upstream=`, the way syft writes them. On the way back in, the distro goes through osv.ecosystem(), the
same mapping a host scan uses, so there is one table for OS ecosystems, not two.
"""
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote, unquote

from . import __version__, osv
from .sources import Target

LANG = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo"}         # OSV ecosystem → purl type
LANG_IN = {**{v: k for k, v in LANG.items()}, "maven": "Maven", "nuget": "NuGet", "gem": "RubyGems",
           "composer": "Packagist", "hex": "Hex", "pub": "Pub", "hackage": "Hackage", "swift": "SwiftURL"}
NAMESPACE = {"rhel": "redhat", "opensuse-leap": "opensuse", "opensuse-tumbleweed": "opensuse"}  # os-release ID → purl
CDX_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
SAFE = ".-_~+"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── package URLs ─────────────────────────────────────────────────────────────
def purl(typ, ns, name, version, qual=None):
    path = "/".join(quote(x, safe=SAFE) for x in [*ns, name])
    q = "&".join(f"{k}={quote(v, safe=SAFE)}" for k, v in sorted((qual or {}).items()) if v)
    return f"pkg:{typ}/{path}" + (f"@{quote(version, safe=SAFE)}" if version else "") + (f"?{q}" if q else "")


def parse_purl(p):
    """→ (type, [namespace...], name, version, {qualifiers}) or None."""
    base = (p or "").split("#", 1)[0]
    base, _, qs = base.partition("?")
    if not base.startswith("pkg:") or "/" not in base:
        return None
    path, at, ver = base.rpartition("@")
    if not at or "/" in ver:                         # no version (a raw "@scope/name" is a namespace, not a version)
        path, ver = base, ""
    typ, _, rest = path[4:].lstrip("/").partition("/")
    segs = [unquote(s) for s in rest.split("/") if s]
    if not segs:
        return None
    qual = {k: unquote(v) for k, _, v in (x.partition("=") for x in qs.split("&") if x)}
    return typ.lower(), segs[:-1], segs[-1], unquote(ver), qual


def _os_id(label):
    """A target's OS label ("debian 12", "pop 22.04 (scanned as ubuntu 22.04)") → (os-release ID, version)."""
    m = re.search(r"scanned as (\S+) ([^)\s]+)", label) or re.match(r"(\S+)\s*(\S*)", label or "")
    return (m.group(1), m.group(2)) if m else ("", "")


def _os_components(t):
    eco, label, kind, entries = t.osinv
    ident, ver = _os_id(label)
    distro = f"{ident}-{ver}" if ver and ver != "?" else ident
    out = []
    for src, sver, b, bver in entries:
        q = {"distro": distro}
        version = bver
        if kind == "rpm":
            m = re.match(r"(?:(\d+):)?(.*)", bver)
            q["epoch"], version = m.group(1) or "", m.group(2)
            if src != b or sver != bver:
                q["upstream"] = f"{src}-{re.sub(r'^[0-9]+:', '', sver)}.src.rpm"
        elif src != b or sver != bver:
            q["upstream"] = src if sver == bver else f"{src}@{sver}"
        out.append((purl(kind, [NAMESPACE.get(ident, ident)], b, version, q), b, bver, eco or ""))
    return out


def _lang(eco, name):
    """(OSV ecosystem, package name) → (purl type, namespace segments, name)."""
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope, _, n = name.partition("/")
        return "npm", [scope], n
    if eco == "Go" and "/" in name:
        *ns, n = name.split("/")
        return "golang", ns, n
    if eco == "PyPI":
        return "pypi", [], re.sub(r"[-_.]+", "-", name).lower()
    return LANG[eco], [], name


def components(t):
    """A scanned Target → [(purl, name, version, OSV ecosystem)], deduplicated."""
    out = _os_components(t) if t.osinv else []
    for e, _, _, b, bv in sorted({p for p in t.pkgs if p[0] in LANG}):
        typ, ns, n = _lang(e, b)
        out.append((purl(typ, ns, n, bv), b, bv, e))
    seen = set()
    return [c for c in out if not (c[0] in seen or seen.add(c[0]))]


# ── export ───────────────────────────────────────────────────────────────────
def _kind(t):
    return {"container": ("container", "CONTAINER"), "host": ("operating-system", "OPERATING_SYSTEM")}.get(
        t.kind, ("application", "SOURCE"))


def cyclonedx(targets, findings=None):
    comps, refs = [], {}
    for i, t in enumerate(targets):
        inner = []
        for p, n, v, e in components(t):
            ref = f"{i}:{p}"
            refs[(t.name, n, v)] = ref
            inner.append({"type": "library", "bom-ref": ref, "name": n, "version": v, "purl": p,
                          "properties": [{"name": "sieve:ecosystem", "value": e}] if e else []})
        comps.append({"type": _kind(t)[0], "bom-ref": f"target:{i}", "name": t.name,
                      "description": t.os, "components": inner})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": {"timestamp": now(), "tools": {"components": [{
               "type": "application", "name": "sieve", "version": __version__,
               "externalReferences": [{"type": "website", "url": "https://github.com/casareanderson/sieve"}]}]}},
           "components": comps}
    if findings is not None:
        doc["vulnerabilities"] = [_vuln(n, f, refs.get((f["target"], f["package"], f["installed"])))
                                  for n, f in enumerate(findings)]
    return doc


def _vuln(n, f, ref):
    props = [("sieve:kev", f["kev"]), ("sieve:malicious", f.get("malicious")), ("sieve:epss", f.get("epss")),
             ("sieve:in_use", f.get("in_use")), ("sieve:fixed", f.get("fixed"))]
    v = {"bom-ref": f"vuln:{n}", "id": f["id"], "source": {"name": "OSV", "url": f["url"] or
         f"https://osv.dev/vulnerability/{f['id']}"},
         "ratings": [{"source": {"name": "OSV"}, "severity": CDX_SEV.get(f["severity"], "unknown")}],
         "description": f.get("summary") or "",
         "recommendation": f"upgrade to {f['fixed']}" if f.get("fixed") else f.get("status") or "",
         "properties": [{"name": k, "value": str(x).lower() if isinstance(x, bool) else str(x)}
                        for k, x in props if x not in (None, "", False)]}
    if ref:
        v["affects"] = [{"ref": ref}]
    return v


def spdx(targets):
    pkgs, rels = [], []
    for i, t in enumerate(targets):
        tid = f"SPDXRef-Target-{i}"
        pkgs.append({"SPDXID": tid, "name": t.name, "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                     "primaryPackagePurpose": _kind(t)[1], "comment": t.os})
        rels.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": tid})
        for j, (p, n, v, _) in enumerate(components(t)):
            pid = f"SPDXRef-Package-{i}-{j}"
            pkgs.append({"SPDXID": pid, "name": n, "versionInfo": v, "downloadLocation": "NOASSERTION",
                         "filesAnalyzed": False, "primaryPackagePurpose": "LIBRARY",
                         "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                           "referenceLocator": p}]})
            rels.append({"spdxElementId": tid, "relationshipType": "CONTAINS", "relatedSpdxElement": pid})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "sieve: " + ", ".join(t.name for t in targets)[:200],
            "documentNamespace": f"https://github.com/casareanderson/sieve/spdx/{uuid.uuid4()}",
            "creationInfo": {"created": now(), "creators": [f"Tool: sieve-{__version__}"]},
            "packages": pkgs, "relationships": rels}


def build(fmt, targets, findings=None):
    return spdx(targets) if fmt == "spdx" else cyclonedx(targets, findings)


# ── import ───────────────────────────────────────────────────────────────────
def to_pkgs(pu):
    """A parsed purl → (match() input tuples, OS label or "") or (None, why it can't be matched)."""
    typ, ns, name, ver, q = pu
    if not ver:
        return None, "no version"
    if typ in ("deb", "apk", "rpm"):
        m = re.match(r"(.+?)-(\d[\w.]*)$", q.get("distro", ""))
        ident, v = (m.group(1), m.group(2)) if m else (q.get("distro") or (ns[0] if ns else ""), "")
        ident = {"redhat": "rhel"}.get(ident, ident)
        eco, label = osv.ecosystem({"ID": ident, "VERSION_ID": v}, v if ident == "alpine" else "")
        if not eco:
            return None, f"{typ}: no OSV feed for distro {q.get('distro') or '(none given)'}"
        if typ == "rpm":
            vr, _, rel = ver.rpartition("-")
            line = "\t".join([name, q.get("epoch", ""), vr or ver, rel if vr else "", q.get("arch", ""),
                              q.get("upstream", "")])
            entries = osv.parse_rpm(line)
        else:
            src, _, sver = q.get("upstream", name).partition("@")
            entries = [(src or name, sver or ver, name, ver)]
        return osv.os_packages(eco, entries), label
    eco = LANG_IN.get(typ)
    if not eco:
        return None, f"purl type {typ!r} not in OSV"
    if typ == "npm" and ns:
        name = f"{ns[0]}/{name}"
    elif typ == "golang" and ns:
        name = "/".join([*ns, name])
    elif typ == "maven" and ns:
        name = f"{ns[0]}:{name}"
    elif typ == "composer" and ns:
        name = f"{ns[0]}/{name}"
    return [(eco, name, ver, name, ver)], ""


def _purls(doc):
    """→ ([purl strings], number of packages without one). Grouping components (an image, an OS) aren't packages."""
    found, missing = [], 0
    if doc.get("bomFormat") == "CycloneDX":
        stack = list(doc.get("components") or [])
        while stack:
            c = stack.pop()
            stack += c.get("components") or []
            if c.get("purl"):
                found.append(c["purl"])
            elif c.get("type", "library") in ("library", "framework"):
                missing += 1
    else:
        for p in doc.get("packages") or []:
            refs = [r.get("referenceLocator") for r in p.get("externalRefs") or []
                    if r.get("referenceType") == "purl"]
            if refs:
                found.append(refs[0])
            elif p.get("primaryPackagePurpose", "LIBRARY") in ("LIBRARY", "FRAMEWORK"):
                missing += 1
    return found, missing


def read_file(path):
    """An SBOM file → Target (match() input in t.pkgs). Anything that can't be mapped is counted in the notes."""
    t = Target(f"sbom:{os.path.basename(path)}", "sbom")
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        t.status = "error"
        t.notes.append(f"{path}: not read ({type(e).__name__}: {str(e)[:120]})")
        return t
    if not isinstance(doc, dict) or not (doc.get("bomFormat") == "CycloneDX"
                                         or str(doc.get("spdxVersion", "")).startswith("SPDX-")):
        t.status = "error"
        t.notes.append(f"{path}: not a CycloneDX or SPDX JSON document")
        return t
    found, missing = _purls(doc)
    pkgs, labels, skipped = set(), Counter(), Counter()
    found = list(dict.fromkeys(found))
    for p in found:
        pu = parse_purl(p)
        got, why = to_pkgs(pu) if pu else (None, "unreadable purl")
        if got is None:
            skipped[why] += 1
            continue
        pkgs.update(got)
        if why:
            labels[why] += 1
    if missing:
        skipped["no purl"] += missing
    t.pkgs = sorted(pkgs)
    t.packages = len(found) - sum(n for k, n in skipped.items() if k != "no purl")
    t.os = labels.most_common(1)[0][0] if labels else "sbom"
    if skipped:
        t.status = "partial"
        t.notes.append(f"{sum(skipped.values())} components not checked: "
                       + ", ".join(f"{n} {k}" for k, n in skipped.most_common()))
    return t
