#!/usr/bin/env python3
"""Weekly benchmark: sieve against trivy, grype and osv-scanner on the same deliberately old public images.

Runs on GitHub Actions (.github/workflows/bench.yml); it needs Docker, root for `sieve containers`, and the three
other scanners on PATH. For each image in bench/images.txt it pulls the pinned digest, saves it to a tar that
trivy, grype and osv-scanner all scan (so every tool sees the same bytes and only one registry pull happens),
and starts a container from it for sieve, which reads running containers. Then it normalises every tool's output
to (image, CVE, package), compares the sets per image, checks which tools caught each CISA KEV CVE, and writes
bench/results.json and bench/RESULTS.md.

  python3 bench/run.py --sieve "sudo /path/to/sieve" --raw-dir /tmp/raw
  python3 bench/run.py --render-only bench/results.json        # re-render RESULTS.md from saved results

Standard library plus requests (already a sieve dependency).
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = ("sieve", "trivy", "grype", "osv-scanner")
OTHERS = TOOLS[1:]
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_QUERY = "https://api.osv.dev/v1/query"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# distro wrappers that carry exactly one CVE in their id (same list sieve's own matcher uses)
WRAPPED_CVE = re.compile(r"^(?:DEBIAN|UBUNTU|ALPINE|DLA|BIT-[A-Za-z0-9]+)-(CVE-\d{4}-\d{4,})$")
NOTICE = ("DSA-", "DLA-", "USN-", "DTSA-")    # notices that bundle several CVEs
KERNEL_PKG = re.compile(r"^linux-(libc-dev|headers|image|modules|tools|kbuild|source)")
SEV_RANK = {"UNKNOWN": 0, "NEGLIGIBLE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# what sieve reads: dpkg/apk databases, Python and npm metadata, Go build info, cargo-auditable Rust
SIEVE_READS = {"os", "python", "npm", "go", "rust"}

TRIVY_TYPES = {"python-pkg": "python", "pip": "python", "pipenv": "python", "poetry": "python", "uv": "python",
               "conda-pkg": "python", "node-pkg": "npm", "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm",
               "gobinary": "go", "gomod": "go", "rustbinary": "rust", "cargo": "rust", "jar": "java", "pom": "java",
               "gradle": "java", "sbt": "java", "gemspec": "ruby", "bundler": "ruby", "composer": "php",
               "composer-vendor": "php", "dotnet-core": "dotnet", "nuget": "dotnet", "packages-props": "dotnet",
               "conan": "c", "swift": "swift", "cocoapods": "swift", "pub": "dart", "hex": "elixir",
               "bitnami": "binary", "k8s": "binary", "wordpress": "php", "julia": "julia"}
GRYPE_TYPES = {"deb": "os", "apk": "os", "rpm": "os", "alpm": "os", "python": "python", "npm": "npm",
               "go-module": "go", "rust-crate": "rust", "java-archive": "java", "jenkins-plugin": "java",
               "gem": "ruby", "php-composer": "php", "dotnet": "dotnet", "binary": "binary",
               "linux-kernel": "os", "linux-kernel-module": "os"}
OSV_ECOS = {"pypi": "python", "npm": "npm", "go": "go", "crates.io": "rust", "maven": "java", "rubygems": "ruby",
            "packagist": "php", "nuget": "dotnet"}


# ── ids and severities ───────────────────────────────────────────────────────
def canon_ids(vid, aliases=(), upstream=(), related=()):
    """One advisory id (+ what the tool says it aliases) → the CVE ids it stands for.

    A CVE stays itself; DEBIAN-CVE-x / UBUNTU-CVE-x / ALPINE-CVE-x unwrap to CVE-x; a GHSA/PYSEC/GO id maps to the
    CVE(s) in its aliases (else upstream); a DSA/DLA/USN notice expands to every CVE it bundles. An id with no CVE
    anywhere (e.g. a GHSA that never got one) is kept as is, so it can still match the same id in another tool."""
    vid = (vid or "").strip()
    if CVE_RE.match(vid):
        return [vid]
    m = WRAPPED_CVE.match(vid)
    if m:
        return [m.group(1)]

    def cves(xs):
        out = []
        for x in xs or ():
            x = (x or "").strip()
            m2 = WRAPPED_CVE.match(x)
            x = m2.group(1) if m2 else x
            if CVE_RE.match(x) and x not in out:
                out.append(x)
        return out
    if vid.startswith(NOTICE):
        found = cves(list(aliases or ()) + list(upstream or ()))
        found = found or cves(related)
    else:
        found = cves(aliases) or cves(upstream)
    return sorted(found) or ([vid] if vid else [])


def sev_from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0:
        return "CRITICAL"
    if s >= 7.0:
        return "HIGH"
    if s >= 4.0:
        return "MEDIUM"
    if s > 0:
        return "LOW"
    return "UNKNOWN"


def norm_sev(s):
    s = str(s or "").strip().upper()
    if s == "MODERATE":
        s = "MEDIUM"
    return s if s in SEV_RANK else "UNKNOWN"


def worse(a, b):
    return a if SEV_RANK.get(a, 0) >= SEV_RANK.get(b, 0) else b


def _rec(cve, package, version, severity, ptype, tool_id, src_name="", src_version="", eco=""):
    return {"id": cve, "package": package or "?", "version": version or "", "severity": norm_sev(severity),
            "type": ptype or "other", "tool_id": tool_id, "src_name": src_name or package or "",
            "src_version": src_version or version or "", "eco": eco or ""}


# ── parsers: one tool's JSON → [record] for one image ────────────────────────
def _trivy_ver(epoch, ver, rel):
    if not ver:
        return ""
    s = f"{ver}-{rel}" if rel else str(ver)
    return f"{epoch}:{s}" if epoch else s


def parse_trivy(doc):
    """`trivy image --format json --list-all-pkgs` → records. Packages (with --list-all-pkgs) give source names."""
    out = []
    for r in (doc or {}).get("Results") or []:
        cls, typ = r.get("Class") or "", r.get("Type") or ""
        ptype = "os" if cls == "os-pkgs" else TRIVY_TYPES.get(typ, typ or "other")
        src = {}
        for p in r.get("Packages") or []:
            src[p.get("ID") or f"{p.get('Name')}@{p.get('Version')}"] = (
                p.get("SrcName") or p.get("Name") or "",
                _trivy_ver(p.get("SrcEpoch"), p.get("SrcVersion"), p.get("SrcRelease")))
        for v in r.get("Vulnerabilities") or []:
            name, ver = v.get("PkgName") or "", v.get("InstalledVersion") or ""
            sn, sv = src.get(v.get("PkgID") or f"{name}@{ver}", (name, ver))
            for cve in canon_ids(v.get("VulnerabilityID"), v.get("VendorIDs") or ()):
                out.append(_rec(cve, name, ver, v.get("Severity"), ptype, v.get("VulnerabilityID"),
                                sn if ptype == "os" else name, (sv or ver) if ptype == "os" else ver))
    return out


def parse_grype(doc):
    """`grype <src> -o json` → records. relatedVulnerabilities supply the CVE behind a GHSA."""
    out = []
    for m in (doc or {}).get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        related = [r.get("id") for r in m.get("relatedVulnerabilities") or [] if r.get("id")]
        ptype = GRYPE_TYPES.get(a.get("type") or "", a.get("type") or "other")
        ups = a.get("upstreams") or []
        sn = (ups[0].get("name") if ups else "") or a.get("name") or ""
        sv = (ups[0].get("version") if ups else "") or a.get("version") or ""
        sev = v.get("severity")
        if norm_sev(sev) == "UNKNOWN":
            for r in m.get("relatedVulnerabilities") or []:
                sev = worse(norm_sev(sev), norm_sev(r.get("severity")))
        for cve in canon_ids(v.get("id"), related):
            out.append(_rec(cve, a.get("name"), a.get("version"), sev, ptype, v.get("id"),
                            sn if ptype == "os" else a.get("name"), sv if ptype == "os" else a.get("version")))
    return out


def _osv_rec_sev(v, group_sev):
    sev = norm_sev((v.get("database_specific") or {}).get("severity"))
    for a in v.get("affected") or []:
        sev = worse(sev, norm_sev((a.get("ecosystem_specific") or {}).get("severity")))
    return worse(sev, group_sev)


def parse_osv_scanner(doc):
    """`osv-scanner scan image --format json` → records (results[].packages[].vulnerabilities[], OSV schema)."""
    out = []
    for res in (doc or {}).get("results") or []:
        for p in res.get("packages") or []:
            pk = p.get("package") or {}
            eco = pk.get("ecosystem") or ""
            base = eco.split(":", 1)[0].lower()
            ptype = "os" if base in ("debian", "ubuntu", "alpine") else OSV_ECOS.get(base, base or "other")
            src_name = pk.get("name") or ""
            shown = pk.get("os_package_name") or src_name
            gsev = {}
            for g in p.get("groups") or []:
                s = sev_from_cvss(g.get("max_severity"))
                for i in g.get("ids") or []:
                    gsev[i] = s
            for v in p.get("vulnerabilities") or []:
                sev = _osv_rec_sev(v, gsev.get(v.get("id"), "UNKNOWN"))
                for cve in canon_ids(v.get("id"), v.get("aliases"), v.get("upstream"), v.get("related")):
                    out.append(_rec(cve, shown, pk.get("version"), sev, ptype, v.get("id"), src_name,
                                    pk.get("version"), eco))
    return out


def parse_sieve(doc, image_of):
    """`sieve containers --json` → ({image: [record]}, {image: target dict}). image_of maps the container image
    name sieve reports (as `docker ps` shows it) to the bench image reference; other targets are ignored."""
    recs, targets = {}, {}
    for t in (doc or {}).get("targets") or []:
        img = image_of.get(t.get("name"))
        if img:
            targets[img] = t
            recs.setdefault(img, [])
    for f in (doc or {}).get("findings") or []:
        img = image_of.get(f.get("target"))
        if not img:
            continue
        for cve in canon_ids(f.get("id")):
            recs.setdefault(img, []).append(_rec(cve, f.get("package"), f.get("installed"), f.get("severity"),
                                                 "", f.get("id")))
    return recs, targets


def osv_ecosystem(os_label):
    """sieve's target os label ('debian 10', 'ubuntu 22.04', 'alpine 3.18.0') → OSV ecosystem, or ''."""
    parts = (os_label or "").split()
    if len(parts) < 2:
        return ""
    ident, ver = parts[0].lower(), parts[1]
    if ident == "debian" and ver.split(".")[0].isdigit():
        return f"Debian:{ver.split('.')[0]}"
    if ident == "ubuntu":
        major = ver.split(".")[0]
        lts = major.isdigit() and int(major) % 2 == 0 and ver.endswith(".04")
        return f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"
    if ident == "alpine":
        return "Alpine:v" + ".".join(ver.split(".")[:2])
    return ""


# ── comparison ───────────────────────────────────────────────────────────────
def by_cve(records):
    """[record] → {cve: {packages, severity, types, srcs}} (one image, one tool)."""
    out = {}
    for r in records:
        e = out.setdefault(r["id"], {"packages": set(), "severity": "UNKNOWN", "types": set(), "srcs": set()})
        e["packages"].add(r["package"])
        e["severity"] = worse(r["severity"], e["severity"])
        e["types"].add(r["type"])
        if r["src_name"]:
            e["srcs"].add((r["type"], r["src_name"], r["src_version"], r["eco"]))
    return out


def classify_miss(cve, infos, target, sieve_pkgs, osv_check=None, eco=""):
    """Why sieve did not report a CVE that another tool did. Returns (reason, osv_listed) where reason is only a
    category the data supports, otherwise 'unknown'. infos: the other tools' by_cve entries for this CVE."""
    pkgs = set().union(*(i["packages"] for i in infos)) if infos else set()
    types = set().union(*(i["types"] for i in infos)) if infos else set()
    if not target:
        return "sieve did not scan this image", None
    if pkgs and all(KERNEL_PKG.match(p) for p in pkgs):
        return "kernel package: sieve skips kernel packages by default (--kernel)", None
    unread = {t for t in types if t not in SIEVE_READS}
    if types and unread == types:
        return f"package type sieve does not read ({', '.join(sorted(unread))})", None
    listed = None
    if osv_check:
        srcs = set().union(*(i["srcs"] for i in infos))
        queries = set()
        for typ, name, ver, e in srcs:
            if typ == "os":
                e = e or eco
            elif typ == "python":
                e = "PyPI"
            elif typ == "npm":
                e = "npm"
            elif typ == "go":
                e = "Go"
            elif typ == "rust":
                e = "crates.io"
            else:
                continue
            if e and name and ver:
                queries.add((e, name, ver))
        asked = []
        for q in sorted(queries):
            r = osv_check(cve, *q)
            if r is True:
                listed = True
                break
            if r is False:
                listed = False
                asked.append(f"{q[1]} {q[2]} in {q[0]}")
    if target.get("status") not in (None, "ok"):
        return f"possibly: sieve's scan of this image was {target.get('status')}", listed
    if listed is True:
        return "unknown: OSV lists this CVE for the installed version, sieve did not report it", listed
    if listed is False:
        return (f"OSV does not list this CVE for {'; '.join(asked[:3])} (OSV coverage, import lag or distro "
                "triage)"), listed
    return "unknown", listed


def compare_image(per_tool, status, kev, target=None, osv_check=None):
    """per_tool: {tool: [record]} for one image; status: {tool: 'ok'|'error'|...}. → comparison dict."""
    sets = {t: by_cve(per_tool.get(t) or []) for t in TOOLS}
    ok = {t for t in TOOLS if status.get(t) == "ok"}
    s = set(sets["sieve"])
    counts = {t: (len(sets[t]) if t in ok else None) for t in TOOLS}
    pairs = {}
    for t in OTHERS:
        if t in ok and "sieve" in ok:
            o = set(sets[t])
            pairs[t] = {"overlap": len(s & o), "sieve_only": len(s - o), "tool_only": len(o - s)}
    others = set().union(*(set(sets[t]) for t in OTHERS if t in ok)) if any(t in ok for t in OTHERS) else set()
    kev_rows = []
    for cve in sorted(set().union(*(set(sets[t]) for t in ok)) & kev if ok else []):
        kev_rows.append({"id": cve, "caught_by": [t for t in TOOLS if t in ok and cve in sets[t]],
                         "packages": sorted(set().union(*(sets[t][cve]["packages"] for t in ok if cve in sets[t])))})
    sieve_pkgs = set().union(*(e["packages"] for e in sets["sieve"].values())) if sets["sieve"] else set()
    eco = osv_ecosystem((target or {}).get("os"))
    misses = []
    if "sieve" in ok:
        for cve in sorted(others - s):
            infos = [sets[t][cve] for t in OTHERS if t in ok and cve in sets[t]]
            sev = "UNKNOWN"
            for i in infos:
                sev = worse(i["severity"], sev)
            if cve not in kev and sev != "CRITICAL":
                continue
            pkgs = sorted(set().union(*(i["packages"] for i in infos)))
            reason, listed = classify_miss(cve, infos, target, sieve_pkgs, osv_check, eco)
            misses.append({"id": cve, "kev": cve in kev, "severity": sev, "packages": pkgs,
                           "found_by": [t for t in OTHERS if t in ok and cve in sets[t]],
                           "sieve_saw_package": bool(set(pkgs) & sieve_pkgs), "osv_listed": listed,
                           "reason": reason})
    return {"counts": counts, "vs_sieve": pairs, "missed_by_sieve": len(others - s) if "sieve" in ok else None,
            "sieve_only_all": len(s - others) if "sieve" in ok and others else None,
            "kev": kev_rows, "misses": misses}


def make_osv_check(session, budget=300):
    """→ osv_check(cve, ecosystem, name, version): True/False whether OSV lists the CVE for that package version,
    None when OSV could not be asked. At most `budget` queries per run."""
    cache, left = {}, [budget]

    def check(cve, eco, name, version):
        key = (eco, name, version)
        if key not in cache:
            if left[0] <= 0:
                return None
            left[0] -= 1
            ids, token, failed = set(), None, False
            for _ in range(20):
                body = {"package": {"ecosystem": eco, "name": name}, "version": version}
                if token:
                    body["page_token"] = token
                try:
                    r = session.post(OSV_QUERY, json=body, timeout=60)
                    r.raise_for_status()
                    d = r.json()
                except Exception:  # noqa: BLE001 — a failed lookup is reported as "unknown", never as a reason
                    failed = True
                    break
                for v in d.get("vulns") or []:
                    if not v.get("withdrawn"):
                        ids.update(canon_ids(v.get("id"), v.get("aliases"), v.get("upstream"), v.get("related")))
                token = d.get("next_page_token")
                if not token:
                    break
            cache[key] = None if failed else ids
        ids = cache[key]
        return None if ids is None else cve in ids
    return check


def totals(images, kev):
    t = {"found": {x: 0 for x in TOOLS}, "kev_any": 0, "kev_caught": {x: 0 for x in TOOLS}, "missed": 0,
         "missed_kev": 0, "missed_critical": 0, "sieve_only": 0, "images_ok": {x: 0 for x in TOOLS}}
    for im in images:
        c = im["comparison"]
        for x in TOOLS:
            if c["counts"].get(x) is not None:
                t["found"][x] += c["counts"][x]
                t["images_ok"][x] += 1
        t["kev_any"] += len(c["kev"])
        for row in c["kev"]:
            for x in row["caught_by"]:
                t["kev_caught"][x] += 1
        t["missed"] += c["missed_by_sieve"] or 0
        t["sieve_only"] += c["sieve_only_all"] or 0
        t["missed_kev"] += sum(1 for m in c["misses"] if m["kev"])
        t["missed_critical"] += sum(1 for m in c["misses"] if not m["kev"])
    return t


# ── RESULTS.md ───────────────────────────────────────────────────────────────
def _fmt_s(x):
    return "-" if x is None else f"{x:.0f}s" if x >= 10 else f"{x:.1f}s"


def _fmt_mem(kb):
    return "-" if not kb else f"{kb / 1024:.0f} MB"


def _n(x):
    return "error" if x is None else str(x)


def render(res):
    L = []
    imgs, tools, t = res["images"], res["tools"], res["totals"]
    n = len(imgs)
    L += ["# sieve benchmark results", "",
          f"Generated {res['generated']} by [`bench/run.py`](run.py) on {res.get('runner', 'GitHub Actions')}. "
          "This file is overwritten by the weekly [bench workflow](../.github/workflows/bench.yml); "
          "don't edit it by hand. Raw numbers: [`results.json`](results.json).", "",
          "## Summary", ""]
    found = ", ".join(f"{x} {t['found'][x]}" + ("" if t["images_ok"][x] == n else f" ({t['images_ok'][x]}/{n} "
                      "images scanned)") for x in TOOLS)
    L.append(f"- **{n} images**, deliberately old, pinned by digest ([`images.txt`](images.txt)).")
    L.append(f"- **Distinct CVEs per image, summed:** {found}. More is not automatically better: tools differ in "
             "what they count (see *How to read this*).")
    if t["kev_any"]:
        kc = ", ".join(f"{x} {t['kev_caught'][x]}" for x in TOOLS)
        L.append(f"- **CISA KEV:** {t['kev_any']} known-exploited (image, CVE) pairs found by at least one tool. "
                 f"Caught: {kc}.")
    else:
        L.append("- **CISA KEV:** no tool found a known-exploited CVE in these images.")
    L.append(f"- **sieve missed** {t['missed']} (image, CVE) pairs that at least one other tool reported; "
             f"{t['missed_kev']} of them are in KEV and {t['missed_critical']} more are rated CRITICAL by another "
             f"tool (listed under *Where sieve misses*). sieve reported {t['sieve_only']} that no other tool did.")
    if res.get("errors"):
        L.append(f"- **Errors this run:** {len(res['errors'])} (listed at the end); affected cells say `error`.")
    L += ["", "## How to read this", "",
          "- Findings are compared **by CVE id per image**, not by package: tools name packages differently "
          "(binary vs source package), so package-level matching would mostly measure naming. GHSA/PYSEC/Go ids are "
          "mapped to their CVE alias where the tool gives one; DSA/DLA/USN notices are expanded into the CVEs they "
          "bundle; ids with no CVE are compared as they are.",
          "- Defaults differ and are kept as shipped: unfixed vulnerabilities are included by every tool here, but "
          "each tool applies its own distro triage (Debian *unimportant*, Ubuntu *negligible*, \"won't fix\", "
          "vendor not-affected statements). A CVE one tool reports and another doesn't is not automatically a miss; "
          "it can be a disagreement about whether it applies.",
          "- \"Critical\" means at least one tool rated it CRITICAL; severities disagree between tools.",
          "- trivy, grype and osv-scanner scan a `docker save` tar of each image; sieve scans a running container "
          "of the same image, which is how it is meant to be used. sieve's time is one run over all images, from a "
          "cold advisory cache. trivy's and grype's scan times exclude their database download, shown separately.",
          "- The *likely reason* column only states a category the data supports (kernel package, a package type "
          "sieve does not read, or what an OSV.dev query for that package version returned at run time). "
          "Otherwise it says `unknown`.", "",
          "## Tools", "",
          "| tool | version | total scan time | peak memory | notes |", "|---|---|---|---|---|"]
    for x in TOOLS:
        i = tools.get(x) or {}
        L.append(f"| {x} | {i.get('version') or '-'} | {_fmt_s(i.get('seconds'))} | {_fmt_mem(i.get('peak_kb'))} "
                 f"| {i.get('note') or ''} |")
    L += ["", "Peak memory is the largest per-image peak resident set size from `/usr/bin/time -v` (for sieve, the "
          "single run including its container collector).", "", "## Per image", ""]
    for im in imgs:
        c, tgt = im["comparison"], im.get("sieve_target") or {}
        L += [f"### {im['slug']}", "",
              f"`{im['ref']}`" + (f" · sieve: {tgt.get('os')}, {tgt.get('packages')} packages"
                                   + ("" if tgt.get("status") in (None, "ok") else f" [{tgt.get('status')}]")
                                   if tgt else " · sieve: not scanned"), ""]
        if tgt.get("notes"):
            L += [f"sieve notes: {'; '.join(tgt['notes'])}", ""]
        L += ["| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |",
              "|---|---|---|---|---|---|"]
        for x in TOOLS:
            kevn = sum(1 for k in c["kev"] if x in k["caught_by"])
            if x == "sieve":
                L.append(f"| sieve | {_n(c['counts']['sieve'])} | | | | "
                         f"{kevn if c['counts']['sieve'] is not None else '-'}/{len(c['kev'])} |")
            else:
                p = c["vs_sieve"].get(x)
                cnt = c["counts"].get(x)
                if p:
                    L.append(f"| {x} | {cnt} | {p['overlap']} | {p['sieve_only']} | {p['tool_only']} | "
                             f"{kevn}/{len(c['kev'])} |")
                else:
                    L.append(f"| {x} | {_n(cnt)} | - | - | - | {kevn if cnt is not None else '-'}/{len(c['kev'])} |")
        if c["kev"]:
            L += ["", "Known-exploited CVEs found by any tool:", "",
                  "| CVE | package | " + " | ".join(TOOLS) + " |", "|---|---|" + "---|" * len(TOOLS)]
            for k in c["kev"]:
                cells = " | ".join("✔" if x in k["caught_by"] else "✘" for x in TOOLS)
                L.append(f"| {k['id']} | {', '.join(k['packages'][:4])} | {cells} |")
        L.append("")
    L += ["## Where sieve misses", "",
          "KEV and CRITICAL CVEs at least one other tool reported and sieve did not. *sieve saw package* means "
          "sieve reported some other CVE for the same package name in that image. *OSV lists it* is the result of "
          "querying OSV.dev for that package version during the run (`-` = not asked or the query failed).", ""]
    rows = [(im["slug"], m) for im in imgs for m in im["comparison"]["misses"]]
    if not rows:
        L.append("Nothing this run.")
    else:
        L += ["| image | CVE | KEV | severity | package | found by | sieve saw package | OSV lists it | likely reason |",
              "|---|---|---|---|---|---|---|---|---|"]
        rows.sort(key=lambda r: (not r[1]["kev"], r[0], r[1]["id"]))
        yn = {True: "yes", False: "no", None: "-"}
        for slug, m in rows:
            L.append(f"| {slug} | {m['id']} | {'yes' if m['kev'] else ''} | {m['severity']} | "
                     f"{', '.join(m['packages'][:3])}{' …' if len(m['packages']) > 3 else ''} | "
                     f"{', '.join(m['found_by'])} | {yn[m['sieve_saw_package']]} | {yn[m['osv_listed']]} | "
                     f"{m['reason']} |")
    if res.get("errors"):
        L += ["", "## Errors", ""] + [f"- {e}" for e in res["errors"]]
    L += ["", "---", "", f"KEV catalog version {res.get('kev_version') or '?'} ({res.get('kev_count') or '?'} "
          "entries). Reproduce: run the bench workflow, or see the top of `bench/run.py`.", ""]
    return "\n".join(L)


# ── running the tools (GitHub Actions only) ──────────────────────────────────
def read_images(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    return out


def slug_of(ref):
    name = ref.split("@", 1)[0]
    repo, _, tag = name.rpartition(":") if ":" in name.rsplit("/", 1)[-1] else (name, "", "latest")
    return re.sub(r"[^a-z0-9._-]+", "-", f"{repo.rsplit('/', 1)[-1]}-{tag}".lower()).strip("-")


TIME = "/usr/bin/time"


def run_cmd(cmd, stdout_path=None, env=None, timeout=3600):
    """→ (rc, stdout text or '', stderr tail, seconds, peak RSS kB or None)."""
    peak = None
    tf = None
    full = list(cmd)
    if os.path.exists(TIME):
        tf = tempfile.NamedTemporaryFile(delete=False, suffix=".time")
        tf.close()
        full = [TIME, "-v", "-o", tf.name] + full
    t0 = time.monotonic()
    out = open(stdout_path, "wb") if stdout_path else subprocess.PIPE
    try:
        p = subprocess.run(full, stdout=out, stderr=subprocess.PIPE, env=env, timeout=timeout)
        rc, so, se = p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        rc, so, se = -1, b"", (e.stderr or b"") + b"\ntimeout"
    finally:
        if stdout_path:
            out.close()
    secs = time.monotonic() - t0
    if tf:
        try:
            with open(tf.name, encoding="utf-8", errors="replace") as f:
                m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", f.read())
                peak = int(m.group(1)) if m else None
        finally:
            os.unlink(tf.name)
    text = ""
    if stdout_path:
        with open(stdout_path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    elif so:
        text = so.decode("utf-8", "replace")
    return rc, text, (se or b"").decode("utf-8", "replace")[-600:], secs, peak


def first_line(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return ((p.stdout or p.stderr).strip().splitlines() or ["?"])[0].strip()
    except (OSError, subprocess.SubprocessError):
        return "?"


def tool_versions(sieve_cmd):
    v = {"sieve": first_line(sieve_cmd + ["--version"]).replace("sieve ", "")}
    try:
        tv = json.loads(subprocess.run(["trivy", "version", "--format", "json"], capture_output=True, text=True,
                                       timeout=120).stdout or "{}")
        v["trivy"] = tv.get("Version") or "?"
        v["trivy_db"] = ((tv.get("VulnerabilityDB") or {}).get("UpdatedAt") or "")[:10]
    except (OSError, ValueError, subprocess.SubprocessError):
        v["trivy"] = first_line(["trivy", "--version"])
    try:
        gv = json.loads(subprocess.run(["grype", "version", "-o", "json"], capture_output=True, text=True,
                                       timeout=120).stdout or "{}")
        v["grype"] = gv.get("version") or "?"
    except (OSError, ValueError, subprocess.SubprocessError):
        v["grype"] = first_line(["grype", "version"])
    m = re.search(r"(\d+\.\d+\.\d+)", first_line(["osv-scanner", "--version"]))
    v["osv-scanner"] = m.group(1) if m else first_line(["osv-scanner", "--version"])
    return v


def load_json(text):
    try:
        return json.loads(text)
    except ValueError:
        i = text.find("{")                              # some tools print a banner line before the JSON
        return json.loads(text[i:]) if i >= 0 else None


def run_bench(args):
    import requests
    sess = requests.Session()
    sess.headers["User-Agent"] = "sieve-bench (+https://github.com/casareanderson/sieve)"
    sieve_cmd = shlex.split(args.sieve)
    raw = args.raw_dir
    os.makedirs(raw, exist_ok=True)
    errors = []
    refs = read_images(args.images)
    versions = tool_versions(sieve_cmd)
    kj = sess.get(KEV_URL, timeout=120)
    kj.raise_for_status()
    kj = kj.json()
    kev = {v["cveID"] for v in kj.get("vulnerabilities") or [] if v.get("cveID")}

    images, running = [], []
    try:
        for ref in refs:
            slug = slug_of(ref)
            local = f"sievebench/{slug}:pinned"
            im = {"ref": ref, "slug": slug, "local": local, "tar": os.path.join(raw, slug + ".tar"),
                  "status": {}, "records": {}, "runs": {}}
            images.append(im)
            pull = subprocess.run(["docker", "pull", "-q", ref], capture_output=True, text=True)
            if pull.returncode:
                errors.append(f"{slug}: docker pull failed: {pull.stderr.strip()[-300:]}")
                for x in TOOLS:
                    im["status"][x] = "error"
                continue
            subprocess.run(["docker", "tag", ref, local], check=True)
            subprocess.run(["docker", "save", "-o", im["tar"], local], check=True)
            name = "sievebench-" + slug.replace(".", "-")
            started = False
            for entry in (["--entrypoint", "sleep", local, "3600"], ["--entrypoint", "tail", local, "-f", "/dev/null"]):
                r = subprocess.run(["docker", "run", "-d", "--rm", "--name", name] + entry,
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    time.sleep(2)
                    st = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                                        capture_output=True, text=True).stdout.strip()
                    if st == "true":
                        started = True
                        running.append(name)
                        break
                subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            if not started:
                errors.append(f"{slug}: could not keep a container running for sieve")
                im["status"]["sieve"] = "error"

        # sieve: one run over every running bench container
        rc, text, err, secs, peak = run_cmd(sieve_cmd + ["containers", "--json", "--limit", "0",
                                                         "--cache", os.path.join(raw, "sieve-cache", "sieve.db")],
                                            os.path.join(raw, "sieve.json"))
        doc = None
        try:
            doc = load_json(text) if rc in (0, 1, 2) else None
        except ValueError:
            pass
        versions_note = {}
        if doc is None:
            errors.append(f"sieve: exit {rc}: {err.strip()[-300:]}")
            for im in images:
                im["status"]["sieve"] = "error"
        else:
            errors += [f"sieve: {e}" for e in doc.get("errors") or []]
            recs, targets = parse_sieve(doc, {im["local"]: im["ref"] for im in images})
            for im in images:
                if im["status"].get("sieve") == "error":
                    continue
                if im["ref"] in targets:
                    im["records"]["sieve"] = recs.get(im["ref"], [])
                    im["sieve_target"] = targets[im["ref"]]
                    im["status"]["sieve"] = "ok" if targets[im["ref"]].get("status") != "error" else "error"
                else:
                    im["status"]["sieve"] = "error"
                    errors.append(f"{im['slug']}: not among sieve's targets")
        sieve_run = {"seconds": secs, "peak_kb": peak}

        # trivy and grype databases, timed separately from the scans
        rc, _, err, tdb, _ = run_cmd(["trivy", "image", "--download-db-only", "--quiet"])
        if rc:
            errors.append(f"trivy db download: exit {rc}: {err.strip()[-200:]}")
        rc, _, err, gdb, _ = run_cmd(["grype", "db", "update"])
        if rc:
            errors.append(f"grype db update: exit {rc}: {err.strip()[-200:]}")
        versions_note["trivy"] = f"DB download {_fmt_s(tdb)}" + (f", DB {versions.get('trivy_db')}"
                                                                    if versions.get("trivy_db") else "")
        versions_note["grype"] = f"DB update {_fmt_s(gdb)}"
        versions_note["osv-scanner"] = "queries OSV.dev online, no local DB"
        versions_note["sieve"] = "queries OSV.dev online, cold cache; one run over all images"
        genv = dict(os.environ, GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false")
        osv_help = first_line(["sh", "-c", "osv-scanner scan image --help 2>&1 | grep -o -- '--all-vulns' | head -1"])
        osv_extra = ["--all-vulns"] if osv_help == "--all-vulns" else []
        commands = {
            "trivy": lambda tar: ["trivy", "image", "--input", tar, "--format", "json", "--list-all-pkgs",
                                  "--scanners", "vuln", "--skip-db-update", "--quiet"],
            "grype": lambda tar: ["grype", "docker-archive:" + tar, "-o", "json"],
            "osv-scanner": lambda tar: ["osv-scanner", "scan", "image", "--archive", tar, "--format", "json"]
            + osv_extra,
        }
        parsers = {"trivy": parse_trivy, "grype": parse_grype, "osv-scanner": parse_osv_scanner}
        ok_rc = {"trivy": (0,), "grype": (0,), "osv-scanner": (0, 1)}      # osv-scanner exits 1 when it finds vulns
        for im in images:
            if not os.path.exists(im["tar"]):
                continue
            for x in OTHERS:
                out = os.path.join(raw, f"{im['slug']}.{x}.json")
                rc, text, err, secs, peak = run_cmd(commands[x](im["tar"]), out,
                                                    env=genv if x == "grype" else None)
                im["runs"][x] = {"seconds": secs, "peak_kb": peak, "rc": rc}
                try:
                    doc = load_json(text) if rc in ok_rc[x] else None
                except ValueError:
                    doc = None
                if doc is None:
                    im["status"][x] = "error"
                    errors.append(f"{im['slug']}: {x} exit {rc}: {err.strip()[-300:]}")
                    continue
                im["records"][x] = parsers[x](doc)
                im["status"][x] = "ok"
            os.unlink(im["tar"])
    finally:
        if running and not args.keep_containers:
            subprocess.run(["docker", "rm", "-f"] + running, capture_output=True)

    osv_check = make_osv_check(sess)
    out_images = []
    for im in images:
        cmp = compare_image(im["records"], im["status"], kev, im.get("sieve_target"), osv_check)
        out_images.append({"ref": im["ref"], "slug": im["slug"], "status": im["status"],
                           "sieve_target": im.get("sieve_target"), "runs": im["runs"], "comparison": cmp})
    tools = {"sieve": dict(version=versions.get("sieve"), note=versions_note.get("sieve"), **sieve_run)}
    for x in OTHERS:
        runs = [im["runs"][x] for im in images if x in im["runs"]]
        peaks = [r["peak_kb"] for r in runs if r.get("peak_kb")]
        tools[x] = {"version": versions.get(x), "note": versions_note.get(x),
                    "seconds": sum(r["seconds"] for r in runs) if runs else None,
                    "peak_kb": max(peaks) if peaks else None,
                    "command": " ".join(commands[x]("<image.tar>"))}
    tools["sieve"]["command"] = "sieve containers --json --limit 0"
    return {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "runner": args.runner, "tools": tools, "kev_version": kj.get("catalogVersion"),
            "kev_count": len(kev), "images": out_images, "totals": totals(out_images, kev), "errors": errors}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--images", default=os.path.join(HERE, "images.txt"))
    p.add_argument("--out", default=HERE, help="where results.json and RESULTS.md go (default: bench/)")
    p.add_argument("--sieve", default="sudo sieve", help="command that runs sieve as root (default: %(default)s)")
    p.add_argument("--raw-dir", default=os.path.join(tempfile.gettempdir(), "sieve-bench"),
                   help="raw tool outputs and image tars (tars are deleted after scanning)")
    p.add_argument("--runner", default="GitHub Actions (ubuntu-latest)")
    p.add_argument("--keep-containers", action="store_true")
    p.add_argument("--render-only", metavar="RESULTS_JSON", help="only re-render RESULTS.md from a results.json")
    args = p.parse_args(argv)
    if args.render_only:
        with open(args.render_only, encoding="utf-8") as f:
            res = json.load(f)
    else:
        for b in ("docker", "trivy", "grype", "osv-scanner"):
            if not shutil.which(b):
                p.error(f"{b} not found on PATH (this benchmark runs on GitHub Actions, see bench.yml)")
        res = run_bench(args)
        with open(os.path.join(args.out, "results.json"), "w", encoding="utf-8") as f:
            json.dump(res, f, indent=1, sort_keys=True)
            f.write("\n")
    with open(os.path.join(args.out, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write(render(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
