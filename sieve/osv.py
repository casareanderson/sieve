"""OSV.dev matcher: package lists in, advisories out.

Why OSV: Debian, Ubuntu, Alpine, the GitHub advisory database, PyPA, the Go team and RustSec all publish to it
directly. sieve reads the package lists a box already has and asks OSV which advisories affect those exact
versions. There is no scanner binary and no vulnerability database to download, verify or keep patched.

  parse_*()      package lists from files a box or image already has (dpkg, apk, rpm, PyPI, npm, Go, Rust)
  ecosystem()    OSV ecosystem name for an os-release (Debian:12, Ubuntu:24.04:LTS, Alpine:v3.20,
                 AlmaLinux:9, Rocky Linux:9, Red Hat:enterprise_linux:9, openSUSE:Leap 15.6, openSUSE:Tumbleweed)
  match(pkgs)    findings as dicts: id, package, installed, fixed, severity, summary, kev, status, target, ...

Advisory bodies are cached in a local SQLite file keyed by OSV's `modified` stamp, so a repeat scan only
downloads what changed.
"""
import json
import math
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests

API = "https://api.osv.dev/v1"
from . import __version__

UA = {"User-Agent": f"sieve/{__version__} (+https://github.com/casareanderson/sieve)"}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
# Containers and LXC guests run the host's kernel, and Debian/Ubuntu kernel advisories are huge and numerous:
# asking about these packages was most of a scan's memory peak and every answer was thrown away (warden, 2026-10-10).
KERNEL_PKG = re.compile(r"^linux-(libc-dev|headers|image|modules|tools|kbuild|source)"
                        r"|^kernel(-(core|modules|modules-core|modules-extra|headers|devel|tools|tools-libs|"
                        r"default|default-base|default-devel|devel-headers|uki-virt))?$")


# ── package lists ────────────────────────────────────────────────────────────
def _stanzas(text):
    for block in text.split("\n\n"):
        d, last = {}, None
        for line in block.splitlines():
            if line[:1] in (" ", "\t") and last:
                continue
            k, _, v = line.partition(":")
            if _:
                last = k.strip()
                d[last] = v.strip()
        if d:
            yield d


def parse_dpkg(text):
    """Installed packages from dpkg status → [(source, source_version, binary, binary_version)]."""
    out = []
    for d in _stanzas(text):
        if "installed" not in d.get("Status", "install ok installed") or not d.get("Package") or not d.get("Version"):
            continue
        src, sver = d.get("Source", d["Package"]), d["Version"]
        m = re.match(r"(\S+)\s*\((.+)\)", src)
        if m:
            src, sver = m.group(1), m.group(2)
        out.append((src, sver, d["Package"], d["Version"]))
    return out


def parse_apk(text):
    out, cur = [], {}
    for line in text.splitlines() + [""]:
        if not line:
            if cur.get("P") and cur.get("V"):
                out.append((cur.get("o") or cur["P"], cur["V"], cur["P"], cur["V"]))
            cur = {}
        elif len(line) > 2 and line[1] == ":":
            cur[line[0]] = line[2:]
    return out


def _rpm_evr(epoch, version, release):
    return (f"{epoch}:" if epoch and epoch != "0" else "") + version + (f"-{release}" if release else "")


def parse_rpm(text):
    """The collector's rpm list ("name\tepoch\tversion\trelease\tarch\tsourcerpm" per line) →
    [(source, source_evr, binary, binary_evr)]. Versions are rpm EVR strings (`1:3.0.7-25.el9_3`, epoch only when
    set), which is how AlmaLinux, Rocky, Red Hat and SUSE write their fixed versions in OSV."""
    out = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        f = (line.split("\t") + [""] * 6)[:6]
        name, epoch, ver, rel, _arch, srpm = f
        if not name or not ver:
            continue
        evr = _rpm_evr(epoch, ver, rel)
        src, sevr = name, evr
        base = re.sub(r"\.(no)?src\.rpm$", "", srpm)
        parts = base.rsplit("-", 2)
        if base != srpm and len(parts) == 3 and parts[0]:
            src, sevr = parts[0], _rpm_evr(epoch, parts[1], parts[2])
        out.add((src, sevr, name, evr))
    return sorted(out)


def parse_pymeta(text):
    name = ver = None
    for line in text.splitlines():
        if not line.strip():
            break
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
    return (name, ver) if name and ver else None


def parse_npm(text):
    try:
        d = json.loads(text)
    except ValueError:
        return None
    n, v = d.get("name"), d.get("version")
    return (n, v) if isinstance(n, str) and isinstance(v, str) and n and v else None


_GO_MAGIC = b"\xff Go buildinf:"


def _uvarint(b, i):
    x = s = 0
    while i < len(b):
        c = b[i]
        i += 1
        x |= (c & 0x7F) << s
        if c < 0x80:
            return x, i
        s += 7
    raise ValueError("short varint")


def parse_gobuild(blob):
    """Go ≥1.18 build info (the collector sends the bytes from the magic onwards) → (go_version, [(module, ver)]).
    Older binaries store pointers instead of inline strings; they return (None, []) and are counted as unread."""
    i = blob.find(_GO_MAGIC)
    if i < 0 or len(blob) < i + 32 or not blob[i + 15] & 2:
        return None, []
    p = i + 32
    n, p = _uvarint(blob, p)
    gover = blob[p:p + n].decode("utf-8", "replace")
    p += n
    n, p = _uvarint(blob, p)
    mod = blob[p:p + n]
    if len(mod) >= 33:
        mod = mod[16:-16]
    deps = {}
    last = None
    for line in mod.decode("utf-8", "replace").splitlines():
        f = line.split("\t")
        if f[0] in ("mod", "dep") and len(f) >= 3:
            last = f[1]
            if f[2] != "(devel)":
                deps[f[1]] = f[2]
        elif f[0] == "=>" and len(f) >= 3 and last:
            deps.pop(last, None)
            deps[f[1]] = f[2]
    return gover, sorted(deps.items())


def parse_rustdeps(blob):
    """cargo-auditable's .dep-v0 section (zlib JSON) → [(crate, version)] from crates.io, build-only deps dropped."""
    import zlib
    try:
        d = json.loads(zlib.decompress(blob))
    except (zlib.error, ValueError):
        return []
    return sorted({(p["name"], p["version"]) for p in d.get("packages") or []
                   if p.get("source") == "crates.io" and p.get("kind") != "build" and p.get("name") and p.get("version")})


# ── OS identity ──────────────────────────────────────────────────────────────
def kv(text):
    return {k: v.strip().strip('"') for k, _, v in (l.partition("=") for l in text.splitlines()) if _}


RPM_ID = {"almalinux": "AlmaLinux:{major}", "rocky": "Rocky Linux:{major}", "rhel": "Red Hat:enterprise_linux:{major}"}
RPM_ECO = ("AlmaLinux:", "Rocky Linux:", "Red Hat:", "openSUSE:")


def ecosystem(osr, alpine_release=""):
    """os-release dict → (OSV ecosystem, label). None when OSV has no feed for it."""
    ident, ver = osr.get("ID", ""), osr.get("VERSION_ID", "")
    like = osr.get("ID_LIKE", "").split()
    if ident == "debian" or (not ident and not ver):
        major = ver.split(".")[0]
        return (f"Debian:{major}", f"debian {ver}") if major.isdigit() else (None, f"debian {ver or '?'}")
    if ident == "ubuntu" or ("ubuntu" in like and ver):
        lts = "LTS" in osr.get("VERSION", "") or (ver.split(".")[0].isdigit() and int(ver.split(".")[0]) % 2 == 0
                                                  and ver.endswith(".04"))
        label = f"ubuntu {ver}" if ident == "ubuntu" else f"{ident} {ver} (scanned as ubuntu {ver})"
        return (f"Ubuntu:{ver}:LTS" if lts else f"Ubuntu:{ver}"), label
    if ident == "alpine":
        v = ".".join((alpine_release or ver).split(".")[:2])
        return f"Alpine:v{v}", f"alpine {alpine_release or ver}"
    # RPM distros OSV has feeds for. Fedora, CentOS Stream, Oracle Linux and Amazon Linux have none (2026-10-11), and
    # SUSE Linux Enterprise files fixes per module ("Basesystem 15 SP5"), which a host can't name reliably.
    major = ver.split(".")[0]
    if ident in RPM_ID and major.isdigit():
        return RPM_ID[ident].format(major=major), f"{ident} {ver}"
    if ident == "opensuse-leap" and ver:
        return f"openSUSE:Leap {ver}", f"opensuse-leap {ver}"
    if ident == "opensuse-tumbleweed":
        return "openSUSE:Tumbleweed", f"opensuse-tumbleweed {ver}".strip()
    return None, f"{ident or 'unknown'} {ver}".strip()


# ── version ordering (enough to pick the right "fixed" event) ────────────────
def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a, b):
    while a or b:
        na = re.match(r"[^\d]*", a).group(0)
        nb = re.match(r"[^\d]*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            x = _deb_order(na[i]) if i < len(na) else 0
            y = _deb_order(nb[i]) if i < len(nb) else 0
            if x != y:
                return -1 if x < y else 1
        da = re.match(r"\d*", a).group(0)
        db = re.match(r"\d*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
    return 0


def deb_cmp(a, b):
    def split(v):
        e, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        u, _, r = rest.rpartition("-") if "-" in rest else (rest, "", "0")
        return int(e or 0), u, r
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part(ua, ub) or _deb_part(ra, rb)


_APK_SUF = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "": 0, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def apk_cmp(a, b):
    """apk-tools ordering: 1.2.3[letter][_suffixN…][-rN]; _alpha<_beta<_pre<_rc<release<_p, -r10 > -r9."""
    def key(v):
        m = re.match(r"^(.*?)(?:-r(\d+))?$", v)
        base, rel = m.group(1), int(m.group(2) or 0)
        m = re.match(r"^([\d.]*\d)?([a-z]?)((?:_[a-z]+\d*)*)$", base)
        if not m:
            return ((), "", (), rel, base)
        nums = tuple(int(x) for x in (m.group(1) or "0").split("."))
        sufs = tuple((_APK_SUF.get(re.match(r"[a-z]+", x).group(0), 0), int(re.sub(r"\D", "", x) or 0))
                     for x in m.group(3).split("_") if x)
        return (nums, m.group(2), sufs + ((0, 0),), rel, "")
    ka, kb = key(a), key(b)
    for x, y in zip(ka[0], kb[0]):                      # numeric parts, then length (1.2 < 1.2.1)
        if x != y:
            return -1 if x < y else 1
    if len(ka[0]) != len(kb[0]):
        return -1 if len(ka[0]) < len(kb[0]) else 1
    ka, kb = ka[1:], kb[1:]
    return (ka > kb) - (ka < kb)


def _alnum(c):
    return c.isascii() and c.isalnum()


def rpmvercmp(a, b):
    """rpm's own segment comparison: digits vs letters, leading zeros ignored, a numeric segment beats an alpha one,
    `~` sorts before anything (1.0~rc1 < 1.0) and `^` after the base but before any further segment."""
    if a == b:
        return 0
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < len(b) and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        if (i < len(a) and a[i] == "~") or (j < len(b) and b[j] == "~"):
            if i >= len(a) or a[i] != "~":
                return 1
            if j >= len(b) or b[j] != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        if (i < len(a) and a[i] == "^") or (j < len(b) and b[j] == "^"):
            if i >= len(a):
                return -1
            if j >= len(b):
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if i >= len(a) or j >= len(b):
            break
        num = a[i].isdigit()
        same = (lambda c: c.isascii() and c.isdigit()) if num else (lambda c: c.isascii() and c.isalpha())
        si, sj = i, j
        while i < len(a) and same(a[i]):
            i += 1
        while j < len(b) and same(b[j]):
            j += 1
        x, y = a[si:i], b[sj:j]
        if not y:
            return 1 if num else -1
        if num:
            x, y = x.lstrip("0"), y.lstrip("0")
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= len(a) and j >= len(b):
        return 0
    return -1 if i >= len(a) else 1


def rpm_cmp(a, b):
    """epoch:version-release, compared the way rpm does (a missing epoch is 0; release only when both have one)."""
    def split(v):
        e, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        ver, _, rel = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(e or 0) if e.isdigit() else 0, ver, rel
    ea, va, ra = split(a)
    eb, vb, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


_PRE = re.compile(r"(?i)^[-._]?(alpha|beta|preview|pre|dev|rc|a|b|c)[-._]?(\d*)")
_POST = re.compile(r"(?i)^[-._]?(post|rev|p|r)[-._]?(\d*)")


def gen_cmp(a, b):
    """semver / PEP 440 / Go: release numbers first, then dev < alpha < beta < rc < release < post.
    (Plain text comparison put 2.0.0rc1 after 2.0.0, research review 2026-10-10.)"""
    rank = {"dev": -5, "a": -4, "alpha": -4, "b": -3, "beta": -3, "c": -2, "pre": -2, "preview": -2, "rc": -1}

    def key(v):
        v = v.strip().lstrip("vV").split("+")[0]
        m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
        if not m:
            return ((), 0, 0, v)
        nums = [int(x) for x in m.group(1).split(".")]
        while len(nums) > 1 and nums[-1] == 0:
            nums.pop()                                  # 1.0 == 1.0.0
        rest = m.group(2)
        p = _PRE.match(rest)
        if p:
            return (tuple(nums), rank[p.group(1).lower()], int(p.group(2) or 0), rest[p.end():])
        p = _POST.match(rest)
        if p and (p.group(2) or p.group(1).lower() == "post"):
            return (tuple(nums), 1, int(p.group(2) or 0), rest[p.end():])
        return (tuple(nums), 0, 0, rest)
    ka, kb = key(a), key(b)
    return (ka > kb) - (ka < kb)


def vcmp(eco, a, b):
    try:
        if eco.startswith(("Debian", "Ubuntu")):
            return deb_cmp(a, b)
        if eco.startswith(RPM_ECO):
            return rpm_cmp(a, b)
        return apk_cmp(a, b) if eco.startswith("Alpine") else gen_cmp(a, b)
    except Exception:  # noqa: BLE001
        return 0


# ── CVSS v3 base score (Alpine and Debian advisories carry vectors, not levels) ─
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
      "UI": {"N": .85, "R": .62}, "C": {"H": .56, "L": .22, "N": 0}}


def cvss3(vector):
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if changed else .62, "H": .5 if changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["C"][m["I"]]) * (1 - _W["C"][m["A"]])
        imp = 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if imp <= 0:
            return 0.0
        raw = min(1.08 * (imp + expl), 10) if changed else min(imp + expl, 10)
        return math.ceil(raw * 10 - 1e-9) / 10
    except Exception:  # noqa: BLE001
        return None


def level(score):
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "UNKNOWN"


def severity(v):
    """Vendor level first (Ubuntu priority, GitHub-reviewed level), then the CVSS v3 vector, else UNKNOWN."""
    for s in v.get("severity") or []:
        if s.get("type") == "Ubuntu":
            u = s.get("score", "").lower()
            return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
                    "negligible": "LOW"}.get(u, "UNKNOWN")
    m = re.match(r"(Critical|Important|Moderate|Low):", v.get("summary") or "")   # RHSA/ALSA/RLSA: Red Hat's rating
    if m:
        return {"Critical": "CRITICAL", "Important": "HIGH", "Moderate": "MEDIUM", "Low": "LOW"}[m.group(1)]
    g = (v.get("database_specific") or {}).get("severity")
    if isinstance(g, str) and g.upper() in ("LOW", "MODERATE", "MEDIUM", "HIGH", "CRITICAL"):
        return "MEDIUM" if g.upper() == "MODERATE" else g.upper()
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            return level(cvss3(s.get("score", "")))
    return "UNKNOWN"


# ── OSV API + cache ──────────────────────────────────────────────────────────
def slim(v):
    """Keep only what matching needs. Ubuntu and Debian records enumerate every affected version of every binary
    across all releases, often megabytes each; keeping whole bodies took one scan past 5 GB of RAM (2026-10-10)."""
    refs = [r for r in v.get("references") or [] if r.get("type") == "ADVISORY"][:1]
    sev_db = (v.get("database_specific") or {}).get("severity")
    aff = []
    for a in v.get("affected") or []:
        es = a.get("ecosystem_specific") or {}
        aff.append({"package": a.get("package") or {},
                    "ranges": [{"events": [e for e in r.get("events") or [] if "fixed" in e]}
                               for r in a.get("ranges") or []],
                    **({"ecosystem_specific": {"urgency": es["urgency"]}} if isinstance(es, dict) and "urgency" in es
                       else {})})
    out = {"id": v["id"], "modified": v.get("modified", ""), "summary": (v.get("summary") or "")[:200],
           "details": (v.get("details") or "")[:1200], "aliases": v.get("aliases") or [],
           "upstream": [u for u in v.get("upstream") or [] if u.startswith("CVE-")],
           "related": [u for u in v.get("related") or [] if u.startswith("CVE-")],
           "severity": v.get("severity") or [], "references": refs, "affected": aff}
    if sev_db:
        out["database_specific"] = {"severity": sev_db}
    if v.get("withdrawn"):
        out["withdrawn"] = v["withdrawn"]
    return out


# RPM distros publish only advisories (errata), each listing its CVEs: expanded like USN/DSA notices below.
RPM_NOTICE = ("RHSA-", "RHBA-", "RHEA-", "ALSA-", "ALBA-", "ALEA-", "RLSA-", "RLBA-", "RLEA-",
              "SUSE-SU-", "SUSE-RU-", "SUSE-FU-", "SUSE-OU-", "openSUSE-SU-", "openSUSE-RU-")
RPM_SECURITY = ("RHSA-", "ALSA-", "RLSA-", "SUSE-SU-", "openSUSE-SU-")
NOTICE = ("USN-", "DSA-", "DLA-", "DTSA-") + RPM_NOTICE
CACHE_SCHEMA = 3                        # bump when slim() keeps more fields, so old cached bodies are refetched


def _notice_cves(b):
    return sorted({c for c in (b.get("upstream") or []) + (b.get("aliases") or []) + (b.get("related") or [])
                   if c.startswith("CVE-")})


class OSV:
    def __init__(self, db_path, session=None):
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.con = sqlite3.connect(db_path, timeout=60, check_same_thread=False)
        if self.con.execute("pragma user_version").fetchone()[0] < CACHE_SCHEMA:
            self.con.execute("drop table if exists osv_vulns")
            self.con.execute(f"pragma user_version={CACHE_SCHEMA}")
        self.con.execute("create table if not exists osv_vulns(id text primary key, modified text, body text, "
                         "fetched text)")
        self.con.commit()
        self.s = session or requests.Session()
        self.s.headers.update(UA)
        self.fetched = 0
        self.failed = 0                     # advisories that could not be fetched → the target is marked partial
        self._secdb = {}

    @staticmethod
    def _wait(r, attempt):
        """Back off 2, 4, 8 s, or what the server's Retry-After asks (capped at 60 s)."""
        ra = r.headers.get("Retry-After", "") if r is not None else ""
        time.sleep(min(int(ra), 60) if ra.isdigit() else 2 ** (attempt + 1))

    def _post(self, path, body):
        for attempt in range(4):
            r = None
            try:
                r = self.s.post(API + path, json=body, timeout=120)
                if r.status_code < 500 and r.status_code != 429:
                    r.raise_for_status()
                    return r.json()
            except requests.RequestException:
                if attempt == 3:
                    raise
            if attempt < 3:
                self._wait(r, attempt)
        raise RuntimeError(f"OSV {path}: server errors")

    def secdb(self, branch):
        """Alpine's own security DB for a branch (v3.24) → {origin: [(fixed_version, [CVE…])]}.
        OSV's Alpine import lags: on 2026-10-10 it had none of v3.24's mbedtls3 3.6.7 or libssh 0.12.1 fixes,
        which secdb had. Cached for 20 hours."""
        if branch in self._secdb:
            return self._secdb[branch]
        self.con.execute("create table if not exists osv_secdb(branch text primary key, fetched real, body text)")
        row = self.con.execute("select fetched, body from osv_secdb where branch=?", (branch,)).fetchone()
        body = row[1] if row and time.time() - row[0] < 20 * 3600 else None
        if body is None:
            try:
                merged = {}
                for repo in ("main", "community"):
                    r = self.s.get(f"https://secdb.alpinelinux.org/{branch}/{repo}.json", timeout=60)
                    if r.status_code == 404:
                        continue
                    r.raise_for_status()
                    for p in r.json().get("packages") or []:
                        pk = p.get("pkg") or {}
                        merged.setdefault(pk.get("name"), {}).update(pk.get("secfixes") or {})
                body = json.dumps(merged)
                self.con.execute("insert or replace into osv_secdb values(?,?,?)", (branch, time.time(), body))
                self.con.commit()
            except (requests.RequestException, ValueError):
                body = row[1] if row else "{}"          # stale secdb beats none; OSV still answers
        out = {}
        for name, fixes in json.loads(body).items():
            out[name] = [(v, [c.split()[0] for c in cves if c.startswith("CVE-")])
                         for v, cves in fixes.items() if v and v != "0"]
        self._secdb[branch] = out
        return out

    def query(self, queries):
        """[{package:{ecosystem,name}, version}] → per query [(id, modified)]. Follows page tokens."""
        out = [[] for _ in queries]
        pending = list(range(len(queries)))
        tokens = {}
        while pending:
            nxt = []
            for k in range(0, len(pending), 1000):
                chunk = pending[k:k + 1000]
                body = {"queries": [dict(queries[i], **({"page_token": tokens[i]} if i in tokens else {}))
                                    for i in chunk]}
                res = self._post("/querybatch", body)["results"]
                for i, r in zip(chunk, res):
                    out[i] += [(v["id"], v.get("modified", "")) for v in r.get("vulns") or []]
                    if r.get("next_page_token"):
                        tokens[i] = r["next_page_token"]
                        nxt.append(i)
            pending = nxt
        return out

    def get(self, pairs):
        """{id: modified} → {id: body}, fetching only ids that are new or changed since the cached copy."""
        self.con.execute("delete from osv_vulns where modified='missing' and fetched < datetime('now','-1 day')")
        have = {}
        ids = list(pairs)
        for k in range(0, len(ids), 500):
            chunk = ids[k:k + 500]
            q = "select id, modified, body from osv_vulns where id in (%s)" % ",".join("?" * len(chunk))
            for i, m, b in self.con.execute(q, chunk):
                have[i] = (m, b)
        # "" modified = id we only want if it exists (alias/severity lookups): a cached miss is not re-asked for a day
        need = [i for i in ids if i not in have or (pairs[i] and have[i][0] != pairs[i])]

        def one(i):
            for attempt in range(4):
                r = None
                try:
                    r = self.s.get(f"{API}/vulns/{i}", timeout=60)
                    if r.status_code == 404:
                        return i, False
                    if r.status_code != 429:
                        r.raise_for_status()
                        return i, slim(r.json())
                except requests.RequestException:
                    pass
                if attempt < 3:
                    self._wait(r, attempt)
            return i, None
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with ThreadPoolExecutor(16) as ex:
            for i, body in ex.map(one, need):
                if body is False:
                    self.con.execute("insert or replace into osv_vulns values(?,?,?,?)", (i, "missing", "null", now))
                    continue
                if body is None:
                    if pairs[i]:                    # a real hit we could not read (not an optional alias lookup)
                        self.failed += 1
                    continue
                self.fetched += 1
                have[i] = (body.get("modified", ""), json.dumps(body, separators=(",", ":")))
                self.con.execute("insert or replace into osv_vulns values(?,?,?,?)",
                                 (i, have[i][0], have[i][1], now))
        self.con.commit()
        out = {}
        for i, (m, b) in have.items():
            if m == "missing":
                continue
            out[i] = json.loads(b)
        return out


# ── matching ─────────────────────────────────────────────────────────────────
def _cve(v):
    if v["id"].startswith("CVE-"):
        return v["id"]
    m = re.match(r"^(?:DEBIAN|UBUNTU|ALPINE|DLA|BIT-[a-z]+)-(CVE-\d{4}-\d+)$", v["id"])
    if m:
        return m.group(1)
    for a in v.get("aliases") or []:
        if a.startswith("CVE-"):
            return a
    return None


def _fixed(v, eco, name, installed):
    """Lowest 'fixed' version above what is installed, for this package in this ecosystem ('' = no fix yet)."""
    cands = []
    for a in v.get("affected") or []:
        p = a.get("package") or {}
        # exact release only: a Debian record also lists unstable's fix (curl 8.21.0~rc2 on trixie, 2026-10-10)
        if p.get("name") != name or p.get("ecosystem") != eco:
            continue
        for r in a.get("ranges") or []:
            for e in r.get("events") or []:
                f = e.get("fixed")
                if f and vcmp(eco, f, installed) > 0:
                    cands.append(f)
    if not cands:
        return ""
    best = cands[0]
    for c in cands[1:]:
        if vcmp(eco, c, best) < 0:
            best = c
    return best


_GA_MEDIA = re.compile(r"^(\S+)-([^-\s]+-[^-\s]+) on GA media$")


def _stale_ga(b, eco, name, installed):
    """openSUSE's "<pkg>-<version> on GA media" records name the fixed build in their title, and some carry a wrong
    fixed event: openSUSE-SU-2024:10106-1 is "bash-4.4-92.1 on GA media" with fixed 7.0-92.1, which flagged
    Tumbleweed's bash 5.3 with 2014's Shellshock (2026-10-11). Already at or past the title's build = not affected."""
    m = _GA_MEDIA.match(b.get("summary") or "")
    return bool(m and b["id"].startswith("openSUSE-SU-") and m.group(1) == name and vcmp(eco, m.group(2), installed) <= 0)


def _url(v):
    for r in v.get("references") or []:
        if r.get("type") == "ADVISORY":
            return r.get("url", "")
    return f"https://osv.dev/vulnerability/{v['id']}"


def _row(vid, rn, rv, fixed, sev, b, kev, status, target, url):
    return {"id": vid, "package": rn, "installed": rv, "fixed": fixed, "severity": sev,
            "summary": (b.get("summary") or "")[:200], "kev": vid in kev, "status": status, "target": target,
            "details": (b.get("details") or "")[:1200], "url": url}


def match(osv, pkgs, kev, target="", alias_sev=True):
    """pkgs: [(ecosystem, query_name, query_version, report_name, report_version)].
    report_name/version is what the user sees and upgrades (the binary package for dpkg/apk); query_name/version
    is what OSV indexes (the source package). Returns finding dicts, deduplicated per (id, package, target),
    with the CVE id as `id` wherever one exists so KEV and EPSS lookups work."""
    uniq = sorted({(e, n, v) for e, n, v, _, _ in pkgs})
    hits = osv.query([{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in uniq])
    pairs = {}
    for h in hits:
        for i, m in h:
            pairs[i] = m
    bodies = osv.get(pairs)
    # Alpine: add fixes that are in Alpine's secdb but not (yet) in OSV
    sec = {}
    for e, n, v in uniq:
        if e.startswith("Alpine:"):
            for fv, cves in osv.secdb(e.split(":", 1)[1]).get(n, []):
                if vcmp(e, fv, v) > 0:
                    for c in cves:
                        if c not in sec.get((e, n, v), {}) or vcmp(e, fv, sec[(e, n, v)][c]) < 0:
                            sec.setdefault((e, n, v), {})[c] = fv
    # Go advisories carry no severity and secdb gives only ids. Borrow it, in order, from the GitHub advisory, the
    # CVE record, then Ubuntu's and Debian's triage of the same CVE (they rate upstream CVEs NVD has not scored yet).
    def chain(b_or_cve):
        if isinstance(b_or_cve, str):
            al, cve = [], b_or_cve
        else:
            al, cve = b_or_cve.get("aliases") or [], _cve(b_or_cve)
        c = [x for x in al if x.startswith("GHSA-")]
        if cve:
            c += [cve, "UBUNTU-" + cve, "DEBIAN-" + cve]
        return c
    if alias_sev:
        extra = {}
        for b in list(bodies.values()):
            if severity(b) == "UNKNOWN":
                for a in chain(b):
                    if a not in bodies:
                        extra[a] = ""
        for d in sec.values():
            for c in d:
                for a in chain(c):
                    if a not in bodies:
                        extra[a] = ""
        for b in list(bodies.values()):
            if b["id"].startswith(NOTICE) and not (b["id"].startswith(RPM_NOTICE) and severity(b) != "UNKNOWN"):
                for c in _notice_cves(b):
                    for a in chain(c):
                        if a not in bodies:
                            extra[a] = ""
        if extra:
            bodies.update(osv.get(extra))

    def borrowed(src):
        for a in chain(src):
            if a in bodies:
                sv = severity(bodies[a])
                if sv != "UNKNOWN":
                    return sv
        return "UNKNOWN"
    by_q = {}
    for (e, n, v), h in zip(uniq, hits):
        by_q[(e, n, v)] = [bodies[i] for i, _ in h if i in bodies]
    out = {}
    for e, n, v, rn, rv in pkgs:
        for b in by_q.get((e, n, v), []):
            # USN/DSA/DLA notices bundle CVEs that UBUNTU-CVE-*/DEBIAN-CVE-* records already carry one by one;
            # counted again they double the fixable list with UNKNOWN severity (research review 2026-10-10).
            # They are only used below, for CVEs no per-CVE record covered.
            if b.get("withdrawn") or b["id"].startswith(NOTICE):
                continue
            vid = _cve(b) or b["id"]
            sev = severity(b)
            if sev == "UNKNOWN":
                sev = borrowed(b)
            fixed = _fixed(b, e, n, v)
            status = "fixed" if fixed else "affected"
            if fixed and e.startswith("Ubuntu") and "esm" in fixed:
                fixed, status = "", "fix needs Ubuntu Pro (ESM)"
            urg = [str((a.get("ecosystem_specific") or {}).get("urgency", "")) for a in b.get("affected") or []]
            if e.startswith("Debian") and urg and all(u == "unimportant" for u in urg):
                sev, status = "LOW", (status if fixed else "unimportant (Debian)")
            row = _row(vid, rn, rv, fixed, sev, b, kev, status, target, _url(b))
            key = (vid, rn, target)
            old = out.get(key)
            # keep the most useful copy when GHSA + PYSEC (etc.) describe the same CVE
            if not old or (row["fixed"] and not old["fixed"]) or SEV_RANK[row["severity"]] > SEV_RANK[old["severity"]]:
                out[key] = row
    # Older releases (Debian 10/11 on 2026-10-10) get no per-CVE records in OSV at all, only DSA/DLA notices:
    # skipping notices outright made a bullseye image with PwnKit and Baron Samedit look clean. Expand a notice
    # into its CVEs, for any CVE a per-CVE record has not already reported for this package.
    for e, n, v, rn, rv in pkgs:
        for b in by_q.get((e, n, v), []):
            if b.get("withdrawn") or not b["id"].startswith(NOTICE) or _stale_ga(b, e, n, v):
                continue
            fixed = _fixed(b, e, n, v)
            status = "fixed" if fixed else "affected"
            if fixed and e.startswith("Ubuntu") and "esm" in fixed:
                fixed, status = "", "fix needs Ubuntu Pro (ESM)"
            own = severity(b) if b["id"].startswith(RPM_NOTICE) else "UNKNOWN"   # the distro's own rating
            cves = _notice_cves(b)
            if not cves and b["id"].startswith(RPM_SECURITY) and (b["id"], rn, target) not in out:
                out[(b["id"], rn, target)] = _row(b["id"], rn, rv, fixed, own, b, kev, status, target, _url(b))
            for c in cves:
                if (c, rn, target) in out:
                    continue
                cb = bodies.get(c) or {}
                out[(c, rn, target)] = _row(c, rn, rv, fixed, own if own != "UNKNOWN" else borrowed(c),
                                            {"summary": cb.get("summary") or b.get("summary"),
                                             "details": cb.get("details") or b.get("details")},
                                            kev, status, target, _url(b))
    for e, n, v, rn, rv in pkgs:
        for c, fv in sec.get((e, n, v), {}).items():
            key = (c, rn, target)
            if key in out:
                if not out[key]["fixed"]:
                    out[key].update(fixed=fv, status="fixed")
                continue
            b = bodies.get(c) or bodies.get("UBUNTU-" + c) or bodies.get("DEBIAN-" + c) or {}
            out[key] = _row(c, rn, rv, fv, borrowed(c), b, kev, "fixed", target,
                            f"https://security.alpinelinux.org/vuln/{c}")
    return list(out.values())


def os_packages(eco, entries):
    """dpkg/apk/rpm entries → match() input: query the source package, report each binary.
    RPM feeds differ in what they index (Rocky: source packages; AlmaLinux and Red Hat: binaries; openSUSE: source),
    so rpm packages are asked about under both names. Red Hat splits RHEL into BaseOS and AppStream ecosystems."""
    if not eco.startswith(RPM_ECO):
        return [(eco, src, sver, b, bver) for src, sver, b, bver in entries]
    ecos = [eco + "::baseos", eco + "::appstream"] if eco.startswith("Red Hat:") else [eco]
    out = []
    for src, sver, b, bver in entries:
        for e in ecos:
            out.append((e, b, bver, b, bver))
            if src != b:
                out.append((e, src, sver, b, bver))
    return out
