"""sieve verify: has any installed file changed since its package manager put it there?

No scanner binary and no download: every package manager below already keeps a checksum for each file it installs,
in a world-readable file next to its package database. sieve re-hashes the files and compares.

  Debian / Ubuntu   /var/lib/dpkg/info/<pkg>[:<arch>].md5sums      MD5    conffiles skipped (they are meant to change;
                                                                           --include-config checks them against the
                                                                           MD5 dpkg recorded in its status file)
  Alpine            /lib/apk/db/installed  F: dir, R: file, Z: Q1… SHA-1
  Python (pip)      <site-packages>/*.dist-info/RECORD              SHA-256
  rpm               the rpm database's own headers (SQLite, ndb or BerkeleyDB, read without the rpm binary):
                    FILEDIGESTS with FILEDIGESTALGO (SHA-256 on current Fedora/EL, MD5 on old releases);
                    config files skipped like dpkg's, and files rpm itself didn't install (nodocs, other
                    languages, the other multilib arch) left out the way `rpm -V` leaves them out
  npm               nothing to check: npm keeps no per-file checksums for installed files (a lockfile's
                    `integrity` is the hash of the downloaded tarball, not of what is on disk)

It is a tripwire, not proof. MD5 and SHA-1 catch accidental changes and naive tampering; someone with root can
rewrite the checksum lists as easily as the files. A changed file is a question to answer, not a verdict.
"""
import base64
import csv
import fnmatch
import glob
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

from . import __version__, collect, sources

BUF = 1 << 20
# where a changed file matters most: what runs as root, what checks passwords, what every process loads
# where minimal and official images delete files after install (docs, man pages, translations): a missing file here
# is the image build, not an attacker, so it is counted as "trimmed" instead of listed (--all-missing lists it)
TRIMMED = re.compile(r"^/usr/share/(doc|man|info|locale|licenses|help|gtk-doc|i18n)/|/LC_MESSAGES/")
HIGH = re.compile(r"^/(usr/)?s?bin/|^/(usr/)?lib(32|64|x32)?/([^/]+/)?security/|"
                  r"(^|/)(sshd|sshd-session|sudo|su|login|passwd|ld-linux[^/]*|libc\.so[^/]*|libpam[^/]*\.so[^/]*|"
                  r"libcrypt[^/]*\.so[^/]*|libsystemd[^/]*\.so[^/]*)$")


class Target:
    """One verified filesystem: the host, a --root directory, or one running container."""

    def __init__(self, name, kind, root):
        self.name, self.kind, self.root = name, kind, root
        self.os = ""
        self.packages = self.files = self.unreadable = self.config_skipped = self.excluded = 0
        self.under_mounts = self.trimmed = 0
        self.all_missing = False
        self.skip_prefixes = []        # container mount points: data, not the image
        self.items = []                # {"package", "version", "ecosystem", "path", "state", "high"}
        self.notes = []
        self.status = "ok"

    def as_dict(self):
        return {"name": self.name, "kind": self.kind, "os": self.os, "packages": self.packages,
                "files": self.files, "unreadable": self.unreadable, "config_skipped": self.config_skipped,
                "excluded": self.excluded, "under_mounts": self.under_mounts, "trimmed": self.trimmed,
                "changed": sum(1 for i in self.items if i["state"] == "changed"),
                "missing": sum(1 for i in self.items if i["state"] == "missing"),
                "status": self.status, "notes": self.notes}


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def digest(path, algo):
    """Hash of a file's content (symlinks followed, like the package managers do) → hex, or None if unreadable,
    or "" if it isn't there. Streams, so a 1 GB file costs 1 MB of memory."""
    h = hashlib.new(algo)
    try:
        with open(path, "rb") as f:
            while True:
                b = f.read(BUF)
                if not b:
                    break
                h.update(b)
    except FileNotFoundError:
        return ""
    except (PermissionError, IsADirectoryError, OSError):
        return None
    return h.hexdigest()


def _exists(path):
    return os.path.lexists(path)


def check(t, pkg, version, eco, rel, algo, want, want_fmt="hex"):
    """One file: compare, and record anything that isn't a match on the target."""
    rel = "/" + rel.lstrip("/")
    if any(rel == p or rel.startswith(p + "/") for p in t.skip_prefixes):
        t.under_mounts += 1
        return
    # inside a container root an absolute symlink would resolve on the HOST: walk the path within the root instead
    full = os.path.join(t.root, rel.lstrip("/")) if os.path.abspath(t.root) == "/" else collect.in_root(t.root, rel)
    got = digest(full, algo) if full else None
    t.files += 1
    if got is None:
        t.unreadable += 1
        return
    if want_fmt == "b64":
        got = base64.b64encode(bytes.fromhex(got)).decode() if got else ""
    elif want_fmt == "b64url":
        got = base64.urlsafe_b64encode(bytes.fromhex(got)).decode().rstrip("=") if got else ""
    if got == "":
        if _exists(full):           # a dangling symlink, say: present but unreadable as content
            t.unreadable += 1
            return
        if TRIMMED.search(rel) and not t.all_missing:
            t.trimmed += 1
            return
        state = "missing"
    elif got.lower() != want.lower() if want_fmt == "hex" else got != want:
        state = "changed"
    else:
        return
    t.items.append({"package": pkg, "version": version, "ecosystem": eco, "path": rel, "state": state,
                    "high": bool(HIGH.search(rel))})


# ── Debian / Ubuntu ──────────────────────────────────────────────────────────
def dpkg_status(text):
    """status → {package: {"version", "arch", "conffiles": {path: md5}}} for installed packages. Conffiles are
    continuation lines, which the CVE parser deliberately ignores, so this reads the stanzas itself."""
    out = {}
    for block in (text or "").split("\n\n"):
        d, conf, inconf = {}, {}, False
        for line in block.splitlines():
            if line[:1] in (" ", "\t"):
                if inconf:
                    f = line.split()
                    if len(f) >= 2 and f[0].startswith("/") and "obsolete" not in f[2:] and f[1] != "newconffile":
                        conf[f[0]] = f[1]
                continue
            k, _, v = line.partition(":")
            inconf = k == "Conffiles"
            if _:
                d[k] = v.strip()
        if d.get("Package") and "installed" in d.get("Status", "install ok installed").split()[-1:]:
            out[d["Package"]] = {"version": d.get("Version", ""), "arch": d.get("Architecture", ""), "conffiles": conf}
    return out


def dpkg_filters(root):
    """path-exclude / path-include from dpkg.cfg(.d): files a minimal image or container told dpkg not to unpack
    (docs, man pages, locales). Their md5sums are still listed, so without this they all read as "missing"."""
    rules = []
    for f in [os.path.join(root, "etc/dpkg/dpkg.cfg")] + sorted(glob.glob(os.path.join(root, "etc/dpkg/dpkg.cfg.d/*"))):
        for line in (_read(f) or "").splitlines():
            line = line.strip()
            for kind in ("path-exclude", "path-include"):
                if line.startswith(kind):
                    pat = line[len(kind):].lstrip(" =").strip()
                    if pat:
                        rules.append((kind == "path-include", pat))
    return rules


def _excluded(path, rules):
    out = False
    for include, pat in rules:            # dpkg: the last matching rule wins
        if fnmatch.fnmatchcase(path, pat):
            out = not include
    return out


def dpkg_diversions(root):
    """{original path: (diverted-to path, diverting package)}. A file from any OTHER package lives at the
    diverted-to path (Debian's /usr merge diverts hundreds of /lib paths this way)."""
    lines = (_read(os.path.join(root, "var/lib/dpkg/diversions")) or "").splitlines()
    return {lines[i]: (lines[i + 1], lines[i + 2]) for i in range(0, len(lines) - 2, 3)}


def verify_dpkg(t, only=None, include_config=False):
    status = dpkg_status(_read(os.path.join(t.root, "var/lib/dpkg/status")))
    if not status:
        return False
    rules, div = dpkg_filters(t.root), dpkg_diversions(t.root)
    info = os.path.join(t.root, "var/lib/dpkg/info")
    for pkg, meta in sorted(status.items()):
        if only and pkg not in only:
            continue
        md5 = next((p for p in (os.path.join(info, f"{pkg}:{meta['arch']}.md5sums"),
                                os.path.join(info, f"{pkg}.md5sums")) if os.path.exists(p)), None)
        conf = meta["conffiles"]
        if not md5 and not (include_config and conf):
            continue
        t.packages += 1
        for line in (_read(md5) or "").splitlines() if md5 else []:
            want, _, rel = line.partition("  ")
            if not rel or len(want) != 32:
                continue
            path = "/" + rel
            if path in conf:
                if not include_config:
                    t.config_skipped += 1
                continue
            if _excluded(path, rules):
                t.excluded += 1
                continue
            if path in div and div[path][1] != pkg:
                path = div[path][0]
            check(t, pkg, meta["version"], "dpkg", path, "md5", want)
        if include_config:
            for path, want in conf.items():
                if len(want) == 32:
                    check(t, pkg, meta["version"], "dpkg", path, "md5", want)
    return True


# ── Alpine ───────────────────────────────────────────────────────────────────
def verify_apk(t, only=None):
    text = _read(os.path.join(t.root, "lib/apk/db/installed"))
    if not text:
        return False
    pkg = ver = folder = ""
    pending = None                       # the R: path waiting for its Z: line
    counted = set()
    for line in text.splitlines() + [""]:
        if not line:
            pkg = ver = folder = ""
            pending = None
            continue
        k, v = line[:2], line[2:]
        if k == "P:":
            pkg = v
        elif k == "V:":
            ver = v
        elif k == "F:":
            folder, pending = v, None
        elif k == "R:":
            pending = f"{folder}/{v}" if folder else v
        elif k == "Z:" and pending and pkg and (not only or pkg in only):
            if v.startswith("Q1"):        # Q1 = base64 SHA-1 of the content (apk writes Q2 for SHA-256)
                algo, fmt = "sha1", "b64"
            elif v.startswith("Q2"):
                algo, fmt = "sha256", "b64"
            else:
                pending = None
                continue
            if pkg not in counted:
                counted.add(pkg)
                t.packages += 1
            if not os.path.islink(os.path.join(t.root, pending)):   # apk hashes a symlink's target PATH: skip those
                check(t, pkg, ver, "apk", pending, algo, v[2:], fmt)
            pending = None
    return True


# ── Python ───────────────────────────────────────────────────────────────────
def verify_python(t, only=None, owned=(), rpm=False):
    """*.dist-info/RECORD under the system site directories. dist-infos owned by an OS package are skipped: dpkg/apk/rpm
    already check those files, and Debian strips RECORD from them anyway. Two distributions can install into the same
    folder (PyJWT and `jwt` both own jwt/): when a file matches ANOTHER installed distribution's RECORD it is reported
    as replaced by that one, not as an unexplained change."""
    records, seen = [], set()
    for pat in sources.PY_DIRS:
        for site in glob.glob(os.path.join(t.root, pat)):
            for rec in sorted(glob.glob(os.path.join(site, "*.dist-info", "RECORD"))):
                di = os.path.dirname(rec)
                rel_di = "/" + os.path.relpath(di, t.root)
                real = os.path.realpath(di)
                if real in seen or rel_di in owned or (rpm and sources.rpm_owned(rel_di)):
                    continue
                seen.add(real)
                pkg, _, ver = os.path.basename(di)[:-len(".dist-info")].partition("-")
                rows = []
                for row in csv.reader(io.StringIO(_read(rec) or "")):
                    if len(row) < 2 or not row[1] or "=" not in row[1]:
                        continue                    # RECORD itself, .pyc files: no hash recorded
                    algo, _, want = row[1].partition("=")
                    if algo not in ("sha256", "sha384", "sha512"):
                        continue
                    target = os.path.normpath(os.path.join(site, row[0]))
                    if t.root != "/" and not target.startswith(os.path.normpath(t.root).rstrip("/") + "/"):
                        continue                    # a RECORD path that climbs out of the scanned root
                    rows.append(("/" + os.path.relpath(target, t.root), algo, want))
                records.append((pkg, ver, rows))
    owners = {}
    for pkg, ver, rows in records:
        for rel, algo, want in rows:
            owners.setdefault(rel, []).append((pkg, ver, algo, want))
    for pkg, ver, rows in records:
        if only and pkg not in only and pkg.replace("_", "-") not in only:
            continue
        t.packages += 1
        before = len(t.items)
        for rel, algo, want in rows:
            check(t, pkg, ver, "PyPI", rel, algo, want, "b64url")
        for item in t.items[before:]:
            if item["state"] != "changed":
                continue
            full = os.path.join(t.root, item["path"].lstrip("/")) if os.path.abspath(t.root) == "/" \
                else collect.in_root(t.root, item["path"])
            for opkg, over, oalgo, owant in owners.get(item["path"], []):
                got = digest(full, oalgo) if full else None
                if opkg != pkg and got and base64.urlsafe_b64encode(bytes.fromhex(got)).decode().rstrip("=") == owant:
                    item["by"] = f"{opkg} {over}"
                    break
    return bool(records)


# ── rpm ──────────────────────────────────────────────────────────────────────
RPMFILE_CONFIG, RPMFILE_GHOST = 1, 64
RPMVERIFY_FILEDIGEST = 1        # cleared by %verify(not md5 …): a file the package itself rewrites after install


def rpm_files(h):
    """A header parsed with collect.rpm_header(digests=True) → (name, version-release,
    [(path, digest, algo, flags, state, mode, verifyflags)]). Missing columns default to "verify everything"."""
    m, paths = h.get("file_meta") or {}, h.get("files") or []
    n = len(paths)
    col = lambda key, default: m.get(key) or [default] * n  # noqa: E731
    files = list(zip(paths, col("digests", ""), [m.get("algo")] * n, col("flags", 0), col("states", 0),
                     col("modes", 0), col("verifyflags", -1)))
    return h["name"], h["version"] + (f"-{h['release']}" if h.get("release") else ""), files


def rpm_headers(root):
    """Every package header with its file digests, from the same database read the CVE scan does → (list, error).
    None when there is no rpm database."""
    details = []
    fmt, _rows, err = collect.rpm_packages(root, details=details)
    if fmt is None:
        return None, None
    return details, err


def verify_rpm(t, only=None, include_config=False):
    headers, err = rpm_headers(t.root)
    if err:
        t.notes.append(err)
        t.status = "partial"
        return False
    if headers is None:
        return False
    for h in headers:
        if only and h["name"] not in only:
            continue
        name, ver, files = rpm_files(h)
        if not files:
            continue
        t.packages += 1
        for path, want, algo, flags, state, mode, vflags in files:
            if flags & RPMFILE_GHOST or not want or not algo or (mode and not stat.S_ISREG(mode)):
                continue                       # ghosts, directories, symlinks: nothing to hash
            if state or not vflags & RPMVERIFY_FILEDIGEST:
                t.excluded += 1                # not installed (nodocs, languages, other arch), or the package says
                continue                       # not to check its digest (`rpm -V` skips it too)
            if flags & RPMFILE_CONFIG and not include_config:
                t.config_skipped += 1
                continue
            check(t, name, ver, "rpm", path, algo, want)
    return True


CHECKERS = [("dpkg", verify_dpkg), ("apk", verify_apk), ("rpm", verify_rpm)]


def verify_target(t, only=None, include_config=False):
    t0 = time.time()
    osr = _read(os.path.join(t.root, "etc/os-release")) or _read(os.path.join(t.root, "usr/lib/os-release"))
    t.os = sources.os_identity({"etc/os-release": osr})[1] if osr else "unknown OS"
    used = []
    for name, fn in CHECKERS:
        ok = fn(t, only) if name == "apk" else fn(t, only, include_config)
        if ok:
            used.append(name)
    owned = sources._os_owned(t.root, _read(os.path.join(t.root, "lib/apk/db/installed")))
    if verify_python(t, only, owned, rpm="rpm" in used):
        used.append("pip")
    if not used:
        t.notes.append("no package checksums found (dpkg md5sums, apk db, rpm database or pip RECORD)")
        t.status = "partial"
    if t.unreadable:
        t.notes.append(f"{t.unreadable} files unreadable (run as root to check them)")
    t.notes.append(f"{', '.join(used) or 'nothing'} checked in {time.time() - t0:.1f}s")
    t.items.sort(key=lambda i: (i["state"] != "changed", not i["high"], i["package"], i["path"]))
    return t


# ── containers ───────────────────────────────────────────────────────────────
def containers(errors):
    """Every running Docker container, read in place through /proc/<pid>/root (root only). Unlike a CVE scan this
    is per container, not per image: a change made inside one running container is exactly what to catch."""
    if not shutil.which("docker"):
        raise RuntimeError("docker CLI not found: `sieve verify --containers` checks running Docker containers")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("`sieve verify --containers` needs root: container roots under /proc/<pid>/root are root-only")
    ids = subprocess.run(["docker", "ps", "-q", "--no-trunc"], capture_output=True, text=True).stdout.split()
    out = []
    for cid in ids:
        r = subprocess.run(["docker", "inspect", "-f", "{{.Name}}|{{.Config.Image}}|{{.State.Pid}}", cid],
                           capture_output=True, text=True)
        f = r.stdout.strip().split("|")
        if len(f) != 3 or f[2] in ("", "0"):
            errors.append(f"{cid[:12]}: could not find its process")
            continue
        name, image, pid = f[0].lstrip("/"), f[1], f[2]
        root = f"/proc/{pid}/root"
        if not os.path.isdir(root + "/"):
            errors.append(f"{name}: container root not readable")
            continue
        t = Target(f"{name} ({image})", "container", root)
        try:
            for line in open(f"/proc/{pid}/mountinfo"):
                mp = line.split()[4].encode().decode("unicode_escape")
                if mp != "/":
                    t.skip_prefixes.append(mp)
        except OSError:
            pass
        out.append(t)
    return out


# ── output ───────────────────────────────────────────────────────────────────
def _cut(s, n):
    s = str(s)
    return s if len(s) <= n else "…" + s[-(n - 1):]


def table(items, limit):
    rows = [("STATE", "", "PACKAGE", "FILE", "TARGET")]
    shown = items if not limit else items[:limit]
    for i in shown:
        path = _cut(i["path"], 60) + (f"  (now {i['by']}'s file)" if i.get("by") else "")
        rows.append((i["state"], "⚠" if i["high"] and i["state"] == "changed" else "",
                     _cut(f"{i['package']} {i['version']}", 34), path, _cut(i["target"], 28)))
    w = [max(len(r[c]) for r in rows) for c in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(w[k]) for k, c in enumerate(r)).rstrip() for r in rows]
    if limit and len(items) > limit:
        lines.append(f"… {len(items) - limit} more (use --limit 0 to show all, or --json)")
    return "\n".join(lines)


def sarif(targets, items, errors):
    from .sarif import INFO_URI, SCHEMA
    rules = [
        {"id": "sieve-verify/changed-critical", "name": "ChangedCriticalFile",
         "shortDescription": {"text": "A security-critical packaged file no longer matches its package checksum"},
         "help": {"text": "A binary, PAM module or core library differs from what its package installed. Find out "
                          "who changed it; reinstall the package if nobody can say."},
         "defaultConfiguration": {"level": "error"},
         "properties": {"tags": ["security", "integrity"], "precision": "high", "security-severity": "8.0"}},
        {"id": "sieve-verify/changed", "name": "ChangedFile",
         "shortDescription": {"text": "A packaged file no longer matches its package checksum"},
         "help": {"text": "The file differs from what its package installed (a local edit, a failed upgrade, or "
                          "tampering)."},
         "defaultConfiguration": {"level": "warning"},
         "properties": {"tags": ["security", "integrity"], "precision": "high", "security-severity": "5.0"}},
        {"id": "sieve-verify/missing", "name": "MissingFile",
         "shortDescription": {"text": "A packaged file is missing"},
         "help": {"text": "A file the package installed is gone."},
         "defaultConfiguration": {"level": "note"},
         "properties": {"tags": ["integrity"], "precision": "high", "security-severity": "2.0"}}]
    index = {r["id"]: n for n, r in enumerate(rules)}
    results = []
    for i in items:
        rid = "sieve-verify/missing" if i["state"] == "missing" else \
            "sieve-verify/changed-critical" if i["high"] else "sieve-verify/changed"
        key = f"{i['target']}|{i['path']}|{i['state']}"
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": rules[index[rid]]["defaultConfiguration"]["level"],
            "message": {"text": f"{i['path']} ({i['package']} {i['version']}, {i['ecosystem']}) is {i['state']} "
                                f"in {i['target']}" + (f": it is now {i['by']}'s copy of that file." if i.get("by")
                                                       else ".")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f"{i['target']}{i['path']}"},
                                                "region": {"startLine": 1}},
                           "logicalLocations": [{"name": i["package"], "fullyQualifiedName": f"{i['target']}/{i['package']}",
                                                 "kind": "package"}]}],
            "partialFingerprints": {"sieveVerify/v1": hashlib.sha256(key.encode()).hexdigest()},
            "properties": dict(i)})
    notes = [{"level": "error", "message": {"text": e}} for e in errors]
    notes += [{"level": "warning", "message": {"text": f"{t['name']}: {t['status']}: {'; '.join(t['notes'])}"}}
              for t in targets if t["status"] != "ok"]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "sieve", "version": __version__, "semanticVersion": __version__,
                            "informationUri": INFO_URI, "rules": rules}},
        "invocations": [{"executionSuccessful": not errors, "toolExecutionNotifications": notes}],
        "results": results, "properties": {"targets": targets}}]}


def main(args):
    """`sieve verify` → exit code: 1 a packaged file changed; 2 nothing could be checked (or a container could not
    be read) and nothing changed; 0 otherwise. Missing files are reported but don't fail the run: minimal images
    delete docs and translations after install, so "missing" there is usually the image build, not an attacker."""
    def warn(m):
        print(f"sieve: {m}", file=sys.stderr)
    only = {p.strip() for p in (args.packages or "").split(",") if p.strip()} or None
    errors, targets = [], []
    if not args.containers or args.host:
        name = "host" if os.path.abspath(args.root) == "/" else f"host ({args.root})"
        targets.append(Target(name, "host", args.root))
    if args.containers:
        try:
            targets += containers(errors)
        except Exception as e:  # noqa: BLE001
            errors.append(f"containers: {e}")
    items = []
    tds = []
    for t in targets:
        t.all_missing = getattr(args, "all_missing", False)
        verify_target(t, only, args.include_config)
        items += [dict(i, target=t.name) for i in t.items]
        tds.append(t.as_dict())
        t.items = []                       # one container's list at a time
    items.sort(key=lambda i: (i["state"] != "changed", not i["high"], i["target"], i["package"], i["path"]))
    changed = sum(1 for i in items if i["state"] == "changed")
    missing = len(items) - changed
    critical = sum(1 for i in items if i["state"] == "changed" and i["high"])
    if args.sarif:
        json.dump(sarif(tds, items, errors), sys.stdout, indent=1)
        sys.stdout.write("\n")
    elif args.json:
        json.dump({"sieve": __version__, "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "targets": tds, "errors": errors,
                   "summary": {"files": sum(t["files"] for t in tds), "changed": changed, "critical": critical,
                               "missing": missing},
                   "items": items}, sys.stdout, indent=1)
        sys.stdout.write("\n")
    else:
        for t in tds:
            flag = "" if t["status"] == "ok" else f" [{t['status']}]"
            extra = [f"{t['config_skipped']} config files skipped"] if t["config_skipped"] else []
            extra += [f"{t['excluded']} not installed or not checked by design (dpkg path-exclude, rpm nodocs / "
                      f"%verify)"] if t["excluded"] else []
            extra += [f"{t['trimmed']} docs/man/locale files trimmed by the image (--all-missing lists them)"] \
                if t["trimmed"] else []
            extra += [f"{t['under_mounts']} under mounted volumes skipped"] if t["under_mounts"] else []
            note = "; ".join(extra + t["notes"])
            print(f"# {t['name']}: {t['os']}, {t['packages']} packages, {t['files']} files{flag}  ({note})")
        if items:
            print()
            print(table(items, args.limit))
        print()
        print(f"{changed} changed ({critical} security-critical), {missing} missing, "
              f"{sum(t['files'] for t in tds)} files checked")
    for e in errors:
        warn(e)
    if changed:
        return 1
    if errors or all(t["status"] != "ok" and not t["files"] for t in tds):
        return 2
    return 0
