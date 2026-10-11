"""Where package lists come from: the local machine, or the running containers on it."""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile

from . import collect, osv
from .collect import rpm_packages          # standard library only, shared with the standalone collector

COLLECTOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect.py")
NPM_DIRS = ["usr/lib/node_modules", "usr/local/lib/node_modules"]
NPMRC = ["etc/npmrc", "usr/etc/npmrc", "usr/local/etc/npmrc", "root/.npmrc"]
PY_DIRS = ["usr/lib/python3*/site-packages", "usr/lib/python3*/dist-packages", "usr/lib/python3/dist-packages",
           "usr/lib64/python3*/site-packages", "usr/local/lib/python3*/site-packages",
           "usr/local/lib/python3*/dist-packages"]


class Target:
    """One scanned thing: the host, or one container image."""

    def __init__(self, name, kind):
        self.name, self.kind = name, kind
        self.os = ""
        self.packages = 0
        self.pkgs = []                  # match() input
        self.notes = []
        self.status = "ok"
        self.inuse = None               # collect.inuse_report() for this target, if it could be read

    def as_dict(self):
        d = {"name": self.name, "kind": self.kind, "os": self.os, "packages": self.packages,
             "status": self.status, "notes": self.notes}
        if self.inuse is not None:
            d["in_use"] = {"processes_read": self.inuse["seen"], "processes": self.inuse["total"]}
        return d


def os_identity(files):
    """files: {relpath: text} → (ecosystem, label, [(src, srcver, bin, binver)])."""
    osr = osv.kv(files.get("etc/os-release") or files.get("usr/lib/os-release") or "")
    eco, label = osv.ecosystem(osr, (files.get("etc/alpine-release") or "").strip())
    if files.get("lib/apk/db/installed"):
        entries = osv.parse_apk(files["lib/apk/db/installed"])
    elif files.get("rpm"):
        entries = osv.parse_rpm(files["rpm"])
    else:
        entries = osv.parse_dpkg(files.get("var/lib/dpkg/status") or "")
    return eco, label, entries


def split_kernel(entries, keep=False):
    """→ (entries without kernel packages, number skipped)."""
    if keep:
        return entries, 0
    rest = [e for e in entries if not osv.KERNEL_PKG.match(e[2])]
    return rest, len(entries) - len(rest)


def _read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def _os_owned(root, apk_db):
    """Directories that the OS package manager installed. Python packages there come from a dpkg/apk package and
    are already covered by the distro's advisories (with its backported fixes); asking PyPI about them as well would
    report fixes the distro has already applied."""
    owned = set()
    for lst in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):
        for line in (_read(lst) or "").splitlines():
            if line.endswith((".dist-info", ".egg-info")):
                owned.add(line.strip())
    folder = ""
    for line in (apk_db or "").splitlines():
        if line.startswith("F:"):
            folder = "/" + line[2:]
            if folder.endswith((".dist-info", ".egg-info")):
                owned.add(folder)
    return owned


def rpm_owned(path):
    """On rpm distros pip and `npm -g` install into /usr/local (Fedora 27+, EL8+); a dist-info under /usr/lib*/python3*
    or a package under /usr/lib/node_modules came with an rpm, whose advisories already cover it."""
    return path.startswith(("/usr/lib/python", "/usr/lib64/python", "/usr/lib/node_modules/"))


def rpm_list(root="/", files=None):
    """→ (rpm list text or "", error or None). Reads the database directly; with an unreadable one on the live
    machine, falls back to the rpm binary when there is one."""
    _fmt, rows, err = rpm_packages(root, files)
    if err and os.path.abspath(root) == "/" and shutil.which("rpm"):
        try:
            out = subprocess.run(["rpm", "-qa", "--qf", "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t"
                                  "%{SOURCERPM}\\n"], capture_output=True, text=True, timeout=300).stdout
            rows = sorted({l.replace("(none)", "") for l in out.splitlines() if l and not l.startswith("gpg-pubkey\t")})
            if rows:
                return "\n".join(rows), None
        except (OSError, subprocess.SubprocessError):
            pass
    return "\n".join(rows), err


def npm_global(root="/"):
    """Globally installed npm packages → [(name, version, path)]: the usual global prefixes plus any `prefix=` set in
    an npmrc. Read straight from package.json, so node doesn't need to be installed (or trusted) to scan it."""
    dirs = list(NPM_DIRS)
    for rc in NPMRC:
        m = re.search(r"^\s*prefix\s*=\s*(\S+)", _read(os.path.join(root, rc)) or "", re.M)
        if m and m.group(1).startswith("/"):
            dirs.append(m.group(1).lstrip("/") + "/lib/node_modules")
    from .projects import node_modules
    out, seen = [], set()
    for d in dirs:
        full = os.path.join(root, d)
        real = os.path.realpath(full)
        if real in seen or not os.path.isdir(full):
            continue
        seen.add(real)
        out += [(n, v, "/" + os.path.relpath(p, root)) for n, v, p in node_modules(full, with_path=True)]
    return out


def _npm_owned(root):
    """Top-level global npm packages that dpkg installed (Debian's `npm` package ships some): its advisories cover them."""
    owned = set()
    for lst in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):
        for line in (_read(lst) or "").splitlines():
            m = re.match(r"^(.*/node_modules/(?:@[^/]+/)?[^/@]+)$", line.strip())
            if m and any(m.group(1).startswith("/" + d + "/") for d in NPM_DIRS):
                owned.add(m.group(1))
    return owned


def python_packages(root="/"):
    """[(name, version, path)] from dist-info / egg-info under the usual system site directories."""
    out, seen = [], set()
    for pat in PY_DIRS:
        for d in glob.glob(os.path.join(root, pat)):
            for meta in glob.glob(os.path.join(d, "*.dist-info", "METADATA")) + \
                    glob.glob(os.path.join(d, "*.egg-info", "PKG-INFO")) + glob.glob(os.path.join(d, "*.egg-info")):
                path = os.path.dirname(meta) if meta.endswith(("METADATA", "PKG-INFO")) else meta
                real = os.path.realpath(path)
                if real in seen or (os.path.isdir(meta)):
                    continue
                seen.add(real)
                nv = osv.parse_pymeta((_read(meta) or "")[:4096])
                if nv:
                    out.append((nv[0], nv[1], "/" + os.path.relpath(path, root)))
    return out


def host(root="/", kernel=False):
    """The local machine: OS packages from dpkg/apk/rpm, Python packages pip installed outside the OS, and global
    npm packages."""
    t = Target("host", "host")
    files = {}
    for rel in ("etc/os-release", "usr/lib/os-release", "etc/alpine-release", "var/lib/dpkg/status",
                "lib/apk/db/installed"):
        txt = _read(os.path.join(root, rel))
        if txt is not None:
            files[rel] = txt
    rpm_files = {}                              # {path: package}, filled by the same rpmdb read, for in-use
    rpm, rpm_err = ("", None) if files.get("var/lib/dpkg/status") or files.get("lib/apk/db/installed") \
        else rpm_list(root, rpm_files)
    if rpm:
        files["rpm"] = rpm
    eco, label, entries = os_identity(files)
    t.os = label
    entries, skipped = split_kernel(entries, kernel)
    if skipped:
        t.notes.append(f"{skipped} kernel packages skipped (use --kernel to include them)")
    if rpm_err:
        t.notes.append(rpm_err)
        t.status = "partial"
    if entries and not eco:
        t.notes.append(f"{label}: OSV has no advisory feed for this OS; OS packages not checked")
        t.status = "partial"
    elif not entries and not rpm_err:
        t.notes.append("no dpkg, apk or rpm package database found")
    pkgs = osv.os_packages(eco, entries) if eco else []
    owned = _os_owned(root, files.get("lib/apk/db/installed"))
    py = [p for p in python_packages(root) if p[2] not in owned and not (rpm and rpm_owned(p[2]))]
    pkgs += [("PyPI", n, v, n, v) for n, v, _ in py]
    npm_owned = _npm_owned(root)
    npm = [p for p in npm_global(root) if p[2] not in npm_owned and not any(p[2].startswith(o + "/") for o in npm_owned)
           and not (rpm and rpm_owned(p[2]))]
    if npm:
        t.notes.append(f"{len(npm)} global npm packages")
    pkgs += [("npm", n, v, n, v) for n, v, _ in npm]
    t.pkgs = sorted(set(pkgs))
    t.packages = len(entries) + len(py) + len(npm)
    # /proc here is this process's own view: with --root it belongs to another filesystem (sieve's own container),
    # whose libraries would be matched against the host's package lists and reported as loaded when they aren't
    if os.path.realpath(root) != "/":
        t.notes.append("in-use not checked with --root (run sieve on the machine itself for that)")
    else:
        try:
            t.inuse = collect.inuse_report(root, collect.host_pids(), rpm_files=rpm_files)
        except Exception as e:  # noqa: BLE001 — in-use is extra information, never a reason to fail the scan
            t.notes.append(f"in-use check failed: {type(e).__name__}: {e}")
    return t


# ── containers ───────────────────────────────────────────────────────────────
NAMED = {"etc_os-release": "etc/os-release", "usr_lib_os-release": "usr/lib/os-release",
         "etc_alpine-release": "etc/alpine-release", "var_lib_dpkg_status": "var/lib/dpkg/status",
         "lib_apk_db_installed": "lib/apk/db/installed"}


def image_target(name, files, kernel=False):
    """One image's collected files ({relname: bytes}) → Target with its match() input."""
    t = Target(name, "container")
    osf = {k[3:]: v for k, v in files.items() if k.startswith("os/")}
    text = {NAMED[k]: v.decode("utf-8", "replace") for k, v in osf.items() if k in NAMED}
    statusd = [v.decode("utf-8", "replace") for k, v in osf.items() if k.startswith("statusd_")]
    if statusd and not text.get("var/lib/dpkg/status"):
        text["var/lib/dpkg/status"] = "\n\n".join(statusd)          # distroless keeps one stanza per file
    rpm = osf.get("rpm_packages", b"").decode("utf-8", "replace")
    if rpm.startswith("#error"):
        t.notes.append(rpm.splitlines()[0][7:])
        t.status = "partial"
    elif rpm:
        text["rpm"] = rpm
    eco, label, entries = os_identity(text)
    entries, skipped = split_kernel(entries, kernel)
    if skipped:
        t.notes.append(f"{skipped} kernel packages skipped (containers run the host kernel)")
    if entries and not eco:
        t.notes.append(f"{label}: OSV has no advisory feed for this OS; OS packages not checked")
    pkgs = osv.os_packages(eco, entries) if eco else []
    unread = 0
    for k, v in files.items():
        kind = k.split("/", 1)[0]
        body = v.split(b"\n", 1)[1] if b"\n" in v else b""
        if kind in ("py", "npm"):                       # the collector already reduced these to name\nversion
            if text.get("rpm") and rpm_owned(v.split(b"\n", 1)[0].decode("utf-8", "replace")):
                continue                                # came with an rpm: its advisories cover it
            nv = body.decode("utf-8", "replace").split("\n")
            if len(nv) == 2 and nv[0] and nv[1]:
                e = "PyPI" if kind == "py" else "npm"
                pkgs.append((e, nv[0], nv[1], nv[0], nv[1]))
        elif kind == "go":
            gover, deps = osv.parse_gobuild(body)
            if not gover:
                unread += 1
                continue
            gv = gover.split()[0].removeprefix("go")
            pkgs.append(("Go", "stdlib", gv, "stdlib", gv))
            pkgs += [("Go", m, ver, m, ver) for m, ver in deps]
        elif kind == "rust":
            pkgs += [("crates.io", c, ver, c, ver) for c, ver in osv.parse_rustdeps(body)]
        elif k == "inuse":
            try:
                t.inuse = json.loads(v)
            except ValueError:
                t.notes.append("in-use data from the collector could not be read")
    if unread:
        t.notes.append(f"{unread} Go binaries older than Go 1.18 not read")
    t.os = label if (entries or eco) else "no OS packages"
    t.pkgs = sorted(set(pkgs))
    # installed packages, not OSV queries (an rpm is asked about under its binary AND source name)
    t.packages = len(entries) + len({p for p in t.pkgs if p[0] in ("PyPI", "npm", "Go", "crates.io")})
    return t


def read_collected(stream, errs, kernel=False):
    """Collector tar stream → yields Targets one image at a time (members arrive grouped by image), so only one
    image's files are held at once. Collector errors are appended to `errs`."""
    cur, files = None, {}

    def done():
        name = files.pop("IMAGE", b"?").decode("utf-8", "replace")
        return image_target(name, files, kernel)
    with tarfile.open(fileobj=stream, mode="r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            data = tf.extractfile(m).read()
            if m.name == "ERRORS":
                errs += [line for line in data.decode("utf-8", "replace").splitlines() if line]
                continue
            n, _, rest = m.name.partition("/")
            if not rest:
                continue                                # metadata a newer collector may add
            if n != cur:
                if files:
                    yield done()
                cur, files = n, {}
            files[rest] = data
    if files:
        yield done()


def run_collector():
    """Start the collector on this machine → (Popen, stdout stream). Needs root and the docker CLI."""
    if not shutil.which("docker"):
        raise RuntimeError("docker CLI not found: `sieve containers` scans running Docker containers on this machine")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise RuntimeError("`sieve containers` needs root: container roots under /proc/<pid>/root are root-only")
    p = subprocess.Popen([sys.executable, "-I", COLLECTOR], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p, p.stdout


def collector_source():
    with open(COLLECTOR, encoding="utf-8") as f:
        return f.read()
