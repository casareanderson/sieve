"""Where package lists come from: the local machine, or the running containers on it."""
import glob
import os
import shutil
import subprocess
import sys
import tarfile

from . import osv
from .collect import rpm_packages          # standard library only, shared with the standalone collector

COLLECTOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect.py")
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

    def as_dict(self):
        return {"name": self.name, "kind": self.kind, "os": self.os, "packages": self.packages,
                "status": self.status, "notes": self.notes}


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
    """On rpm distros pip installs into /usr/local (Fedora 27+, EL8+); a dist-info under /usr/lib*/python3* came with
    an rpm, whose advisories already cover it."""
    return path.startswith(("/usr/lib/python", "/usr/lib64/python"))


def rpm_list(root="/"):
    """→ (rpm list text or "", error or None). Reads the database directly; with an unreadable one on the live
    machine, falls back to the rpm binary when there is one."""
    _fmt, rows, err = rpm_packages(root)
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
    """The local machine: OS packages from dpkg/apk/rpm plus Python packages pip installed outside the OS."""
    t = Target("host", "host")
    files = {}
    for rel in ("etc/os-release", "usr/lib/os-release", "etc/alpine-release", "var/lib/dpkg/status",
                "lib/apk/db/installed"):
        txt = _read(os.path.join(root, rel))
        if txt is not None:
            files[rel] = txt
    rpm, rpm_err = ("", None) if files.get("var/lib/dpkg/status") or files.get("lib/apk/db/installed") \
        else rpm_list(root)
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
    t.pkgs = sorted(set(pkgs))
    t.packages = len(entries) + len(py)
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
            if kind == "py" and text.get("rpm") and rpm_owned(v.split(b"\n", 1)[0].decode("utf-8", "replace")):
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
