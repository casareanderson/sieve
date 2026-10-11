"""Where package lists come from: the local machine, the running containers on it, or another machine over ssh."""
import json
import os
import shutil
import subprocess
import sys
import tarfile

from . import collect, osv
# standard library only, shared with the standalone collector: local and remote host scans run the same code
from .collect import (HOST_FILES, NPM_DIRS, NPMRC, PY_DIRS, npm_global, npm_owned as _npm_owned,  # noqa: F401
                      os_owned as _os_owned, python_dists, rpm_list, rpm_packages)

COLLECTOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect.py")


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
        self.osinv = None               # (ecosystem, label, "deb"|"apk"|"rpm", entries), for --sbom

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


def _db(files):
    return "apk" if files.get("lib/apk/db/installed") else "rpm" if files.get("rpm") else "deb"


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


def rpm_owned(path):
    """On rpm distros pip and `npm -g` install into /usr/local (Fedora 27+, EL8+); a dist-info under /usr/lib*/python3*
    or a package under /usr/lib/node_modules came with an rpm, whose advisories already cover it."""
    return path.startswith(("/usr/lib/python", "/usr/lib64/python", "/usr/lib/node_modules/"))


def python_packages(root="/"):
    """[(name, version, path)] from dist-info / egg-info under the usual system site directories."""
    return python_dists(root)


def host(root="/", kernel=False):
    """The local machine: OS packages from dpkg/apk/rpm, Python packages pip installed outside the OS, and global
    npm packages."""
    files = {}
    for rel in HOST_FILES:
        txt = _read(os.path.join(root, rel))
        if txt is not None:
            files[rel] = txt
    rpm_files = {}                              # {path: package}, filled by the same rpmdb read, for in-use
    rpm, rpm_err = ("", None) if files.get("var/lib/dpkg/status") or files.get("lib/apk/db/installed") \
        else rpm_list(root, rpm_files)
    if rpm:
        files["rpm"] = rpm
    t = host_target("host", files, python_packages(root), _os_owned(root, files.get("lib/apk/db/installed")),
                    npm_global(root), _npm_owned(root), kernel, rpm_err)
    # /proc here is this process's own view: with --root it belongs to another filesystem (sieve's own container),
    # whose libraries would be matched against the host's package lists and reported as loaded when they aren't.
    # (`sieve remote` runs the same check on the remote machine: collect.host_main.)
    if os.path.realpath(root) != "/":
        t.notes.append("in-use not checked with --root (run sieve on the machine itself for that)")
    else:
        try:
            t.inuse = collect.inuse_report(root, collect.host_pids(), rpm_files=rpm_files)
        except Exception as e:  # noqa: BLE001 — in-use is extra information, never a reason to fail the scan
            t.notes.append(f"in-use check failed: {type(e).__name__}: {e}")
    return t


def host_target(name, files, py, owned, npm, npm_owned, kernel=False, rpm_err=None):
    """files {relpath: text, "rpm": rpm list}, py / npm [(name, version, path)], owned / npm_owned {path} → Target.
    Shared by `host` and `remote`, so both report the same thing for the same machine (an unreadable rpm database is
    partial, never empty, either way)."""
    t = Target(name, "host")
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
    rpm = files.get("rpm")
    t.osinv = (eco, label, _db(files), entries) if entries else None
    py = [p for p in py if p[2] not in owned and not (rpm and rpm_owned(p[2]))]
    pkgs += [("PyPI", n, v, n, v) for n, v, _ in py]
    npm = [p for p in npm if p[2] not in npm_owned and not any(p[2].startswith(o + "/") for o in npm_owned)
           and not (rpm and rpm_owned(p[2]))]
    if npm:
        t.notes.append(f"{len(npm)} global npm packages")
    pkgs += [("npm", n, v, n, v) for n, v, _ in npm]
    t.pkgs = sorted(set(pkgs))
    t.packages = len(entries) + len(py) + len(npm)
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
    t.osinv = (eco, label, _db(text), entries) if entries else None
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


# ── another machine, over ssh ────────────────────────────────────────────────
def read_host(stream, name, kernel=False):
    """`collect.py host`'s tar stream → the remote machine's host Target, in-use report included."""
    files, py, npm, owned, npm_own, rpm_err, inuse, notes = {}, [], [], set(), set(), None, None, []
    with tarfile.open(fileobj=stream, mode="r|gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            data = tf.extractfile(m).read().decode("utf-8", "replace")
            if m.name == "os/rpm_packages":
                if data.startswith("#error"):
                    rpm_err = data.splitlines()[0][7:]
                elif data.strip():
                    files["rpm"] = data
            elif m.name.startswith("os/") and m.name[3:] in NAMED:
                files[NAMED[m.name[3:]]] = data
            elif m.name == "owned":
                owned = {line for line in data.splitlines() if line}
            elif m.name == "inuse":
                try:
                    inuse = json.loads(data)
                except ValueError:
                    notes.append("in-use data from the collector could not be read")
            elif m.name == "inuse_note":
                notes.append(data)
            elif m.name == "npm_owned":
                npm_own = {line for line in data.splitlines() if line}
            elif m.name.startswith(("py/", "npm/")):
                parts = data.split("\n")
                if len(parts) == 3 and parts[1] and parts[2]:
                    (py if m.name.startswith("py/") else npm).append((parts[1], parts[2], parts[0]))
    t = host_target(name, files, py, owned, npm, npm_own, kernel, rpm_err)
    t.inuse = inuse                             # read on the remote machine, where its processes are
    t.notes += notes
    return t


def ssh_command(dest, port=None, identity=None, opts=(), sudo=False, mode=""):
    """argv that runs a script fed on stdin with the remote python3. BatchMode: a key that needs a password, or an
    unknown host key, fails at once instead of hanging on a prompt. -I keeps the remote's cwd and environment out
    of the script's imports. sudo -n never asks for a password (and sieve never holds one)."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
    if port:
        cmd += ["-p", str(port)]
    if identity:
        cmd += ["-i", identity]
    for o in opts:
        cmd += ["-o", o]
    return cmd + ["--", dest, ("sudo -n " if sudo else "") + "python3 -I -" + (f" {mode}" if mode else "")]


def run_remote(cmd, script):
    """Start `cmd` with `script` on its stdin → (Popen, stdout stream). Nothing is written on the remote machine:
    the script arrives on stdin and its tar comes back on stdout."""
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.stdin.write(script.encode())
    p.stdin.close()
    return p, p.stdout


def ssh_error(rc, stderr):
    """A failed ssh run → one line that says what to do about it."""
    text = stderr.decode("utf-8", "replace")
    tail = text.strip().splitlines()[-1:] or [""]
    msg = f"exited {rc}: {tail[0][:200]}"
    if "a password is required" in text:
        msg += " (--sudo needs passwordless sudo for python3 on the remote machine)"
    elif rc == 127 or "python3: not found" in text or "python3: command not found" in text:
        msg += " (the remote machine needs python3)"
    elif rc == 255:
        msg += " (ssh could not connect or authenticate; sieve uses BatchMode, so it needs key auth and a known host key)"
    return msg

