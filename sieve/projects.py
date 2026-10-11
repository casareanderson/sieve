"""Projects on disk: lockfiles, node_modules trees and Python environments under a directory.

`sieve path DIR` walks DIR (skipping .git, at most --depth levels) and reads what a project already pins:

  package-lock.json / npm-shrinkwrap.json   lockfileVersion 1 (nested "dependencies") and 2/3 ("packages")
  yarn.lock                                 classic (v1) and berry (v2+)
  pnpm-lock.yaml                            lockfileVersion 5.x, 6.x and 9.x, read line by line (no YAML library)
  node_modules/                             every installed package.json, nested ones included
  requirements*.txt                         `name==version` pins only (ranges can't be matched to one version)
  poetry.lock, uv.lock                      [[package]] name + version
  site-packages / dist-packages             *.dist-info METADATA, so a virtualenv is covered too

The same (ecosystem, name, version) found in several places is asked about once. A lockfile that exists but can't
be read (an unknown pnpm lockfileVersion, broken JSON) is reported in the target's notes and marks it partial: an
empty answer from a file sieve didn't understand would look like a clean project.
"""
import json
import os
import re

from . import osv
from .sources import Target

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
_NOT_A_VERSION = re.compile(r"[:/\s]|^(file|link|workspace|portal|git|github|http)")


def _read(path, limit=64 << 20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def _ok(version):
    """A concrete registry version, not a path, URL, git ref or workspace link."""
    return bool(version) and not _NOT_A_VERSION.search(version)


def pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# ── npm ──────────────────────────────────────────────────────────────────────
def parse_package_lock(text):
    """package-lock.json / npm-shrinkwrap.json → [(name, version)]. Raises ValueError if it isn't one."""
    d = json.loads(text)
    out = []
    pk = d.get("packages")
    if isinstance(pk, dict) and pk:                       # lockfileVersion 2 and 3
        for key, e in pk.items():
            if not key or not isinstance(e, dict) or e.get("link"):
                continue                                  # "" is the project itself; links point at workspaces
            name = e.get("name") or key.rsplit("node_modules/", 1)[-1]
            if _ok(e.get("version")) and "node_modules/" in key:
                out.append((name, e["version"]))
        return out

    def walk(deps):                                       # lockfileVersion 1: nested "dependencies"
        for name, e in (deps or {}).items():
            if isinstance(e, dict):
                if _ok(e.get("version")):
                    out.append((name, e["version"]))
                walk(e.get("dependencies"))
    if "dependencies" not in d and "lockfileVersion" not in d:
        raise ValueError("no packages or dependencies")
    walk(d.get("dependencies"))
    return out


def _spec_name(spec):
    """'@scope/name@^1.2', 'name@npm:^1.0', '"name@1"' → 'name' (or '@scope/name')."""
    spec = spec.strip().strip('"').strip("'")
    if spec.startswith("@"):
        scope, _, rest = spec[1:].partition("/")
        return "@" + scope + "/" + rest.split("@", 1)[0]
    return spec.split("@", 1)[0]


def parse_yarn_lock(text):
    """yarn.lock, classic or berry → [(name, version)]."""
    out, names = [], []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():                         # a header: one or more specs, ending in ':'
            names = []
            if line.startswith("__metadata"):
                continue
            for spec in line.rstrip(":").split(","):
                s = spec.strip().strip('"')
                if any(x in s for x in ("@workspace:", "@link:", "@portal:", "@file:")):
                    continue
                names.append(_spec_name(s))
            continue
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?\s*$', line)
        if m and names and _ok(m.group(1)):
            out.append((names[0], m.group(1)))
            names = []                                    # one version per block
    return out


class Unreadable(ValueError):
    pass


def parse_pnpm_lock(text):
    """pnpm-lock.yaml → [(name, version)], from the `packages:` keys, without a YAML library.
    5.x: '/name/1.2.3' or '/name/1.2.3_peer@1.0.0'   6.x: '/name@1.2.3(peer@1.0.0)'   9.x: 'name@1.2.3(peer@1.0.0)'"""
    m = re.search(r"^lockfileVersion:\s*'?\"?([\d.]+)", text, re.M)
    if not m:
        raise Unreadable("no lockfileVersion")
    major = int(m.group(1).split(".")[0])
    if major not in (5, 6, 9):
        raise Unreadable(f"lockfileVersion {m.group(1)} is not one sieve knows (5, 6 or 9)")
    out, inside = [], False
    for line in text.splitlines():
        if not line.strip():
            continue                                      # blank lines separate entries, they don't end a section
        if not line.startswith(" "):
            inside = line.rstrip() == "packages:"
            continue
        if not inside or not re.match(r"^  \S", line) or not line.rstrip().endswith(":"):
            continue
        key = line.strip()[:-1].strip("'\"")
        if major == 5:
            key = key.lstrip("/")
            name, _, ver = key.rpartition("/")
            ver = ver.split("_", 1)[0]
        else:
            key = key.lstrip("/").split("(", 1)[0]
            at = key.rfind("@")
            if at <= 0:
                continue
            name, ver = key[:at], key[at + 1:]
        if name and _ok(ver):
            out.append((name, ver))
    if not out and re.search(r"^packages:\s*$", text, re.M):
        raise Unreadable("a packages section, but no entries sieve could read")
    return out


def node_modules(path, depth=12, with_path=False):
    """Every package.json directly under a node_modules tree, nested node_modules included → [(name, version)]
    (or [(name, version, package_dir)] with with_path)."""
    out = []

    def visit(nm, d):
        if d < 0:
            return
        try:
            entries = sorted(os.scandir(nm), key=lambda e: e.name)
        except OSError:
            return
        for e in entries:
            if not e.is_dir(follow_symlinks=False) or e.name.startswith("."):
                continue
            pkgs = [e.path]
            if e.name.startswith("@"):                    # scoped: node_modules/@scope/name
                try:
                    pkgs = [x.path for x in os.scandir(e.path) if x.is_dir(follow_symlinks=False)]
                except OSError:
                    pkgs = []
            for p in pkgs:
                nv = osv.parse_npm(_read(os.path.join(p, "package.json"), 1 << 20) or "")
                if nv and _ok(nv[1]):
                    out.append((*nv, p) if with_path else nv)
                inner = os.path.join(p, "node_modules")
                if os.path.isdir(inner):
                    visit(inner, d - 1)
    visit(path, depth)
    return out


# ── Python ───────────────────────────────────────────────────────────────────
def parse_requirements(text):
    """`name==version` pins → [(name, version)]; ranges, URLs, -r/-e/-c lines are skipped."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        line = line.split(";", 1)[0].split(" --hash", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$", line)
        if m:
            out.append((pep503(m.group(1)), m.group(3)))
    return out


def parse_toml_packages(text, skip_local=True):
    """poetry.lock / uv.lock `[[package]]` blocks → [(name, version)]. uv's own project entries (editable, virtual,
    path or directory sources) are skipped: they are your code, not something on PyPI."""
    out = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        block = re.split(r"^\[(?!\[package\])", block, maxsplit=1, flags=re.M)[0]
        n = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        v = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        if not (n and v):
            continue
        src = re.search(r"^source\s*=\s*\{([^}]*)\}", block, re.M)
        if skip_local and src and re.search(r"\b(editable|virtual|path|directory)\s*=", src.group(1)):
            continue
        out.append((pep503(n.group(1)), v.group(1)))
    return out


def site_packages(path):
    """*.dist-info / *.egg-info in one site-packages directory → [(name, version)]."""
    out = []
    try:
        names = os.listdir(path)
    except OSError:
        return out
    for n in names:
        meta = os.path.join(path, n, "METADATA" if n.endswith(".dist-info") else "PKG-INFO")
        if n.endswith((".dist-info", ".egg-info")):
            nv = osv.parse_pymeta((_read(meta, 4096) or ""))
            if nv:
                out.append((pep503(nv[0]), nv[1]))
    return out


# ── the walk ─────────────────────────────────────────────────────────────────
NPM_LOCKS = {"package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock,
             "yarn.lock": parse_yarn_lock, "pnpm-lock.yaml": parse_pnpm_lock}
PY_LOCKS = {"poetry.lock": parse_toml_packages, "uv.lock": parse_toml_packages}


def scan_path(root, depth=8):
    """A directory → Target with its match() input."""
    root = os.path.abspath(root)
    t = Target(f"path:{root}", "path")
    t.os = "project files"
    if not os.path.isdir(root):
        t.status = "error"
        t.notes.append(f"{root}: not a directory")
        return t
    found, read = set(), {}
    base = root.rstrip(os.sep).count(os.sep)

    def add(eco, pairs, label):
        for n, v in pairs:
            found.add((eco, n, v))
        read[label] = read.get(label, 0) + 1

    def bad(path, why):
        t.status = "partial"
        t.notes.append(f"{os.path.relpath(path, root)}: not read ({why})")

    for d, dirs, files in os.walk(root):
        level = d.count(os.sep) - base
        keep = []
        for x in sorted(dirs):
            full = os.path.join(d, x)
            if x in SKIP_DIRS or os.path.islink(full):
                continue
            if x == "node_modules":                       # read as a tree, not walked file by file
                add("npm", node_modules(full), "node_modules")
                continue
            if x in ("site-packages", "dist-packages"):
                add("PyPI", site_packages(full), "site-packages")
                continue
            keep.append(x)
        dirs[:] = keep if level < depth else []
        for f in files:
            p = os.path.join(d, f)
            parser = NPM_LOCKS.get(f) or PY_LOCKS.get(f)
            if parser:
                try:
                    add("npm" if f in NPM_LOCKS else "PyPI", parser(_read(p) or ""), f)
                except (ValueError, Unreadable) as e:
                    bad(p, str(e)[:120])
            elif re.match(r"^requirements.*\.txt$", f):
                add("PyPI", parse_requirements(_read(p) or ""), "requirements")
    if read:
        t.notes.insert(0, "read " + ", ".join(f"{n} {k}" for k, n in sorted(read.items())))
    else:
        t.notes.append("no lockfiles, node_modules or Python environments found")
    t.pkgs = sorted((e, n, v, n, v) for e, n, v in found)
    t.packages = len(t.pkgs)
    return t
