"""Package collector for containers, and for a whole machine over ssh. Standalone: no imports from sieve, standard
library only.

Run it as root on a Docker host, either directly or with its source fed on stdin (`python3 -`), for example
over ssh:  sieve collector | ssh root@dockerhost python3 - > packages.tgz ;  sieve containers --from-tar packages.tgz

For each distinct image with a running container it reads the container's real root through /proc/<pid>/root
(this works on every storage driver, including Docker's containerd image store), skips mounted volumes, and
writes a gzipped tar to stdout holding only package metadata. It installs nothing and writes nothing to disk.

  <n>/IMAGE        image name as `docker ps` shows it
  <n>/os/...       os-release, dpkg status (+ distroless status.d), apk db
  <n>/os/rpm_packages  one "name\\tepoch\\tversion\\trelease\\tarch\\tsourcerpm" line per installed rpm, read from
                   the rpm database itself (SQLite, ndb or BerkeleyDB; no rpm binary needed), after a
                   "#format …" line, or a single "#error …" line when the database can't be read
  <n>/py/<i>       "path\\nname\\nversion" from each *.dist-info/METADATA, *.egg-info/PKG-INFO
  <n>/npm/<i>      "path\\nname\\nversion" from each node_modules/<pkg>/package.json
                   (name and version are pulled out here: shipping whole package.json files took one scan to 1.1 GB)
  <n>/go/<i>       256 KB from the Go build-info magic of each Go executable
  <n>/rust/<i>     the .dep-v0 section of each Rust executable built with cargo-auditable
  <n>/inuse        JSON: which of the image's packages have code mapped into a running process of ANY container
                   of that image (see inuse_report)
  ERRORS           one line per image that could not be read

`python3 - host` (what `sieve remote` runs over ssh) collects the machine itself instead, with the same rules as
`sieve host` (sources.host uses the helpers below, so the two can't drift):

  os/...           os-release, alpine-release, dpkg status, apk db
  os/rpm_packages  as above ("#format …" or "#error …" first); falls back to `rpm -qa` when the database can't be read
  owned            one *.dist-info / *.egg-info path per line that dpkg or apk installed
  py/<i>           "path\\nname\\nversion" from each dist-info / egg-info in the system site directories
  npm_owned        one global node_modules package directory per line that dpkg installed
  npm/<i>          "path\\nname\\nversion" for each globally installed npm package (the global prefixes plus any
                   `prefix=` set in an npmrc)
  inuse            JSON: which of the machine's packages have code mapped into a running process (inuse_report),
                   or inuse_note: why it wasn't checked
  accounts         JSON: which accounts have an empty or usable password (state + hash scheme only, never the
                   hash) and the sshd options that decide password logins (accounts_report)
"""
import glob
import io
import json
import mmap
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import re

OS_FILES = ["etc/os-release", "usr/lib/os-release", "etc/alpine-release", "etc/debian_version", "etc/lsb-release",
            "var/lib/dpkg/status", "lib/apk/db/installed"]
MAGIC = b"\xff Go buildinf:"
# a whole machine (`sieve host`, and `python3 - host` for `sieve remote`)
HOST_FILES = ["etc/os-release", "usr/lib/os-release", "etc/alpine-release", "var/lib/dpkg/status",
              "lib/apk/db/installed"]
NPM_DIRS = ["usr/lib/node_modules", "usr/local/lib/node_modules"]
NPMRC = ["etc/npmrc", "usr/etc/npmrc", "usr/local/etc/npmrc", "root/.npmrc"]
NOT_A_VERSION = re.compile(r"[:/\s]|^(file|link|workspace|portal|git|github|http)")
PY_DIRS = ["usr/lib/python3*/site-packages", "usr/lib/python3*/dist-packages", "usr/lib/python3/dist-packages",
           "usr/lib64/python3*/site-packages", "usr/local/lib/python3*/site-packages",
           "usr/local/lib/python3*/dist-packages"]



def head(path, n):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return None


def pymeta(b):
    name = ver = None
    for line in (b or b"").decode("utf-8", "replace").splitlines():
        if not line.strip():
            break
        if line.startswith("Name:"):
            name = line[5:].strip()
        elif line.startswith("Version:"):
            ver = line[8:].strip()
    return f"{name}\n{ver}".encode() if name and ver else None


def npmmeta(b):
    try:
        d = json.loads(b or b"")
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    n, v = d.get("name"), d.get("version")
    return f"{n}\n{v}".encode() if isinstance(n, str) and isinstance(v, str) and n and v else None


def sh(*a):
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def elf_section(m, want):
    is64, le = m[4] == 2, m[5] == 1
    e = "<" if le else ">"
    if is64:
        shoff, = struct.unpack_from(e + "Q", m, 0x28)
        shent, shnum, shstr = struct.unpack_from(e + "HHH", m, 0x3A)
    else:
        shoff, = struct.unpack_from(e + "I", m, 0x20)
        shent, shnum, shstr = struct.unpack_from(e + "HHH", m, 0x2E)
    if not shoff or shnum == 0 or shstr >= shnum or shoff + shnum * shent > len(m):
        return None

    def section(k):
        o = shoff + k * shent
        if is64:
            name, _t = struct.unpack_from(e + "II", m, o)
            off, size = struct.unpack_from(e + "QQ", m, o + 24)
        else:
            name, _t = struct.unpack_from(e + "II", m, o)
            off, size = struct.unpack_from(e + "II", m, o + 16)
        return name, off, size
    _, stroff, strsize = section(shstr)
    for k in range(shnum):
        name, off, size = section(k)
        if m[stroff + name:stroff + name + len(want) + 1] == want + b"\0":
            return m[off:off + min(size, 4 << 20)]
    return None


# ── rpm (Fedora, RHEL, Rocky, AlmaLinux, CentOS, openSUSE) ───────────────────
# Read straight from the package database, no rpm binary: SQLite (rpm ≥ 4.16: EL9, Fedora 33+), ndb (openSUSE)
# and BerkeleyDB hash (EL7/EL8, Amazon Linux 2). Each record is an rpm header blob; only six tags are needed.
RPM_DBS = ["usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages.db",
           "var/lib/rpm/Packages.db", "usr/lib/sysimage/rpm/Packages", "var/lib/rpm/Packages"]
RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1022: "arch", 1044: "sourcerpm"}


def in_root(root, rel):
    """rel resolved INSIDE root, following symlinks as the container would (an absolute link like
    /var/lib/rpm -> /usr/lib/sysimage/rpm must not land on the host's own files). None if it escapes or loops."""
    parts, done, hops = rel.strip("/").split("/"), [], 0
    while parts:
        p = parts.pop(0)
        if p in ("", "."):
            continue
        if p == "..":
            if done:
                done.pop()
            continue
        cur = os.path.join(root, *done, p)
        if os.path.islink(cur):
            hops += 1
            if hops > 40:
                return None
            t = os.readlink(cur)
            if t.startswith("/"):
                done = []
            parts = t.strip("/").split("/") + parts
            continue
        done.append(p)
    return os.path.join(root, *done)


RPM_FILE_TAGS = (1116, 1117, 1118, 1027)                     # DIRINDEXES, BASENAMES, DIRNAMES, OLDFILENAMES
# for `sieve verify`: FILESTATES, FILEMODES, FILEDIGESTS, FILEFLAGS, FILEVERIFYFLAGS, FILEDIGESTALGO
RPM_DIGEST_TAGS = (1029, 1030, 1035, 1037, 1045, 5011)


def _rpm_strings(store, off, cnt):
    out = []
    for _ in range(cnt):
        end = store.find(b"\0", off)
        if end < 0:
            break
        out.append(store[off:end].decode("utf-8", "replace"))
        off = end + 1
    return out


def rpm_header(blob, files=False, digests=False):
    """Header blob (index count, data length, 16-byte index entries, data store) → {name, version, …} or None.
    files=True also returns the package's file paths under "files" (for the in-use check), from the same parse.
    digests=True (implies files) adds "file_meta": per file, the columns `sieve verify` needs
    {"digests", "algo", "flags", "states", "modes", "verifyflags"}, each a list as long as "files" (or None)."""
    files = files or digests
    try:
        il, dl = struct.unpack_from(">II", blob, 0)
    except struct.error:
        return None
    start = 8 + 16 * il
    if il > 200000 or start + dl > len(blob):
        return None
    store, out, fl = blob[start:start + dl], {}, {}
    for k in range(il):
        tag, typ, off, cnt = struct.unpack_from(">IIII", blob, 8 + 16 * k)
        if (files and tag in RPM_FILE_TAGS or digests and tag in RPM_DIGEST_TAGS) and off < len(store) and cnt < 1000000:
            fl[tag] = list(struct.unpack_from(f">{cnt}i", store, off)) if typ == 4 and off + 4 * cnt <= len(store) \
                else _rpm_strings(store, off, cnt) if typ == 8 \
                else list(struct.unpack_from(f">{cnt}H", store, off)) if typ == 3 and off + 2 * cnt <= len(store) \
                else list(store[off:off + cnt]) if typ in (1, 2) else None
        if tag not in RPM_TAGS or off >= len(store):
            continue
        if typ in (6, 8, 9):                                  # STRING, STRING_ARRAY, I18NSTRING: first string
            end = store.find(b"\0", off)
            out[RPM_TAGS[tag]] = store[off:end if end >= 0 else len(store)].decode("utf-8", "replace")
        elif typ == 4 and off + 4 <= len(store):              # INT32
            out[RPM_TAGS[tag]] = str(struct.unpack_from(">i", store, off)[0])
    if files:
        idx, base, dirs = fl.get(1116), fl.get(1117), fl.get(1118)
        out["files"] = [dirs[i] + b for i, b in zip(idx, base) if 0 <= i < len(dirs)] \
            if idx and base and dirs and len(idx) == len(base) else list(fl.get(1027) or [])
    if digests:
        n = len(out["files"])
        col = lambda tag: fl.get(tag) if fl.get(tag) is not None and len(fl[tag]) == n else None  # noqa: E731
        algo = (fl.get(5011) or [1])[0]
        out["file_meta"] = {"digests": col(1035), "algo": {1: "md5", 2: "sha1", 8: "sha256", 9: "sha384",
                                                           10: "sha512"}.get(algo), "flags": col(1037),
                            "states": col(1029), "modes": col(1030), "verifyflags": col(1045)}
    return out if out.get("name") and out.get("version") else None


def _rpm_sqlite(path):
    """Copy, then open. SQLite resolves symlinks in the path it is given, and /proc/<pid>/root is one: opened in
    place it read the DOCKER HOST's /var/lib/rpm instead of the container's (2026-10-11). A copy made with open()
    goes through the kernel's own resolution. A live WAL (recent installs) is copied with it and replayed."""
    import shutil
    import sqlite3
    import tempfile
    tmp = tempfile.mkdtemp(prefix="sieve-rpm-")
    try:
        db = os.path.join(tmp, "rpmdb.sqlite")
        shutil.copyfile(path, db)
        if os.path.exists(path + "-wal") and os.path.getsize(path + "-wal") > 0:
            shutil.copyfile(path + "-wal", db + "-wal")
        con = sqlite3.connect(db)
        try:
            return [bytes(b) for (b,) in con.execute("select blob from Packages")]
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _rpm_ndb(data):
    """openSUSE's ndb Packages.db: 'RpmP' header, a slot table (pkgidx, block offset, block count; 16-byte blocks),
    each slot pointing at a 'BlbS' blob = 16-byte blob header + the rpm header."""
    if data[:4] != b"RpmP":
        raise ValueError("not an ndb Packages.db")
    slotpages = struct.unpack_from("<I", data, 12)[0]
    out = []
    for o in range(32, min(slotpages * 4096, len(data)), 16):
        magic, idx, blkoff, _blkcnt = struct.unpack_from("<4sIII", data, o)
        if magic != b"Slot" or not idx:
            continue
        b = blkoff * 16
        if data[b:b + 4] != b"BlbS":
            continue
        _m, bidx, _gen, blen = struct.unpack_from("<4sIII", data, b)
        if bidx == idx:
            out.append(data[b + 16:b + 16 + blen])
    return out


def _rpm_bdb(data):
    """BerkeleyDB hash file (EL7/EL8 Packages): data items on hash pages, big ones in chains of overflow pages."""
    if len(data) < 512 or struct.unpack_from("<I", data, 12)[0] != 0x061561:
        raise ValueError("not a BerkeleyDB hash file")
    psize = struct.unpack_from("<I", data, 20)[0]
    if psize < 512 or psize > 65536:
        raise ValueError("bad BerkeleyDB page size")

    def page(n):
        return data[n * psize:(n + 1) * psize]

    def overflow(pgno, total):
        buf, seen = b"", set()
        while pgno and pgno not in seen and len(buf) < total:
            seen.add(pgno)
            p = page(pgno)
            if len(p) < 26 or p[25] != 7:                      # P_OVERFLOW
                break
            nxt, used = struct.unpack_from("<I", p, 16)[0], struct.unpack_from("<H", p, 22)[0]
            buf += p[26:26 + used]
            pgno = nxt
        return buf[:total]
    out = []
    for n in range(1, len(data) // psize):
        p = page(n)
        if p[25] != 13:                                         # P_HASH
            continue
        entries = struct.unpack_from("<H", p, 20)[0]
        offs = [struct.unpack_from("<H", p, 26 + 2 * i)[0] for i in range(entries)]
        for i in range(1, entries, 2):                         # key, data, key, data …
            o = offs[i]
            if o >= psize:
                continue
            if p[o] == 1:                                       # H_KEYDATA: inline
                end = offs[i - 1] if i - 1 >= 0 and offs[i - 1] > o else psize
                out.append(p[o + 1:end])
            elif p[o] == 3:                                     # H_OFFPAGE
                pgno, tlen = struct.unpack_from("<II", p, o + 4)
                out.append(overflow(pgno, tlen))
    return out


def rpm_packages(root="/", files=None, details=None):
    """→ (format, ["name\\tepoch\\tversion\\trelease\\tarch\\tsourcerpm", …], error). ([], None) when there is no
    rpm database at all; an unreadable one is an error, never an empty list. Pass a dict as `files` to also get
    {path: package name} for the in-use check, from the same read. Pass a list as `details` to get each package's
    parsed header with its file digests and flags (rpm_header(digests=True)) for `sieve verify`."""
    for rel in RPM_DBS:
        path = in_root(root, rel)
        if not path or not os.path.isfile(path) or os.path.getsize(path) == 0:
            continue
        try:
            if rel.endswith(".sqlite"):
                fmt, blobs = "sqlite", _rpm_sqlite(path)
            else:
                with open(path, "rb") as f:
                    data = f.read(512 << 20)
                fmt, blobs = ("ndb", _rpm_ndb(data)) if data[:4] == b"RpmP" else ("bdb", _rpm_bdb(data))
        except Exception as e:  # noqa: BLE001
            return "?", [], f"unsupported or unreadable rpm database {rel}: {type(e).__name__}: {e}"
        rows = set()
        for b in blobs:
            h = rpm_header(b, files=files is not None, digests=details is not None)
            if h and details is not None and h["name"] != "gpg-pubkey":
                details.append(dict(h))
            if h and files is not None and h["name"] != "gpg-pubkey":
                files.update(dict.fromkeys(h.pop("files"), h["name"]))
            if h and h["name"] != "gpg-pubkey":
                rows.add("\t".join(h.get(k, "") for k in ("name", "epoch", "version", "release", "arch", "sourcerpm")))
        if blobs and not rows:
            return fmt, [], f"rpm database {rel} ({fmt}) held {len(blobs)} records but none could be read"
        return fmt, sorted(rows), None
    return None, [], None


def rpm_list(root="/", files=None):
    """→ (rpm list text or "", error or None). Reads the database directly; with an unreadable one on the live
    machine, falls back to the rpm binary when there is one. `files`: as for rpm_packages (in-use)."""
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


def os_owned(root, apk_db):
    """Directories that the OS package manager installed. Python packages there come from a dpkg/apk package and
    are already covered by the distro's advisories (with its backported fixes); asking PyPI about them as well would
    report fixes the distro has already applied."""
    owned = set()
    for lst in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):
        for line in (head(lst, 16 << 20) or b"").decode("utf-8", "replace").splitlines():
            if line.endswith((".dist-info", ".egg-info")):
                owned.add(line.strip())
    for line in (apk_db or "").splitlines():
        if line.startswith("F:"):
            folder = "/" + line[2:]
            if folder.endswith((".dist-info", ".egg-info")):
                owned.add(folder)
    return owned


def python_dists(root="/"):
    """[(name, version, path)] from dist-info / egg-info under the usual system site directories."""
    out, seen = [], set()
    for pat in PY_DIRS:
        for d in glob.glob(os.path.join(root, pat)):
            for meta in glob.glob(os.path.join(d, "*.dist-info", "METADATA")) + \
                    glob.glob(os.path.join(d, "*.egg-info", "PKG-INFO")) + glob.glob(os.path.join(d, "*.egg-info")):
                path = os.path.dirname(meta) if meta.endswith(("METADATA", "PKG-INFO")) else meta
                real = os.path.realpath(path)
                if real in seen or os.path.isdir(meta):
                    continue
                seen.add(real)
                nv = pymeta(head(meta, 4096))
                if nv:
                    name, ver = nv.decode().split("\n")
                    out.append((name, ver, "/" + os.path.relpath(path, root)))
    return out


def _text(path, n=1 << 20):
    d = head(path, n)
    return d.decode("utf-8", "replace") if d is not None else None


def node_modules(path, depth=12, with_path=False):
    """Every package.json directly under a node_modules tree, nested node_modules included → [(name, version)]
    (or [(name, version, package_dir)] with with_path). Only concrete registry versions, not paths, URLs or links."""
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
                nv = npmmeta(head(os.path.join(p, "package.json"), 1 << 20))
                if nv:
                    name, ver = nv.decode().split("\n")
                    if not NOT_A_VERSION.search(ver):
                        out.append((name, ver, p) if with_path else (name, ver))
                inner = os.path.join(p, "node_modules")
                if os.path.isdir(inner):
                    visit(inner, d - 1)
    visit(path, depth)
    return out


def npm_global(root="/"):
    """Globally installed npm packages → [(name, version, path)]: the usual global prefixes plus any `prefix=` set in
    an npmrc. Read straight from package.json, so node doesn't need to be installed (or trusted) to scan it."""
    dirs = list(NPM_DIRS)
    for rc in NPMRC:
        m = re.search(r"^\s*prefix\s*=\s*(\S+)", _text(os.path.join(root, rc)) or "", re.M)
        if m and m.group(1).startswith("/"):
            dirs.append(m.group(1).lstrip("/") + "/lib/node_modules")
    out, seen = [], set()
    for d in dirs:
        full = os.path.join(root, d)
        real = os.path.realpath(full)
        if real in seen or not os.path.isdir(full):
            continue
        seen.add(real)
        out += [(n, v, "/" + os.path.relpath(p, root)) for n, v, p in node_modules(full, with_path=True)]
    return out


def npm_owned(root="/"):
    """Top-level global npm packages that dpkg installed (Debian's `npm` package ships some): its advisories cover them."""
    owned = set()
    for lst in glob.glob(os.path.join(root, "var/lib/dpkg/info/*.list")):
        for line in (_text(lst, 16 << 20) or "").splitlines():
            m = re.match(r"^(.*/node_modules/(?:@[^/]+/)?[^/@]+)$", line.strip())
            if m and any(m.group(1).startswith("/" + d + "/") for d in NPM_DIRS):
                owned.add(m.group(1))
    return owned


# ── accounts: who can log in with a password, and can root do it over ssh ──────
# Only the STATE of each password is reported (empty / usable / locked) and its hash scheme; a hash never leaves
# this function, so nothing crackable is written to the tar or printed.
SCHEMES = {"1": "md5", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt", "5": "sha256", "6": "sha512", "7": "scrypt",
           "y": "yescrypt", "gy": "gost-yescrypt", "sha1": "sha1", "md5": "sun-md5"}
SSHD_DEFAULTS = {"permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
                 "permitemptypasswords": "no", "kbdinteractiveauthentication": "yes", "usepam": "no"}


def pw_state(field):
    """/etc/shadow password field → (state, scheme). state: empty | usable | locked."""
    if field == "":
        return "empty", ""
    if field[0] in "!*":
        return "locked", ""
    if field.startswith("$"):
        return "usable", SCHEMES.get(field.split("$")[1], "unknown")
    return "usable", "des" if len(field) == 13 else "unknown"


def sshd_settings(root):
    """→ dict of the sshd options that decide password logins, or None when there's no sshd config. Uses `sshd -T`
    (the effective config) when it can run here as root; otherwise reads the config files, first value wins as in
    sshd, Include followed, and stops at the first Match block (noted, since a Match can loosen things)."""
    conf = os.path.join(root, "etc/ssh/sshd_config")
    if not os.path.isfile(conf):
        return None
    want = set(SSHD_DEFAULTS)
    if os.path.realpath(root) == "/" and hasattr(os, "geteuid") and os.geteuid() == 0:
        exe = shutil.which("sshd") or next((p for p in ("/usr/sbin/sshd", "/usr/bin/sshd") if os.path.isfile(p)), None)
        if exe:
            try:
                r = subprocess.run([exe, "-T"], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    got = dict(SSHD_DEFAULTS)
                    for line in r.stdout.splitlines():
                        k, _, v = line.partition(" ")
                        if k in want:
                            got[k] = v.strip().lower()
                    got["source"] = "sshd -T"
                    return got
            except (OSError, subprocess.SubprocessError):
                pass
    got, seen, match = {}, set(), False

    def read(path, depth=0):
        nonlocal match
        if depth > 8 or path in seen:
            return
        seen.add(path)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            return
        for line in lines:
            parts = line.split("#", 1)[0].replace("=", " ", 1).split()
            if not parts:
                continue
            k = parts[0].lower()
            if k == "match":
                match = True
                return
            if k == "include":
                for pat in parts[1:]:
                    if not pat.startswith("/"):
                        pat = "/etc/ssh/" + pat
                    for p in sorted(glob.glob(os.path.join(root, pat.lstrip("/")))):
                        read(p, depth + 1)
                        if match:
                            return
            elif k in want and k not in got and len(parts) > 1:
                got[k] = parts[1].lower()
    read(conf)
    out = dict(SSHD_DEFAULTS, **got)
    out["source"] = "config files" + (" (stopped at a Match block)" if match else "")
    return out


# Passwords board images ship with (and forum guides tell people to keep). Each one is hashed HERE with the
# account's own salt and compared; only the image name leaves this machine, never a password or a hash.
IMAGE_DEFAULTS = [("pi", "raspberry", "Raspberry Pi OS (before 2022)"), ("root", "dietpi", "DietPi"),
                  ("dietpi", "dietpi", "DietPi"), ("root", "1234", "Armbian first boot"),
                  ("root", "orangepi", "Orange Pi OS"), ("orangepi", "orangepi", "Orange Pi OS"),
                  ("debian", "temppwd", "BeagleBone Debian"), ("ubuntu", "ubuntu", "Ubuntu Server for Pi"),
                  ("odroid", "odroid", "ODROID images"), ("rock", "rock", "Radxa ROCK images"),
                  ("radxa", "radxa", "Radxa images"), ("alarm", "alarm", "Arch Linux ARM"),
                  ("root", "root", "Arch Linux ARM / many SBC images"), ("khadas", "khadas", "Khadas images"),
                  ("kali", "kali", "Kali ARM"), ("root", "toor", "Kali (old)"), ("nvidia", "nvidia", "Jetson images"),
                  ("root", "raspberry", "Raspberry Pi guides")]


def _crypt_fn():
    """libcrypt's crypt(3) through ctypes (Python's crypt module is gone from 3.13). None when there is no libcrypt."""
    import ctypes
    import ctypes.util
    for name in (ctypes.util.find_library("crypt"), "libcrypt.so.1", "libcrypt.so.2"):
        if not name:
            continue
        try:
            lib = ctypes.CDLL(name)
        except OSError:
            continue
        fn = lib.crypt
        fn.argtypes, fn.restype = [ctypes.c_char_p, ctypes.c_char_p], ctypes.c_char_p
        return lambda pw, setting: (fn(pw.encode(), setting.encode()) or b"").decode("ascii", "replace")
    return None


def default_password(user, field, crypt=None):
    """→ the image name whose default password `user` still has, "" if none, None if it can't be tested."""
    cands = [(pw, img) for u, pw, img in IMAGE_DEFAULTS if u == user]
    if not cands or not field.startswith("$"):
        return ""
    crypt = crypt or _crypt_fn()
    if crypt is None:
        return None
    for pw, img in cands:
        try:
            if crypt(pw, field) == field:
                return img
        except Exception:  # noqa: BLE001 — an unsupported scheme reads as "not tested", never as a match
            return None
    return ""


def board_model(root="/"):
    """The board's own name from the device tree (Raspberry Pi 4 Model B Rev 1.4, Orange Pi 5, ...), or ""."""
    for rel in ("proc/device-tree/model", "sys/firmware/devicetree/base/model"):
        d = head(os.path.join(root, rel), 256)
        if d:
            return d.rstrip(b"\0\n").decode("utf-8", "replace")
    return ""


def accounts_report(root="/"):
    """→ {"checked": bool, "note": str, "accounts": [{user, uid, state, scheme}], "sshd": {...} or None}.
    accounts lists root plus every account whose password is empty or usable; locked ones are only counted."""
    rep = {"checked": False, "note": "", "accounts": [], "locked": 0, "sshd": sshd_settings(root),
           "board": board_model(root)}
    uids = {}
    try:
        with open(os.path.join(root, "etc/passwd"), encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) >= 7:
                    uids[p[0]] = (p[2], p[6])
    except OSError:
        pass
    try:
        with open(os.path.join(root, "etc/shadow"), encoding="utf-8", errors="replace") as f:
            shadow = f.read().splitlines()
    except PermissionError:
        rep["note"] = "passwords not checked: /etc/shadow needs root"
        return rep
    except OSError:
        rep["note"] = "passwords not checked: no /etc/shadow"
        return rep
    for line in shadow:
        p = line.split(":")
        if len(p) < 2 or not p[0]:
            continue
        state, scheme = pw_state(p[1])
        if state == "locked" and p[0] != "root":
            rep["locked"] += 1
            continue
        uid, shell = uids.get(p[0], ("", ""))
        a = {"user": p[0], "uid": uid, "shell": shell, "state": state, "scheme": scheme}
        if state == "usable":
            a["default_of"] = default_password(p[0], p[1])
        rep["accounts"].append(a)
    rep["checked"] = True
    return rep


def host_main(root="/"):
    """`python3 - host`: this machine, for `sieve remote`. Reads only; the tar goes to stdout."""
    out = tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz")

    def add(name, data):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        out.addfile(ti, io.BytesIO(data))
    apk = None
    for rel in HOST_FILES:
        d = head(os.path.join(root, rel), 64 << 20)
        if d is not None:
            add("os/" + rel.replace("/", "_"), d)
            if rel == "lib/apk/db/installed":
                apk = d.decode("utf-8", "replace")
    rpm_files = {}                              # {path: package}, from the same rpmdb read, for in-use
    if not (os.path.isfile(os.path.join(root, "var/lib/dpkg/status")) or apk):
        rows, err = rpm_list(root, rpm_files)
        if rows or err:
            add("os/rpm_packages", (f"#error {err}" if err else "#format host\n" + rows).encode())
    add("owned", "\n".join(sorted(os_owned(root, apk))).encode())
    for k, (name, ver, path) in enumerate(python_dists(root), 1):
        add(f"py/{k}", f"{path}\n{name}\n{ver}".encode())
    add("npm_owned", "\n".join(sorted(npm_owned(root))).encode())
    for k, (name, ver, path) in enumerate(npm_global(root), 1):
        add(f"npm/{k}", f"{path}\n{name}\n{ver}".encode())
    # in use is read HERE, on the scanned machine: /proc belongs to the machine the collector runs on
    if os.path.realpath(root) != "/":
        add("inuse_note", b"in-use not checked with --root (run sieve on the machine itself for that)")
    else:
        try:
            add("inuse", json.dumps(inuse_report(root, host_pids(), rpm_files=rpm_files)).encode())
        except Exception as e:  # noqa: BLE001 — in-use is extra information, never a reason to fail the scan
            add("inuse_note", f"in-use check failed: {type(e).__name__}: {e}".encode())
    try:
        add("accounts", json.dumps(accounts_report(root)).encode())
    except Exception as e:  # noqa: BLE001 — extra information, never a reason to fail the scan
        add("accounts", json.dumps({"checked": False, "note": f"account check failed: {e}"}).encode())
    out.close()


def walk_root(root, skip, add, p):
    """Every language package and Go/Rust binary under one container root."""
    k = 0
    for dp, dns, fns in os.walk(root):
        rel = dp[len(root):] or "/"
        dns[:] = [x for x in dns if os.path.join(rel, x) not in skip and not (rel == "/" and x in ("proc", "sys", "dev"))]
        for fn in fns:
            fp = os.path.join(dp, fn)
            kind = data = None
            if fn == "METADATA" and dp.endswith(".dist-info") or fn == "PKG-INFO" and dp.endswith(".egg-info"):
                kind, data = "py", pymeta(head(fp, 4096))
            elif fn.endswith(".egg-info") and os.path.isfile(fp):
                kind, data = "py", pymeta(head(fp, 4096))
            elif fn == "package.json" and re.search(r"/node_modules/(@[^/]+/)?[^/@]+$", dp):
                kind, data = "npm", npmmeta(head(fp, 1 << 20))
            else:
                try:
                    st = os.lstat(fp)
                except OSError:
                    continue
                if not (st.st_mode & 0o111) or not (0o100000 & st.st_mode) or st.st_size < 500_000 \
                        or st.st_size > 400 << 20 or head(fp, 4) != b"\x7fELF":
                    continue
                try:
                    with open(fp, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                        i = m.find(MAGIC)
                        if i >= 0:
                            kind, data = "go", m[i:i + 262144]
                        else:
                            sec = elf_section(m, b".dep-v0")      # Rust built with cargo-auditable
                            if not sec:
                                continue
                            kind, data = "rust", sec
                except (OSError, ValueError, struct.error):
                    continue
            if kind and data:
                k += 1
                add(f"{p}{kind}/{k}", (rel + "/" + fn + "\n").encode() + data)


# ── in use: which installed packages have code mapped into a running process ─────────────────────────────────────
# Read from /proc/<pid>/maps: every shared library, executable and mmapped file a process has open. A path is mapped
# back to its package through the package manager's own file lists (dpkg *.list, apk F:/R:; rpm to come) and, for
# compiled Python extensions, the wheel's RECORD. "(deleted)" means the file was replaced on disk (an upgrade) while
# the process kept running the old copy: in use, and it needs a restart.
USRMERGE = ("/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/")
BIN_DIRS = {"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin"}
SHARED = re.compile(r"\.so(\.[0-9][^/]*)?$")
SITE = ("/site-packages/", "/dist-packages/")


def _twins(p):
    """A listed path and its usrmerge twin: dpkg lists /lib/x/libssl.so.3, maps shows /usr/lib/x/libssl.so.3."""
    if p.startswith(USRMERGE):
        return p, "/usr" + p
    if p.startswith("/usr/") and p[4:].startswith(USRMERGE):
        return p, p[4:]
    return (p,)


def proc_pids(proc="/proc"):
    try:
        return [d for d in os.listdir(proc) if d.isdigit()]
    except OSError:
        return []


def host_pids(proc="/proc"):
    """Processes in this machine's own mount namespace (container processes see a different filesystem, so their
    paths would be matched against the wrong package lists). Without root pid 1's namespace can't be read; then
    every process is a candidate and the ones that can't be read are counted as not seen."""
    try:
        ns = os.readlink(f"{proc}/1/ns/mnt")
    except OSError:
        return proc_pids(proc)
    out = []
    for pid in proc_pids(proc):
        try:
            if os.readlink(f"{proc}/{pid}/ns/mnt") == ns:
                out.append(pid)
        except OSError:
            out.append(pid)
    return out


def container_pids(proc="/proc"):
    """{64-hex container id: [pid]} from each process's cgroup path (docker-<id>.scope, /docker/<id>, ...)."""
    hexid = re.compile(r"[0-9a-f]{64}")
    out = {}
    for pid in proc_pids(proc):
        try:
            with open(f"{proc}/{pid}/cgroup") as f:
                m = hexid.search(f.read())
        except OSError:
            continue
        if m:
            out.setdefault(m.group(0), []).append(pid)
    return out


def mapped(pids, proc="/proc"):
    """→ ({path: replaced_on_disk}, processes read, processes there). Only EXECUTABLE mappings count: every process
    maps data files too (/etc/ld.so.cache, locale archives) and those would make their packages look "in use". Kernel
    threads (empty cmdline) map nothing and are not counted; a process whose maps can't be read (not root, or it
    exited) counts as there but not read."""
    paths, seen, total = {}, 0, 0
    for pid in pids:
        try:
            with open(f"{proc}/{pid}/cmdline", "rb") as f:
                if not f.read(1):
                    continue
            total += 1
            with open(f"{proc}/{pid}/maps", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            continue
        seen += 1
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) < 6 or not parts[5].startswith("/") or "x" not in parts[1]:
                continue
            path, gone = parts[5], parts[5].endswith(" (deleted)")
            if gone:
                path = path[:-len(" (deleted)")]
            paths[path] = paths.get(path, False) or gone
    return paths, seen, total


def _is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def owners(root, want, rpm_files=None):
    """Who owns each mapped path. → ({path: "os:<pkg>" | "py:<dist>"}, {OS packages that ship native code}).
    A package "ships native code" when it has a shared library or an ELF executable: only for those can "nothing is
    mapped" honestly mean "not loaded" (a script or a pure-Python module runs inside an interpreter's mapping)."""
    own, native = {}, set()

    def add(pkg, path):
        for q in _twins(path):
            if q in want:
                own.setdefault(q, "os:" + pkg)
        if pkg not in native and (SHARED.search(path) or
                                  (os.path.dirname(path) in BIN_DIRS and _is_elf(in_root(root, path) or ""))):
            native.add(pkg)
    info = os.path.join(root, "var/lib/dpkg/info")
    try:
        lists = [f for f in os.listdir(info) if f.endswith(".list")]
    except OSError:
        lists = []
    for fn in lists:
        pkg = fn[:-5].split(":")[0]
        for line in _read_text(os.path.join(info, fn)).splitlines():
            if line.startswith("/") and line != "/.":
                add(pkg, line.rstrip("/"))
    pkg = folder = ""
    for line in _read_text(os.path.join(root, "lib/apk/db/installed")).splitlines():
        if line.startswith("P:"):
            pkg = line[2:]
        elif line.startswith("F:"):
            folder = "/" + line[2:]
        elif line.startswith("R:") and pkg:
            add(pkg, f"{folder}/{line[2:]}")
    for path, pkg in (rpm_files or {}).items():                # read with the package list (rpm_packages files=)
        add(pkg, path)
    sites = {}
    for path in want:
        if path in own:
            continue
        for mark in SITE:
            i = path.find(mark)
            if i < 0:
                continue
            site = path[:i + len(mark) - 1]
            if site not in sites:
                sites[site] = _record_index(root, site)
            dist = sites[site].get(os.path.normpath(path))
            if dist:
                own[path] = "py:" + dist
            break
    return own, native


def _record_index(root, site):
    """{absolute file path: distribution name} from every *.dist-info/RECORD in one site directory."""
    out = {}
    base = root.rstrip("/") + site
    try:
        infos = [d for d in os.listdir(base) if d.endswith(".dist-info")]
    except OSError:
        return out
    for d in infos:
        meta = pymeta(head(os.path.join(base, d, "METADATA"), 4096))
        if not meta:
            continue
        name = meta.decode().split("\n")[0]
        for line in _read_text(os.path.join(base, d, "RECORD")).splitlines():
            rel = line.rsplit(",", 2)[0] if line.count(",") >= 2 else line
            if rel:
                out[os.path.normpath(os.path.join(site, rel))] = name
    return out


def inuse_report(root, pids, proc="/proc", rpm_files=None):
    """Packages with code mapped into any of `pids` right now. Paths in /proc/<pid>/maps are the process's own view of
    its filesystem, so `root` must be that filesystem (the host's /, or a container's /proc/<pid>/root)."""
    paths, seen, total = mapped(pids, proc)
    own, native = owners(root, set(paths), rpm_files)
    loaded = {}
    for path, gone in paths.items():
        o = own.get(path)
        if o:
            loaded[o] = loaded.get(o, False) or gone
    return {"seen": seen, "total": total, "loaded": loaded, "native": sorted(native)}


def main():
    out = tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz")
    errs = []

    def add(name, data):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        out.addfile(ti, io.BytesIO(data))

    try:                        # if this itself runs inside a container, skip that container
        me = open("/proc/self/cgroup").read()
    except OSError:
        me = ""
    ids = [c for c in sh("docker", "ps", "-q", "--no-trunc").split() if c not in me]
    images = {}                 # image id → [name, pid of its first container, every container id]
    for cid in ids:
        # name as `docker ps` shows it (an image id once its tag has moved on)
        info = sh("docker", "ps", "-f", "id=" + cid, "--format", "{{.Image}}").strip().split("\n")[:1] + \
            sh("docker", "inspect", "-f", "{{.Image}}|{{.State.Pid}}", cid).strip().split("|")
        if len(info) != 3:
            continue
        images.setdefault(info[1], [info[0], info[2], []])[2].append(cid)
    cpids = container_pids()
    n = 0
    for name, pid, cids in images.values():
        root = f"/proc/{pid}/root"
        if pid in ("", "0") or not os.path.isdir(root + "/"):
            errs.append(f"{name}: container root not readable")
            continue
        # volumes and bind mounts are data, not the image: prune every mount point except /
        skip = set()
        try:
            for line in open(f"/proc/{pid}/mountinfo"):
                mp = line.split()[4].encode().decode("unicode_escape")
                if mp != "/":
                    skip.add(mp)
        except OSError:
            pass
        n += 1
        p = f"{n}/"
        add(p + "IMAGE", name.encode())
        for rel in OS_FILES:
            d = head(os.path.join(root, rel), 64 << 20)
            if d is not None:
                add(p + "os/" + rel.replace("/", "_"), d)
        rpmf = {}
        fmt, rows, err = rpm_packages(root, rpmf)
        if fmt or err:
            add(p + "os/rpm_packages", ((f"#error {err}" if err else f"#format {fmt}") + "\n" + "\n".join(rows)).encode())
        sd = os.path.join(root, "var/lib/dpkg/status.d")
        if os.path.isdir(sd):
            for f in sorted(os.listdir(sd)):
                if not f.endswith(".md5sums"):
                    d = head(os.path.join(sd, f), 1 << 20)
                    if d:
                        add(p + "os/statusd_" + f, d)
        walk_root(root, skip, add, p)
        try:
            pids = sorted({x for c in cids for x in cpids.get(c, [])}, key=int)
            r = inuse_report(root, pids or [pid], rpm_files=rpmf)
            r["main_only"] = not pids               # cgroup lookup found nothing: only the main process was read
            add(p + "inuse", json.dumps(r).encode())
        except Exception as e:  # noqa: BLE001 — in-use is extra; the package list above is what matters
            errs.append(f"{name}: in-use check failed: {type(e).__name__}: {e}")
    add("ERRORS", "\n".join(errs).encode())
    out.close()


if __name__ == "__main__":
    host_main() if sys.argv[1:2] == ["host"] else main()
