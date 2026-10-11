"""Container package collector. Standalone: no imports from sieve, standard library only.

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
  ERRORS           one line per image that could not be read
"""
import io
import json
import mmap
import os
import struct
import subprocess
import sys
import tarfile
import re

OS_FILES = ["etc/os-release", "usr/lib/os-release", "etc/alpine-release", "etc/debian_version", "etc/lsb-release",
            "var/lib/dpkg/status", "lib/apk/db/installed"]
MAGIC = b"\xff Go buildinf:"


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


def rpm_header(blob):
    """Header blob (index count, data length, 16-byte index entries, data store) → {name, version, …} or None."""
    try:
        il, dl = struct.unpack_from(">II", blob, 0)
    except struct.error:
        return None
    start = 8 + 16 * il
    if il > 200000 or start + dl > len(blob):
        return None
    store, out = blob[start:start + dl], {}
    for k in range(il):
        tag, typ, off, _cnt = struct.unpack_from(">IIII", blob, 8 + 16 * k)
        if tag not in RPM_TAGS or off >= len(store):
            continue
        if typ in (6, 8, 9):                                  # STRING, STRING_ARRAY, I18NSTRING: first string
            end = store.find(b"\0", off)
            out[RPM_TAGS[tag]] = store[off:end if end >= 0 else len(store)].decode("utf-8", "replace")
        elif typ == 4 and off + 4 <= len(store):              # INT32
            out[RPM_TAGS[tag]] = str(struct.unpack_from(">i", store, off)[0])
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


def rpm_packages(root="/"):
    """→ (format, ["name\\tepoch\\tversion\\trelease\\tarch\\tsourcerpm", …], error). ([], None) when there is no
    rpm database at all; an unreadable one is an error, never an empty list."""
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
            h = rpm_header(b)
            if h and h["name"] != "gpg-pubkey":
                rows.add("\t".join(h.get(k, "") for k in ("name", "epoch", "version", "release", "arch", "sourcerpm")))
        if blobs and not rows:
            return fmt, [], f"rpm database {rel} ({fmt}) held {len(blobs)} records but none could be read"
        return fmt, sorted(rows), None
    return None, [], None


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
    seen = set()
    n = 0
    for cid in ids:
        # name as `docker ps` shows it (an image id once its tag has moved on)
        info = sh("docker", "ps", "-f", "id=" + cid, "--format", "{{.Image}}").strip().split("\n")[:1] + \
            sh("docker", "inspect", "-f", "{{.Image}}|{{.State.Pid}}", cid).strip().split("|")
        if len(info) != 3 or info[1] in seen:
            continue
        name, iid, pid = info
        seen.add(iid)
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
        fmt, rows, err = rpm_packages(root)
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
    add("ERRORS", "\n".join(errs).encode())
    out.close()


if __name__ == "__main__":
    main()
