"""Container package collector. Standalone: no imports from sieve, standard library only.

Run it as root on a Docker host, either directly or with its source fed on stdin (`python3 -`), for example
over ssh:  sieve collector | ssh root@dockerhost python3 - > packages.tgz ;  sieve containers --from-tar packages.tgz

For each distinct image with a running container it reads the container's real root through /proc/<pid>/root
(this works on every storage driver, including Docker's containerd image store), skips mounted volumes, and
writes a gzipped tar to stdout holding only package metadata. It installs nothing and writes nothing to disk.

  <n>/IMAGE        image name as `docker ps` shows it
  <n>/os/...       os-release, dpkg status (+ distroless status.d), apk db
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
