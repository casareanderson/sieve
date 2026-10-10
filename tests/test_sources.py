"""Host and container package gathering from fake roots and collector tars."""
import io
import os
import tarfile

from sieve import sources

STATUS = ("Package: bash\nStatus: install ok installed\nVersion: 5.2.37-1\n\n"
          "Package: linux-libc-dev\nStatus: install ok installed\nSource: linux\nVersion: 6.12.1-1\n\n"
          "Package: python3-requests\nStatus: install ok installed\nSource: requests\nVersion: 2.32.3+dfsg-1\n")


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


def test_host_from_fake_root(tmp_path):
    r = str(tmp_path)
    write(r, "etc/os-release", 'ID=debian\nVERSION_ID="13"\n')
    write(r, "var/lib/dpkg/status", STATUS)
    write(r, "usr/lib/python3/dist-packages/requests-2.32.3.dist-info/METADATA", "Name: requests\nVersion: 2.32.3\n")
    write(r, "var/lib/dpkg/info/python3-requests.list",
          "/usr/lib/python3/dist-packages/requests-2.32.3.dist-info\n")
    write(r, "usr/local/lib/python3.13/dist-packages/flask-2.0.0.dist-info/METADATA", "Name: Flask\nVersion: 2.0.0\n")
    t = sources.host(root=r)
    assert t.os == "debian 13"
    assert ("Debian:13", "bash", "5.2.37-1", "bash", "5.2.37-1") in t.pkgs
    assert not any(p[1] == "linux" for p in t.pkgs)                  # kernel package skipped
    assert ("PyPI", "Flask", "2.0.0", "Flask", "2.0.0") in t.pkgs     # pip-installed: checked against PyPI
    assert not any(p[0] == "PyPI" and p[1] == "requests" for p in t.pkgs)   # dpkg-owned: distro advisories cover it
    assert any("kernel" in n for n in t.notes)
    assert sources.host(root=r, kernel=True).pkgs != t.pkgs


def test_host_unknown_os(tmp_path):
    r = str(tmp_path)
    write(r, "etc/os-release", "ID=arch\n")
    write(r, "var/lib/dpkg/status", "Package: a\nStatus: install ok installed\nVersion: 1\n")
    t = sources.host(root=r)
    assert t.pkgs == [] and t.status == "partial"


def test_image_target_distroless_and_languages():
    files = {"os/etc_os-release": b"ID=debian\nVERSION_ID=12\n",
             "os/statusd_base": b"Package: libc6\nVersion: 2.36-9+deb12u7\nSource: glibc\n",
             "py/1": b"/usr/lib/python3.11/site-packages/x.dist-info/METADATA\nurllib3\n1.26.5",
             "npm/2": b"/app/node_modules/lodash/package.json\nlodash\n4.17.20",
             "go/3": b"/usr/bin/app\n\xff Go buildinf:\x08\x00" + b"\0" * 40}
    t = sources.image_target("example/app:1", files)
    assert ("Debian:12", "glibc", "2.36-9+deb12u7", "libc6", "2.36-9+deb12u7") in t.pkgs
    assert ("PyPI", "urllib3", "1.26.5", "urllib3", "1.26.5") in t.pkgs
    assert ("npm", "lodash", "4.17.20", "lodash", "4.17.20") in t.pkgs
    assert any("Go 1.18" in n for n in t.notes)


def test_read_collected_streams_per_image():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in [("1/IMAGE", b"nginx:1.27"), ("1/os/etc_os-release", b"ID=alpine\nVERSION_ID=3.20.3\n"),
                           ("1/os/lib_apk_db_installed", b"P:musl\nV:1.2.5-r0\n"),
                           ("2/IMAGE", b"python:3.12-slim"), ("2/py/1", b"/x/METADATA\npip\n24.0"),
                           ("ERRORS", b"broken:latest: container root not readable")]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    buf.seek(0)
    errs = []
    ts = list(sources.read_collected(buf, errs))
    assert [t.name for t in ts] == ["nginx:1.27", "python:3.12-slim"]
    assert ts[0].pkgs == [("Alpine:v3.20", "musl", "1.2.5-r0", "musl", "1.2.5-r0")]
    assert ts[1].pkgs == [("PyPI", "pip", "24.0", "pip", "24.0")] and ts[1].os == "no OS packages"
    assert errs == ["broken:latest: container root not readable"]


def test_collector_is_standalone():
    src = sources.collector_source()
    assert "\nfrom sieve" not in src and "\nimport sieve" not in src and "from ." not in src
    compile(src, "collect.py", "exec")


def test_collector_walk_root(tmp_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location("collect", sources.COLLECTOR)
    c = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(c)
    r = str(tmp_path)
    write(r, "usr/lib/python3/site-packages/six-1.16.0.dist-info/METADATA", "Name: six\nVersion: 1.16.0\n")
    write(r, "app/node_modules/@scope/pkg/package.json", '{"name": "@scope/pkg", "version": "1.2.3"}')
    write(r, "data/node_modules/x/package.json", '{"name": "x", "version": "9"}')    # a mounted volume
    got = {}
    c.walk_root(r, {"/data"}, lambda n, d: got.__setitem__(n, d), "1/")
    vals = sorted(v.split(b"\n", 1)[1] for v in got.values())
    assert vals == [b"@scope/pkg\n1.2.3", b"six\n1.16.0"]
