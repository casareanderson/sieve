# sieve

[![CI](https://github.com/casareanderson/sieve/actions/workflows/ci.yml/badge.svg)](https://github.com/casareanderson/sieve/actions/workflows/ci.yml)
[![Licence: AGPL-3.0](https://img.shields.io/github/license/casareanderson/sieve)](LICENSE)
[![Latest release](https://img.shields.io/github/v/release/casareanderson/sieve)](https://github.com/casareanderson/sieve/releases/latest)

Find the CVEs that matter on a Linux box and its running containers.

No scanner binary, no 1.4 GB database, no server: sieve reads the package lists already on the box, asks
[OSV.dev](https://osv.dev) which advisories affect those exact versions, then ranks the results by
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [EPSS](https://www.first.org/epss/).
Its only dependency is `requests`.

![sieve ranking old container images: two actively exploited CVEs first](docs/sieve-run.png)

## Why

![What sieve replaced: trivy's binary, database and server vs package lists and OSV.dev](docs/sieve-vs-trivy.png)

sieve started as the scanner inside [warden](https://github.com/casareanderson/warden), where it replaced trivy on
10 October 2026. Trivy's v0.69.4 release and its v0.69.5 and v0.69.6 images were malicious (CVE-2026-33634), and the
scanner you run as root to find supply-chain problems shouldn't be a supply-chain problem itself.

OSV.dev is the open database behind Google's osv-scanner. Debian, Ubuntu, Alpine, the GitHub advisory database,
PyPA, the Go team and RustSec all publish to it directly, so there is nothing to download, verify or keep patched
on your side.

## Install

Full step-by-step setup, tested every week on a fresh machine: [docs/SETUP.md](docs/SETUP.md).

```
pipx install git+https://github.com/casareanderson/sieve
```

Python 3.10 or newer. It also runs straight from a checkout: `python3 -m sieve host`.

### Docker

The image only needs to read the host's filesystem, so mount it read-only and point `--root` at it:

```
docker run --rm -v /:/host:ro ghcr.io/casareanderson/sieve host --root /host
```

Add `-v sieve-cache:/home/sieve/.cache` to keep the advisory cache between runs. The image runs as an
unprivileged user; package databases are world-readable, so host scans don't need root.

The image can't scan running containers itself: that needs the docker CLI and root on the Docker host. Run the
collector there instead (it's standard-library Python) and pipe its output into the image:

```
docker run --rm ghcr.io/casareanderson/sieve collector | sudo python3 - \
  | docker run --rm -i ghcr.io/casareanderson/sieve containers --from-tar -
```

## Usage

```
sieve host          # this machine: dpkg, apk or rpm packages, Python packages pip installed outside the OS, global npm
sieve containers    # every running Docker container on this machine (needs root)
sieve all           # both
sieve path DIR ...  # project directories: lockfiles, node_modules, requirements, virtualenvs (see below)
sieve verify        # has any installed file changed since its package manager put it there? (see Verify)
```

Options (for `host`, `containers`, `all` and `path`):

| option | what it does |
|---|---|
| `--json` | machine-readable output |
| `--sarif` | SARIF 2.1.0 output for GitHub code scanning (see [Code scanning](#code-scanning)) |
| `--min-severity low\|medium\|high\|critical` | hide findings below this severity (known-exploited findings are always shown) |
| `--kev-only` | only findings in CISA's known-exploited list |
| `--fixable-only` | only findings with a fixed version available |
| `--in-use-only` | only findings whose code is loaded in a running process right now (see [In use](#in-use)) |
| `--cache PATH` | advisory cache, default `~/.cache/sieve/sieve.db`; the KEV and EPSS files are kept next to it |
| `--no-epss` | don't download or use EPSS scores |
| `--kernel` | also check kernel packages (skipped by default, see Limits) |
| `--root PATH` | `host` and `all`: read the host's packages from this directory instead of `/` (for example the host's `/` mounted at `/host` in a container) |
| `--limit N` | table rows to print, default 50, `0` for all; the summary line always counts everything |
| `--depth N` | `path`: how deep to look under each directory, default 8 |

Exit codes: `1` if any known-malicious package or known-exploited (KEV) finding is in the output, `2` if part of
the scan failed, otherwise `0`. Filters apply first, so `sieve all --fixable-only` in cron or CI fails only on KEV
findings you can actually fix. A malicious package is never hidden by a filter.

### Project directories and malicious packages

`sieve path` scans what a project has pinned or installed, without running npm, yarn, pnpm, pip or node:

| file | what is read |
|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` | every package, lockfile versions 1, 2 and 3 |
| `yarn.lock` | classic (v1) and berry (v2+); workspace and link entries skipped |
| `pnpm-lock.yaml` | lockfile versions 5, 6 and 9 |
| `node_modules/` | every installed `package.json`, nested ones included |
| `requirements*.txt` | `name==version` pins (ranges can't be matched to one version) |
| `poetry.lock`, `uv.lock` | every `[[package]]`; your own editable or path projects skipped |
| `site-packages/` | `*.dist-info` metadata, so a virtualenv inside the project is covered |

`.git` is never read. A lockfile sieve can't parse (a pnpm `lockfileVersion` it doesn't know, broken JSON) is
named in the output and marks the scan partial, instead of looking like a clean project.

**Known-malicious packages come first.** OSV carries the OpenSSF malicious-packages feed (`MAL-` ids), and GitHub
files planted malware as CWE-506. A package that matches is not a bug with a patch: someone put code there on
purpose. sieve ranks it above everything else, shows it as `☠ MALWARE`, folds the duplicate records into one row,
exits `1`, and in SARIF reports it as `error` with a security-severity of 10.0:

```
$ sieve path ./demo
# path:/demo: project files, 2 packages  (read 1 package-lock.json)

ALERT      EPSS  SEVERITY  ID              PACKAGE         INSTALLED → FIXED             TARGET
☠ MALWARE  -     CRITICAL  MAL-2025-20690  flatmap-stream  0.1.1 → malicious: remove it  path:/demo

1 MALICIOUS PACKAGE (remove it, rotate secrets), 1 findings, 0 actively exploited, 0 fixable
```

(`flatmap-stream` 0.1.1 is the 2018 event-stream backdoor. The lockfile only names it; nothing was installed.)
If you find one: remove it, rebuild from a clean lockfile, and rotate every secret the machine or CI job could read.

### Verify

`sieve verify` asks a different question from the CVE scan: **has any installed file been changed since its
package manager put it there?** A vulnerability list can't see a swapped `sshd` or an edited library whose version
number stayed the same. Every package manager already keeps a checksum for each file it installs, in a
world-readable file next to its database, so sieve re-hashes the files and compares. No binary, no download, and
no root for the host (unreadable files are counted and named in the output).

```
sieve verify                              # this machine
sieve verify --root /mnt/image            # a mounted filesystem or an exported image
sudo sieve verify --containers [--host]   # every running Docker container, read in place
sieve verify --packages openssh-server,sudo
```

| system | checksums read | algorithm |
|---|---|---|
| Debian, Ubuntu | `/var/lib/dpkg/info/<pkg>.md5sums` | MD5 |
| Alpine | `/lib/apk/db/installed` (`Z:` lines) | SHA-1 |
| rpm (AlmaLinux, Rocky, RHEL, openSUSE, Fedora) | the rpm database's own headers (FILEDIGESTS) | SHA-256 on current releases, MD5 on old ones |
| Python (pip) | `*.dist-info/RECORD` | SHA-256 |
| npm | **nothing to check**: npm keeps no checksum for installed files (a lockfile's `integrity` is the hash of the downloaded tarball, not of what is on disk) | |

```
$ sieve verify --root ./rocky-9-minimal
# host (./rocky-9-minimal): rocky 9.8, 118 packages, 4038 files  (76 config files skipped; …; rpm checked in 0.6s)

STATE       PACKAGE                       FILE                TARGET
changed  ⚠  coreutils-single 8.32-40.el9  /usr/bin/sha256sum  host (./rocky-9-minimal)

1 changed (1 security-critical), 0 missing, 4038 files checked
```

(That image had one byte appended to `sha256sum` for the demo.) What it reports:

- **changed**: the file's content differs from the checksum its package recorded. Files under `/usr/bin`,
  `/usr/sbin`, `/bin`, `/sbin`, PAM modules, `sshd`, `sudo`, `su`, `login`, the C library and the dynamic loader
  are marked ⚠ security-critical (SARIF `error`); other changed files are `warning`.
- **now X's file**: two Python distributions can install into the same folder (`PyJWT` and `jwt` both own `jwt/`).
  When a changed file matches another installed distribution's RECORD, sieve says so instead of leaving it
  unexplained. It is still a broken install (`import jwt` gets the other library), so it still counts as changed.
  Found exactly this in a popular crawler image.
- **missing**: a file the package installed is gone. Minimal and official images delete docs, man pages and
  translations after install; those are counted as *trimmed* and not listed (`--all-missing` lists them).
- **not checked by design**: dpkg `path-exclude` (docs a minimal image never unpacked), rpm files that were never
  installed (nodocs, other languages, the other multilib architecture) and rpm files the package marks
  `%verify(not md5)` because it rewrites them itself (glibc's `gconv-modules.cache`), the same files `rpm -V` skips.
- **config files** are meant to change, so dpkg conffiles and rpm `%config` files are skipped unless you pass
  `--include-config`. Debian's `/usr` merge diversions and container mount points (volumes, `/etc/hosts`) are
  handled, and inside a container root an absolute symlink is followed within the container, never onto the host.

Exit codes: `1` if a packaged file changed, `2` if nothing could be checked, otherwise `0`. Missing files are
reported but don't fail the run. `--json` and `--sarif` work as for the scan.

**It's a tripwire, not proof.** MD5 and SHA-1 catch accidental changes, failed upgrades and naive tampering, but
anyone with root can rewrite the checksum lists as easily as the files. A clean result means nothing was changed
*carelessly*; a changed file is a question to answer (a local edit? a hotfix? someone else?), not a verdict.

Measured: a Debian 13 Proxmox node, 811 packages and 70,795 files, in 34 s (clean); twelve running containers,
81,079 files, in 31 s. It is IO-bound: on a spinning disk the first full pass over a desktop-sized install took
over 20 minutes, so use `--packages` for a quick look or run it at night.

### Examples

A fully patched Debian 13 host. Nothing is fixable, which is normal: most of what any scanner reports is "affected,
no fix released yet", and Debian marks a lot of it as unimportant.

```
$ sieve host --limit 8
# host: debian 13, 811 packages

ALERT  EPSS   SEVERITY  ID              PACKAGE              INSTALLED → FIXED                          TARGET
       73.3%  UNKNOWN   CVE-2011-3389   gnutls-bin           3.8.9-3+deb13u4 → no fix                   host
       73.3%  UNKNOWN   CVE-2011-3389   libgnutls-dane0t64   3.8.9-3+deb13u4 → no fix                   host
       73.3%  UNKNOWN   CVE-2011-3389   libgnutls30t64       3.8.9-3+deb13u4 → no fix                   host
       20.9%  LOW       CVE-2019-6110   openssh-client       1:10.0p1-7+deb13u4 → unimportant (Debian)  host
       20.9%  LOW       CVE-2019-6110   openssh-server       1:10.0p1-7+deb13u4 → unimportant (Debian)  host
       20.9%  LOW       CVE-2019-6110   openssh-sftp-server  1:10.0p1-7+deb13u4 → unimportant (Debian)  host
       20.9%  LOW       CVE-2019-6110   ssh                  1:10.0p1-7+deb13u4 → unimportant (Debian)  host
       13.0%  LOW       CVE-2020-15778  openssh-client       1:10.0p1-7+deb13u4 → unimportant (Debian)  host
… 1957 more (use --limit 0 to show all, or --json)

1965 findings, 0 actively exploited, 0 fixable
```

Three deliberately old package lists (Alpine 3.18, Debian 12 at release, Debian 10), fed in with `--from-tar`:

```
$ sieve containers --from-tar old-images.tgz --min-severity high --limit 12
# example/legacy-app:1.0: alpine 3.18.0, 5 packages
# example/old-web:2: debian 12, 2 packages
# example/buster-tools:0.9: debian 10, 2 packages

ALERT  EPSS    SEVERITY  ID              PACKAGE         INSTALLED → FIXED                    TARGET
⚠      100.0%  HIGH      CVE-2021-3156   sudo            1.8.27-1+deb10u2 → 1.8.27-1+deb10u3  example/buster-tools:0.9
⚠      94.3%   HIGH      CVE-2021-4034   policykit-1     0.105-25 → 0.105-25+deb10u1          example/buster-tools:0.9
       99.5%   HIGH      CVE-2024-6387   openssh-server  1:9.2p1-2 → 1:9.2p1-2+deb12u3        example/old-web:2
       79.7%   CRITICAL  CVE-2023-38408  openssh-server  1:9.2p1-2 → 1:9.2p1-2+deb12u1        example/old-web:2
       78.5%   CRITICAL  CVE-2023-38545  libcurl         8.1.0-r0 → 8.4.0-r0                  example/legacy-app:1.0
       66.6%   HIGH      CVE-2024-6119   libcrypto3      3.1.0-r4 → 3.1.7-r0                  example/legacy-app:1.0
       58.1%   HIGH      CVE-2023-38039  libcurl         8.1.0-r0 → 8.3.0-r0                  example/legacy-app:1.0
       55.4%   HIGH      CVE-2023-22809  sudo            1.8.27-1+deb10u2 → 1.8.27-1+deb10u5  example/buster-tools:0.9
       36.1%   HIGH      CVE-2024-2398   libcurl         8.1.0-r0 → 8.7.1-r0                  example/legacy-app:1.0
       5.6%    CRITICAL  CVE-2024-5535   libcrypto3      3.1.0-r4 → 3.1.6-r0                  example/legacy-app:1.0
       3.2%    CRITICAL  CVE-2022-48174  busybox         1.36.0-r9 → 1.36.1-r1                example/legacy-app:1.0
       2.3%    CRITICAL  CVE-2023-28531  openssh-server  1:9.2p1-2 → 1:9.2p1-2+deb12u2        example/old-web:2
… 23 more (use --limit 0 to show all, or --json)

35 findings, 2 actively exploited, 31 fixable (102 hidden by filters)
```

Is the vulnerable code actually running? The `IN USE` column says, per finding (an Ubuntu 24.04 container, as
root, fixable findings only):

```
$ sudo sieve host --fixable-only --limit 4
# host: ubuntu 24.04, 772 packages  (1 kernel packages skipped (use --kernel to include them))

ALERT  EPSS  SEVERITY  IN USE  ID              PACKAGE       INSTALLED → FIXED  TARGET
       0.3%  CRITICAL  ?       CVE-2026-63374  anyio         4.13.0 → 4.14.2    host
       0.3%  HIGH      yes     CVE-2026-69247  cryptography  49.0.0 → 50.0.0    host
       0.3%  HIGH      ?       CVE-2026-97689  urllib3       2.7.0 → 2.8.0      host
       0.3%  MEDIUM    ?       CVE-2026-97688  urllib3       2.7.0 → 2.8.0      host
… 4 more (use --limit 0 to show all, or --json)

8 findings, 0 actively exploited, 8 fixable (1252 hidden by filters)
1 in code running right now
```

### Scanning containers on another machine

The container collector is a single standard-library script. It reads, it doesn't install or write anything,
and it doesn't need sieve on the Docker host:

```
sieve collector | ssh root@dockerhost python3 - > packages.tgz
sieve containers --from-tar packages.tgz
```

`--from-tar -` reads the tar from stdin.

### Use it in CI

sieve is also a GitHub Action. It scans the runner, writes the ranked table to the job summary and fails the
job when a known-exploited finding is reported:

```yaml
name: sieve
on:
  schedule:
    - cron: "0 7 * * 1"
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - id: sieve
        uses: casareanderson/sieve@v1
        with:
          command: host              # host, containers or all
          args: --fixable-only       # any other sieve options
          fail-on-kev: "true"        # the default
      - run: echo "${{ steps.sieve.outputs.kev }} KEV, ${{ steps.sieve.outputs.fixable }} fixable"
```

| input | default | |
|---|---|---|
| `command` | `host` | `host`, `containers` or `all`; `containers` and `all` run sieve with `sudo -E` when the runner isn't root |
| `args` | `""` | extra sieve options |
| `fail-on-kev` | `true` | fail the step on a known-exploited finding; `false` turns that into a warning |
| `python-version` | `3.12` | Python to install sieve with |
| `sarif` | `false` | also write a SARIF file from the same scan, for GitHub code scanning |

Outputs: `findings`, `kev`, `fixable` (the summary counts after filters), `report` (path to the JSON report) and
`sarif` (path to the SARIF file, when the `sarif` input is `true`).
A scan that partly failed (exit code 2) always fails the step. On GitHub-hosted runners this mostly tells you
about the runner image; it's more useful on self-hosted runners and in jobs that start the containers you ship.

`@v1` follows the latest 0.x release; pin a release tag such as `@v0.1.0` if you want it fixed.

### Code scanning

`--sarif` (or the Action's `sarif: "true"`) writes SARIF 2.1.0, so findings show up in the repository's
**Security → Code scanning** tab, with GitHub's own alert tracking, dismissals and history:

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write       # to upload SARIF
      contents: read
    steps:
      - id: sieve
        uses: casareanderson/sieve@v1
        with:
          sarif: "true"
          fail-on-kev: "false"       # let the upload run; the alerts are the signal
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.sieve.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.sieve.outputs.sarif }}
          category: sieve-host
```

One rule per advisory (help link to the advisory), one alert per advisory, package and target. Known-exploited
findings, fixable findings with EPSS ≥ 10%, CRITICAL and HIGH are `error`, MEDIUM is `warning`, the rest `note`;
a KEV finding is scored at least 9.0 so GitHub files it as critical. A package has no source line, so each alert
points at `<target>/<package>`. Alerts are fingerprinted on target, package and advisory, not version: upgrading to
a version that is still affected keeps the same alert, and fixing it closes the alert on the next upload.

### JSON

`--json` prints `targets` (what was scanned, OS, package count, status, notes), `errors`, `summary` and
`findings`. Each finding has `id` (the CVE where there is one), `package`, `installed`, `fixed` (empty when there
is no fix), `severity`, `kev`, `epss`, `epss_percentile`, `tier`, `status`, `target`, `summary`, `details` and `url`.

## How it works

![How sieve works: package lists, OSV.dev, KEV and EPSS, ranked table](docs/sieve-how.png)

**Package lists.** For the host: `/var/lib/dpkg/status`, `/lib/apk/db/installed` or the rpm database,
`/etc/os-release`, every `*.dist-info`/`*.egg-info` under the system Python site directories, and the
`package.json` of every global npm package (`/usr/lib/node_modules`, `/usr/local/lib/node_modules`, and any
`prefix=` set in an npmrc), read directly so neither node nor the `rpm` binary needs to be installed. Python and
npm packages that dpkg, apk or rpm installed are left to the distro's advisories, which know about backported
fixes. The rpm database is read directly: SQLite (EL9, Fedora), ndb (openSUSE) and the older BerkeleyDB hash file
(EL7/EL8). For containers: the collector finds each
image with a running container and reads its real root filesystem through `/proc/<pid>/root`, skipping mounted
volumes. From each image it takes the OS package database, Python and npm package metadata, the build info
embedded in Go binaries, and the dependency list Rust binaries carry when built with `cargo-auditable`.

**Matching.** Debian and Alpine packages are queried by source package and reported by binary package, so you
see what to upgrade. RPM feeds disagree on which name they index (Rocky: source, AlmaLinux and Red Hat: binary),
so rpm packages are asked about under both; RHEL is asked under BaseOS and AppStream. RPM distros publish errata
(RHSA, ALSA, RLSA, SUSE-SU) rather than per-CVE records, so each erratum is expanded into the CVEs it fixes and
keeps the distro's own rating. Version comparisons follow each ecosystem's own rules (dpkg, apk, rpm's
epoch:version-release with `~` and `^`, and semver/PEP 440 for language packages). Debian records also list the fix in unstable, so sieve only uses fixes for your exact
release. Alpine's own secdb is merged in because OSV's Alpine import can lag behind it. Advisory bodies are cut
down to what matching needs before they're cached, because Ubuntu and Debian records list every affected version
of every binary and the full bodies ran a scan past 5 GB of memory.

**Ranking.** Malware and known-exploited first, then what is likely to be exploited and can be fixed:

0. a known-malicious package (OpenSSF `MAL-`, or an advisory filed as embedded malicious code): remove it
1. in CISA KEV (known exploited in the wild), fix or not
2. EPSS of 10% or more (at least a 1 in 10 chance of exploitation in the next 30 days) with a fix available
3. CRITICAL with a fix available
4. anything else with a fix
5. no fix yet

Within a tier, code that is loaded in a running process comes first (then unknown, then not loaded), then higher
EPSS, then higher severity. Being loaded never moves a finding into another tier: a known-exploited package nothing
is running still outranks everything else. Severity is the vendor's rating where there is one
(Ubuntu priority, Red Hat's Critical/Important/Moderate/Low, GitHub's reviewed level), otherwise the CVSS v3 base score; when an advisory has neither, sieve
borrows the rating from the GitHub, CVE, Ubuntu or Debian record for the same CVE.

<a id="in-use"></a>**In use.** Each finding says whether its package's code is loaded in a running process right
now, read from `/proc/<pid>/maps` (every shared library and executable a process has mapped) and traced back to its
package through dpkg's `*.list` files, apk's file list, the rpm database (read once, with the package list), or a
wheel's `RECORD` for compiled Python extensions. Only
executable mappings count; data files every process maps (`/etc/ld.so.cache`, locale archives) don't. Containers
are read the same way, by the collector, for every process of every container of that image. Three answers:

- **yes** (`loaded`): a file of that package is mapped by a running process.
- **no** (`not loaded`): every process was read, the package ships native code (a shared library or an ELF
  executable), and none of it is mapped.
- **?** (`unknown`): anything else. Not every process could be read, or the package is scripts or pure Python (they
  run inside the interpreter's mapping, so `maps` can't show them), or it's an npm, Go or Rust package.

`↻` after `yes` (`restart_needed` in `--json`) means the running copy was replaced on disk by an upgrade: the fix is
installed, but the process is still executing the old code until it's restarted.

Without root only your own processes can be read. sieve says how many it read ("read 1 of 72 processes") and then
never answers **no**, only **yes** or **?**. With `--root` (scanning a filesystem mounted from elsewhere) the
check is skipped, because this machine's processes aren't that filesystem's. It's a snapshot: something that only
runs from cron may be **no** when you look.

**Caching.** Advisories are cached in SQLite and refetched only when OSV's `modified` stamp changes. KEV and EPSS
are downloaded at most every 20 hours; if a download fails, the last copy is used and a warning is printed.

## Limits

- **Forks, renamed and vendored packages are invisible.** sieve only knows what a package database or metadata
  file says. A library copied into a project, a binary built from a fork, or a package renamed by its publisher
  won't match an advisory.
- **OSV import lag.** Advisories reach OSV after the source publishes them, usually within hours, sometimes days.
  Alpine's secdb is merged in to cover the worst of it.
- **Kernel packages are skipped by default.** Containers and LXC guests run the host's kernel, and kernel
  advisories are numerous and large. Use `--kernel` on a real host if you want them. Vendor kernels such as
  Proxmox's `proxmox-kernel-*` aren't in any distro feed, so they're never covered.
- **Containers need root.** Container roots under `/proc/<pid>/root` are root-only. Only images with a running
  container are scanned.
- **Supported OS feeds:**

  | OS | OSV ecosystem | Package database |
  |---|---|---|
  | Debian, Ubuntu (and `ID_LIKE=ubuntu` derivatives) | `Debian:13`, `Ubuntu:24.04:LTS` | dpkg |
  | Alpine | `Alpine:v3.20` + Alpine secdb | apk |
  | AlmaLinux 8, 9 | `AlmaLinux:9` | rpm (BerkeleyDB on 8, SQLite on 9) |
  | Rocky Linux 8, 9 | `Rocky Linux:9` | rpm |
  | RHEL and UBI images | `Red Hat:enterprise_linux:9::baseos` / `::appstream` | rpm |
  | openSUSE Leap, Tumbleweed | `openSUSE:Leap 15.6`, `openSUSE:Tumbleweed` | rpm (ndb) |

  OSV has no feed for Fedora, CentOS Stream, Oracle Linux, Amazon Linux or Arch, and SUSE Linux Enterprise files
  its fixes per module, which a host can't name reliably. Those get their Python and container language packages
  checked, not their OS packages, and the scan says so.
- **Some openSUSE records carry a wrong fixed version.** openSUSE-SU-2024:10106-1 says bash is fixed in 7.0, which
  would flag every Tumbleweed with 2014's Shellshock. For openSUSE's "… on GA media" records sieve trusts the
  build named in the title instead.
- **`sieve verify` can't check npm** (npm keeps no per-file checksums for installed packages), and it can't tell a
  careful attacker with root from nothing: they can rewrite the checksum lists too. See [Verify](#verify).
- **Go binaries built before Go 1.18** store their build info differently and are counted but not read.
- **In use is a snapshot**, and only native code is visible: pure-Python, npm, Go and Rust packages are always
  "unknown". See [In use](#in-use).
- Ubuntu fixes that only exist in Ubuntu Pro (ESM) are shown as "fix needs Ubuntu Pro (ESM)", not as fixable.
- The advisory data comes from OSV.dev, KEV from CISA and EPSS from FIRST, so scanning needs outbound HTTPS to
  `api.osv.dev`, `secdb.alpinelinux.org`, `www.cisa.gov` and `epss.empiricalsecurity.com`. Package names and
  versions are sent to OSV.dev; nothing else about the machine is.

## Relationship to warden

sieve is the scanner inside warden, on its own. warden adds the parts that need a server: scanning many machines
over SSH, history, a console, alerts and patching. If you only want to know what to patch on one box, sieve is
enough.

## Benchmark

A weekly job ([`bench.yml`](.github/workflows/bench.yml)) scans the same deliberately old public images, pinned
by digest, with sieve, trivy, grype and osv-scanner, then compares the CVEs each one found, per image. It checks
which tools caught the known-exploited (KEV) ones, and lists the KEV and critical CVEs sieve missed, with the
reason where the data shows one. The results are in [`bench/RESULTS.md`](bench/RESULTS.md), and how they're made
is in [`bench/run.py`](bench/run.py).

## Development

```
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

The tests run offline; OSV is stubbed.

## Support

If sieve is useful to you, [buy me a coffee](https://buymeacoffee.com/iamc_tech). More field notes at [dev.to/iam-tech](https://dev.to/iam-tech).

## Licence

AGPL-3.0, the same as warden. Copyright (C) 2026 casareanderson. See [LICENSE](LICENSE).
