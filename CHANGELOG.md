# Changelog

## 0.2.0 (2026-10-11)

### Scanning

- `sieve remote user@host`: scan another machine over ssh, covering what `sieve all` would there: dpkg, apk or rpm,
  Python outside the OS, global npm, and its running containers. Only python3 is needed on the other side: the
  standard-library collector is piped to `python3 -I -` (a new `host` mode for the machine itself), nothing is
  copied or written there, and rpm databases are read there so only the package list comes back. Local and remote
  host scans share one code path, so an unreadable rpm database is partial, never empty, either way. The in-use
  check runs on the remote machine (it reads that machine's `/proc`), with the same rules as a local scan. `--sudo`
  (`sudo -n`, never a password prompt), `--no-containers`, `--port`, `-i`, `--ssh-opt`; ssh runs in BatchMode with a
  connect timeout, and a failed run says why (no key auth, no python3, sudo wants a password). `--json`, `--sarif`
  and `--in-use-only` work with it.
- RPM distributions: AlmaLinux, Rocky Linux, RHEL (including UBI images) and openSUSE Leap and Tumbleweed, for
  host and container scans. The rpm database is read directly (SQLite, ndb and BerkeleyDB), so no `rpm` binary is
  needed; an unreadable database is reported, never treated as empty. On a live host with an unreadable database
  sieve falls back to `rpm -qa` when the binary is there.
- rpm version ordering (epoch, `~`, `^`, rpm's segment rules), checked against rpm's own test cases.
- RHSA/ALSA/RLSA/SUSE-SU errata are expanded into their CVEs and keep the distro's Critical/Important/Moderate/Low
  rating. AlmaLinux errata list their CVEs under `related`, which is now kept in the cache.
- rpm packages are queried under both their binary and source names, because Rocky indexes source packages while
  AlmaLinux and Red Hat index binaries.
- Fedora, CentOS Stream, Oracle Linux and Amazon Linux are read and counted, with a note that OSV has no feed for
  them.
- Python packages under `/usr/lib*/python3*` on rpm distributions are left to the rpm advisories, as dpkg-owned
  ones already were.
- Containers: the package count is installed packages, not OSV queries.
- `kernel`, `kernel-core`, `kernel-modules` and friends are skipped like `linux-image-*` unless `--kernel`.
- openSUSE "… on GA media" records whose title names a build at or below the installed one are ignored: one gave
  bash 5.3 on Tumbleweed a fixed version of 7.0 and flagged Shellshock.
- `sieve path DIR ...`: scan project directories: `package-lock.json` (v1-3), `yarn.lock` (classic and berry),
  `pnpm-lock.yaml` (v5, v6, v9, read without a YAML library), `node_modules` trees, `requirements*.txt` pins,
  `poetry.lock`, `uv.lock` and virtualenv `site-packages`. Lockfiles it can't read are reported, never silently empty.
- `sieve host` also reads global npm packages (`/usr/lib/node_modules`, `/usr/local/lib/node_modules`, an npmrc
  `prefix=`), without needing node. npm packages that dpkg installed, and those under `/usr/lib/node_modules` on rpm
  distributions (host and containers), are left to the distro's advisories.
- Known-malicious packages (OpenSSF `MAL-` ids, or advisories filed as CWE-506, in any ecosystem) are a new top tier
  above KEV: one finding per package with the duplicate records in `related`, no "fixed" version, never hidden by a
  filter, and exit code 1 like KEV.
- The advisory cache schema is now 4 (it keeps AlmaLinux `related` CVEs and the malicious flag), so the first scan
  after upgrading refetches advisories once.
- **In use**: every finding says whether its package's code is loaded in a running process right now (`yes`, `no`
  or `?`, from `/proc/<pid>/maps` traced back through dpkg/apk/rpm file lists and wheel `RECORD`s), with `↻` when an
  upgrade replaced the file but the old copy is still running. Loaded findings rank first within their tier;
  `--in-use-only` keeps just those. In the table, `--json` (`in_use`, `restart_needed`, per-target process
  coverage) and SARIF (`inUse`, `restartNeeded`). Containers get it from the collector, for every container of an
  image. Without root it reports how many processes it could read and never says `no`. rpm file lists come from
  the same rpmdb read as the package list.

### Verify

- `sieve verify`: has any installed file changed since its package manager put it there? Re-hashes files against
  the checksums already on disk: dpkg md5sums, the apk database (SHA-1), the rpm database's file digests (from the
  same header parse the CVE scan uses) and pip RECORD files (SHA-256). No binary, no download, no root for the host.
  `--root DIR`, `--containers [--host]` (running containers read in place, mount points skipped, absolute symlinks
  kept inside the container), `--packages`, `--include-config`, `--all-missing`, `--json`, `--sarif`.
- Security-critical paths (system binaries, PAM, sshd, sudo, libc, the loader) are marked ⚠ and are SARIF `error`.
- Skipped by design, the way the package managers themselves skip them: conffiles / `%config`, dpkg `path-exclude`,
  rpm files that were never installed or are marked `%verify(not md5)`, and Debian's `/usr`-merge diversions.
  Docs, man pages and translations deleted by minimal images are counted as trimmed, not listed.
- A changed pip file that matches another installed distribution's RECORD is reported as "now X's file" (two
  distributions sharing one folder, e.g. PyJWT and jwt).
- Exit code 1 when a file changed; missing files are reported but don't fail the run. npm is documented as
  uncheckable: it keeps no per-file checksums.

### Output

- Known-malicious findings show as `☠ MALWARE`; the table's first column is now `ALERT`. In `--json` each finding
  has `malicious` and the summary counts it; in `--sarif` they are `error` with a security-severity of 10.0 and a
  `malicious` tag.
- `--sarif`: SARIF 2.1.0 output for GitHub code scanning, validated against the OASIS schema; the Action's new
  `sarif` input writes it from the same scan and returns its path as the `sarif` output.

## 0.1.0 (2026-10-10)

First release, extracted from warden's vulnerability scanner.

### Scanning

- `sieve host`, `sieve containers`, `sieve all`: OS packages (dpkg, apk), Python, npm, Go and Rust (cargo-auditable)
  packages matched against OSV.dev, with Alpine secdb merged in.
- Debian and Alpine packages are queried by source package and reported by binary package; version comparisons
  follow dpkg, apk, semver and PEP 440 rules, and Debian fixes are taken only from your own release.
- DSA/DLA/USN notices are expanded into their CVEs when no per-CVE record covers them. OSV has only notices for
  older releases such as Debian 10 and 11, which warden's matcher skipped.
- Kernel packages are skipped unless `--kernel` is given.
- `sieve collector` and `sieve containers --from-tar` for scanning containers on another machine.
- `--root PATH` reads the host's packages from another directory, for scanning from inside a container.

### Ranking and output

- Ranking by CISA KEV, then EPSS >= 10% with a fix, then CRITICAL with a fix.
- `--json`, `--min-severity`, `--kev-only`, `--fixable-only`, `--cache`, `--no-epss`, `--kernel`, `--limit`,
  `--version`.
- Advisories cached in SQLite and refetched only when OSV's `modified` stamp changes; KEV and EPSS refreshed at
  most every 20 hours, falling back to the last copy.
- Exit code 1 when a known-exploited finding is reported, 2 when part of the scan failed.

### Packaging

- Composite GitHub Action (`uses: casareanderson/sieve@v1`) with a job-summary table and `findings`, `kev`,
  `fixable` and `report` outputs.
- Docker image `ghcr.io/casareanderson/sieve`, built from release tags.
- CI on Python 3.10 to 3.13, and a weekly live scan against OSV.dev, KEV and EPSS to catch upstream changes.
