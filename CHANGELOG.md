# Changelog

## Unreleased

### Scanning

- RPM distributions: AlmaLinux, Rocky Linux, RHEL (including UBI images) and openSUSE Leap and Tumbleweed, for
  host and container scans. The rpm database is read directly (SQLite, ndb and BerkeleyDB), so no `rpm` binary is
  needed; an unreadable database is reported, never treated as empty. On a live host with an unreadable database
  sieve falls back to `rpm -qa` when the binary is there.
- rpm version ordering (epoch, `~`, `^`, rpm's segment rules), checked against rpm's own test cases.
- RHSA/ALSA/RLSA/SUSE-SU errata are expanded into their CVEs and keep the distro's Critical/Important/Moderate/Low
  rating. AlmaLinux errata list their CVEs under `related`, which is now kept in the cache (cache schema 3).
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

### Output

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
