# Changelog

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
