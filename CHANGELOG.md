# Changelog

## 0.1.0 (2026-10-10)

First release, extracted from warden's vulnerability scanner.

- `sieve host`, `sieve containers`, `sieve all`: OS packages (dpkg, apk), Python, npm, Go and Rust (cargo-auditable)
  packages matched against OSV.dev, with Alpine secdb merged in.
- Ranking by CISA KEV, then EPSS >= 10% with a fix, then CRITICAL with a fix.
- `--json`, `--min-severity`, `--kev-only`, `--fixable-only`, `--cache`, `--no-epss`, `--kernel`, `--limit`.
- `sieve collector` and `sieve containers --from-tar` for scanning containers on another machine.
- Exit code 1 when a known-exploited finding is reported, 2 when part of the scan failed.
- DSA/DLA/USN notices are expanded into their CVEs when no per-CVE record covers them. OSV has only notices for
  older releases such as Debian 10 and 11, which warden's matcher skipped.
