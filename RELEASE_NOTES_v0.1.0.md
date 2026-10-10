sieve 0.1.0 is the first release. It's the vulnerability scanner from warden, split out so it can be used on its
own: it reads the package lists already on a Linux box and in its running containers, asks OSV.dev which
advisories affect those exact versions, and ranks what it finds by CISA KEV and EPSS. Its only dependency is
`requests`; there's no scanner binary or vulnerability database to download.

## What it does

- Scans the host (`sieve host`), every running Docker container (`sieve containers`, needs root) or both
  (`sieve all`).
- Covers dpkg and apk OS packages, plus Python, npm, Go and Rust (cargo-auditable) packages inside images.
  Debian, Ubuntu and Alpine have OS advisory feeds; other distributions get their language packages checked.
- Puts known-exploited (KEV) findings first, then fixable findings with an EPSS of 10% or more, then fixable
  CRITICAL ones. Most of the rest is "affected, no fix yet", and the filters (`--fixable-only`,
  `--min-severity`, `--kev-only`) let you hide it.
- Exits 1 when a known-exploited finding is in the output and 2 when part of the scan failed, so it fits in cron
  or CI. `--json` gives the full report.
- Scans containers on another machine with a standalone collector script:
  `sieve collector | ssh root@dockerhost python3 - > packages.tgz`, then `sieve containers --from-tar packages.tgz`.

## Ways to run it

- pipx: `pipx install git+https://github.com/casareanderson/sieve`
- Docker: `docker run --rm -v /:/host:ro ghcr.io/casareanderson/sieve host --root /host`
- GitHub Actions: `uses: casareanderson/sieve@v1`. The `v1` tag follows the latest 0.x release; pin `@v0.1.0`
  if you'd rather it didn't move.

## Things to know

- Package names and versions are sent to OSV.dev. Scanning needs outbound HTTPS to `api.osv.dev`,
  `secdb.alpinelinux.org`, `www.cisa.gov` and `epss.empiricalsecurity.com`.
- Vendored, forked or renamed packages can't be matched, and OSV can lag the original advisories by hours or
  occasionally days.
- Kernel packages are skipped by default (`--kernel` includes them).
- The Docker image can't scan running containers itself; pipe the collector into `containers --from-tar -`
  as shown in the README.

Licensed under AGPL-3.0. The full list of changes is in CHANGELOG.md.
