sieve 0.2.0 goes from "scan this Linux box" to four new questions: **is a known-malicious package installed, is the vulnerable code actually running, has anything installed been changed, and what about the machines I'm not logged into?** It still needs no scanner binary and no vulnerability database, and its only dependency is still `requests`.

## New

- **Known-malicious packages, ranked above everything.** OSV.dev carries OpenSSF's malicious-package reports (`MAL-…`). sieve now treats those as their own top tier, above CISA KEV: `☠ MALWARE`, never hidden by a filter, exit code 1. Checked against the real thing: a lockfile pinning `flatmap-stream@0.1.1` (the 2018 event-stream backdoor) comes back as `MAL-2025-20690`.
- **`sieve path DIR`**: scan a project before you install it, from `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `node_modules`, `requirements*.txt`, `poetry.lock`, `uv.lock` and virtualenvs. `sieve host` also reads global npm installs now (no node needed): on the test box that was 221 packages no scan had looked at before.
- **In use: is it actually loaded?** Every finding says whether its package's code is mapped into a running process right now (`yes` / `no` / `?`), with `↻` when an upgrade replaced a file but the old copy is still running. Loaded findings sort first within their tier, and `--in-use-only` keeps just those. On a Docker host with 11 images, 1,162 of 6,771 findings (17%) were in running code. Without root it says how much it could see, and never claims "not loaded".
- **`sieve verify`**: has any installed file changed since its package manager put it there? It re-hashes files against the checksums already on disk (dpkg, apk, rpm, pip RECORD). A Proxmox node's 70,795 files took 34 seconds. It's a tripwire, not proof: someone with root can rewrite the checksum lists too. npm keeps no per-file checksums, so it can't be verified.
- **`sieve remote user@host`**: scan another machine over SSH, host and running containers, with only `python3` needed there. Nothing is copied or written on the other side, and the in-use check runs there too.
- **RPM distributions**: AlmaLinux, Rocky, RHEL and UBI, openSUSE Leap and Tumbleweed. The rpm database (SQLite, ndb or BerkeleyDB) is read directly, with no `rpm` binary needed. Fedora, CentOS Stream, Oracle and Amazon Linux are counted, with a note that OSV has no feed for them.
- **SARIF 2.1.0** (`--sarif`, and a `sarif` input on the GitHub Action) for GitHub code scanning, validated against the OASIS schema.

## Fixed along the way

- Container scans on rpm images would have read the **Docker host's** rpm database, because SQLite resolves `/proc/<pid>/root` back to the host. It now reads a private copy.
- One openSUSE record in OSV lists bash's fix as version 7.0, which made every Tumbleweed box show Shellshock as known-exploited. Records of that type now trust the build named in their title.

## Upgrading

- The advisory cache schema is now 4, so the first scan after upgrading refetches advisories once.
- The table's first column is now `ALERT` (was `KEV`), and a new `IN USE` column sits after `SEVERITY`. If you parse the table, use `--json`.
- The Action's `v1` tag now points at 0.2.0; pin `@v0.2.0` if you'd rather it didn't move.

162 tests. AGPL-3.0.
