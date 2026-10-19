# sieve benchmark results

Generated 2026-10-19 10:53 UTC by [`bench/run.py`](run.py) on GitHub Actions (ubuntu24, 4 CPUs). This file is overwritten by the weekly [bench workflow](../.github/workflows/bench.yml); don't edit it by hand. Raw numbers: [`results.json`](results.json).

## Summary

- **8 images**, deliberately old, pinned by digest ([`images.txt`](images.txt)).
- **Distinct CVEs per image, summed:** sieve 732, trivy 939, grype 1283, osv-scanner 842. More is not automatically better: tools differ in what they count (see *How to read this*).
- **CISA KEV:** 4 known-exploited (image, CVE) pairs found by at least one tool. Caught: sieve 3, trivy 3, grype 4, osv-scanner 3.
- **sieve missed** 682 (image, CVE) pairs that at least one other tool reported; 1 of them are in KEV and 54 more are rated CRITICAL by another tool (listed under *Where sieve misses*). sieve reported 0 that no other tool did.

## How to read this

- Findings are compared **by CVE id per image**, not by package: tools name packages differently (binary vs source package), so package-level matching would mostly measure naming. GHSA/PYSEC/Go ids are mapped to their CVE alias where the tool gives one; DSA/DLA/USN notices are expanded into the CVEs they bundle; ids with no CVE are compared as they are.
- Defaults differ and are kept as shipped: unfixed vulnerabilities are included by every tool here, but each tool applies its own distro triage (Debian *unimportant*, Ubuntu *negligible*, "won't fix", vendor not-affected statements). A CVE one tool reports and another doesn't is not automatically a miss; it can be a disagreement about whether it applies.
- "Critical" means at least one tool rated it CRITICAL; severities disagree between tools.
- trivy, grype and osv-scanner scan a `docker save` tar of each image; sieve scans a running container of the same image, which is how it is meant to be used. sieve's time is one run over all images, from a cold advisory cache. trivy's and grype's scan times exclude their database download, shown separately.
- The *likely reason* column only states a category the data supports (kernel package, a package type sieve does not read, or what an OSV.dev query for that package version returned at run time). Otherwise it says `unknown`.

## Tools

| tool | version | total scan time | peak memory | notes |
|---|---|---|---|---|
| sieve | 0.6.0 | 24s | 107 MB | queries OSV.dev online, cold cache; one run over all images |
| trivy | 0.74.0 | 2.1s | 342 MB | DB download 6.9s |
| grype | 0.119.0 | 22s | 333 MB | DB update 78s |
| osv-scanner | 2.6.0 | 13s | 458 MB | queries OSV.dev online, no local DB |

Peak memory is the largest per-image peak resident set size from `/usr/bin/time -v` (for sieve, the single run including its container collector).

## Per image

### debian-10.13-slim

`debian:10.13-slim@sha256:bb3dc79fddbca7e8903248ab916bb775c96ec61014b3d02b4f06043b604726dc` · sieve: debian 10, 84 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 4 | | | | 0/0 |
| trivy | 37 | 4 | 0 | 33 | 0/0 |
| grype | 75 | 4 | 0 | 71 | 0/0 |
| osv-scanner | 4 | 4 | 0 | 0 | 0/0 |

### debian-11.6-slim

`debian:11.6-slim@sha256:9404b05bd09b57c76eccc0c5505b3c88b5feccac808d9b193a4fbac87bb44745` · sieve: debian 11, 96 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 57 | | | | 1/1 |
| trivy | 270 | 57 | 0 | 213 | 1/1 |
| grype | 214 | 57 | 0 | 157 | 1/1 |
| osv-scanner | 61 | 57 | 0 | 4 | 1/1 |

Known-exploited CVEs found by any tool:

| CVE | package | sieve | trivy | grype | osv-scanner |
|---|---|---|---|---|---|
| CVE-2023-4911 | libc-bin, libc6 | ✔ | ✔ | ✔ | ✔ |

### debian-12.0-slim

`debian:12.0-slim@sha256:9bd077d2f77c754f4f7f5ee9e6ded9ff1dff92c6dce877754da21b917c122c77` · sieve: debian 12, 88 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 190 | | | | 1/1 |
| trivy | 196 | 189 | 1 | 7 | 1/1 |
| grype | 188 | 188 | 2 | 0 | 1/1 |
| osv-scanner | 190 | 190 | 0 | 0 | 1/1 |

Known-exploited CVEs found by any tool:

| CVE | package | sieve | trivy | grype | osv-scanner |
|---|---|---|---|---|---|
| CVE-2023-4911 | libc-bin, libc6 | ✔ | ✔ | ✔ | ✔ |

### ubuntu-focal-20220426

`ubuntu:focal-20220426@sha256:47f14534bda344d9fe6ffd6effb95eefe579f4be0d508b7445cf77f61a0e5724` · sieve: ubuntu 20.04, 92 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 74 | | | | 0/0 |
| trivy | 46 | 46 | 28 | 0 | 0/0 |
| grype | 183 | 68 | 6 | 115 | 0/0 |
| osv-scanner | 192 | 74 | 0 | 118 | 0/0 |

### ubuntu-jammy-20220801

`ubuntu:jammy-20220801@sha256:34fea4f31bf187bc915536831fd0afc9d214755bf700b5cdb1336c82516d154e` · sieve: ubuntu 22.04, 101 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 290 | | | | 1/1 |
| trivy | 228 | 228 | 62 | 0 | 1/1 |
| grype | 257 | 257 | 33 | 0 | 1/1 |
| osv-scanner | 307 | 290 | 0 | 17 | 1/1 |

Known-exploited CVEs found by any tool:

| CVE | package | sieve | trivy | grype | osv-scanner |
|---|---|---|---|---|---|
| CVE-2023-4911 | libc-bin, libc6 | ✔ | ✔ | ✔ | ✔ |

### alpine-3.18.0

`alpine:3.18.0@sha256:02bb6f428431fbc2809c5d1b41eab5a68350194fb508869a33cb1af4444c9b11` · sieve: alpine 3.18.0, 15 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 22 | | | | 0/0 |
| trivy | 22 | 22 | 0 | 0 | 0/0 |
| grype | 28 | 22 | 0 | 6 | 0/0 |
| osv-scanner | 22 | 22 | 0 | 0 | 0/0 |

### python-3.9.16-slim-buster

`python:3.9.16-slim-buster@sha256:83c6f59ca894629d710ea03243819b8af63e1b074c5a1bdc96f2b8694163e65f` · sieve: debian 10, 96 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 33 | | | | 0/0 |
| trivy | 78 | 33 | 0 | 45 | 0/0 |
| grype | 195 | 33 | 0 | 162 | 0/0 |
| osv-scanner | 36 | 33 | 0 | 3 | 0/0 |

### node-16.20.0-alpine3.17

`node:16.20.0-alpine3.17@sha256:01b4c77bab0eec8c12c15ca96d1da583ee61d3bd710432d6fa5d0bf9132ae5e0` · sieve: alpine 3.17.4, 222 packages

| tool | CVEs | in both (with sieve) | sieve only | this tool only | KEV caught |
|---|---|---|---|---|---|
| sieve | 62 | | | | 0/1 |
| trivy | 62 | 62 | 0 | 0 | 0/1 |
| grype | 143 | 62 | 0 | 81 | 1/1 |
| osv-scanner | 30 | 30 | 32 | 0 | 0/1 |

Known-exploited CVEs found by any tool:

| CVE | package | sieve | trivy | grype | osv-scanner |
|---|---|---|---|---|---|
| CVE-2023-44487 | node | ✘ | ✘ | ✔ | ✘ |

## Where sieve misses

KEV and CRITICAL CVEs at least one other tool reported and sieve did not. *sieve saw package* means sieve reported some other CVE for the same package name in that image. *OSV lists it* is the result of querying OSV.dev for that package version during the run (`-` = not asked or the query failed).

| image | CVE | KEV | severity | package | found by | sieve saw package | OSV lists it | likely reason |
|---|---|---|---|---|---|---|---|---|
| node-16.20.0-alpine3.17 | CVE-2023-44487 | yes | HIGH | node | grype | no | - | package type sieve does not read (binary) |
| debian-10.13-slim | CVE-2019-8457 |  | CRITICAL | libdb5.3 | trivy, grype | no | no | OSV does not list this CVE for db5.3 5.3.28+dfsg1-0.5 in Debian:10 (OSV coverage, import lag or distro triage) |
| debian-10.13-slim | CVE-2023-45853 |  | CRITICAL | zlib1g | trivy | no | no | OSV does not list this CVE for zlib 1:1.2.11.dfsg-1+deb10u2 in Debian:10 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2019-8457 |  | CRITICAL | libdb5.3 | trivy, grype | no | no | OSV does not list this CVE for db5.3 5.3.28+dfsg1-0.8 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2023-45853 |  | CRITICAL | zlib1g | trivy | no | no | OSV does not list this CVE for zlib 1:1.2.11.dfsg-2+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-12087 |  | CRITICAL | perl-base | trivy, grype | yes | no | OSV does not list this CVE for perl 5.32.1-4+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-13221 |  | CRITICAL | perl-base | trivy, grype | yes | no | OSV does not list this CVE for perl 5.32.1-4+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-33845 |  | CRITICAL | libgnutls30 | trivy, grype | yes | no | OSV does not list this CVE for gnutls28 3.7.1-5+deb11u3 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-42010 |  | CRITICAL | libgnutls30 | trivy, grype | yes | no | OSV does not list this CVE for gnutls28 3.7.1-5+deb11u3 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-42496 |  | CRITICAL | perl-base | trivy, grype | yes | no | OSV does not list this CVE for perl 5.32.1-4+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-5450 |  | CRITICAL | libc-bin, libc6 | trivy, grype | yes | no | OSV does not list this CVE for glibc 2.31-13+deb11u5 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-57433 |  | CRITICAL | perl-base | trivy, grype | yes | no | OSV does not list this CVE for perl 5.32.1-4+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-75803 |  | CRITICAL | libssl1.1 | trivy, grype | yes | no | OSV does not list this CVE for openssl 1.1.1n-0+deb11u4 in Debian:11 (OSV coverage, import lag or distro triage) |
| debian-11.6-slim | CVE-2026-8376 |  | CRITICAL | perl-base | trivy, grype | yes | no | OSV does not list this CVE for perl 5.32.1-4+deb11u2 in Debian:11 (OSV coverage, import lag or distro triage) |
| node-16.20.0-alpine3.17 | CVE-2022-48174 |  | CRITICAL | busybox, busybox-binsh, ssl_client | grype | yes | no | OSV does not list this CVE for busybox 1.35.0-r29 in Alpine:v3.17 (OSV coverage, import lag or distro triage) |
| node-16.20.0-alpine3.17 | CVE-2023-32002 |  | CRITICAL | node | grype | no | - | package type sieve does not read (binary) |
| node-16.20.0-alpine3.17 | CVE-2026-31789 |  | CRITICAL | libcrypto3, libssl3 | grype | yes | no | OSV does not list this CVE for openssl 3.0.9-r1 in Alpine:v3.17 (OSV coverage, import lag or distro triage) |
| node-16.20.0-alpine3.17 | CVE-2026-34182 |  | CRITICAL | libcrypto3, libssl3 | grype | yes | no | OSV does not list this CVE for openssl 3.0.9-r1 in Alpine:v3.17 (OSV coverage, import lag or distro triage) |
| node-16.20.0-alpine3.17 | CVE-2026-75803 |  | CRITICAL | libcrypto3, libssl3 | grype | yes | no | OSV does not list this CVE for openssl 3.0.9-r1 in Alpine:v3.17 (OSV coverage, import lag or distro triage) |
| python-3.9.16-slim-buster | CVE-2019-8457 |  | CRITICAL | libdb5.3 | trivy, grype | no | no | OSV does not list this CVE for db5.3 5.3.28+dfsg1-0.5 in Debian:10 (OSV coverage, import lag or distro triage) |
| python-3.9.16-slim-buster | CVE-2023-45853 |  | CRITICAL | zlib1g | trivy | no | no | OSV does not list this CVE for zlib 1:1.2.11.dfsg-1+deb10u2 in Debian:10 (OSV coverage, import lag or distro triage) |
| python-3.9.16-slim-buster | CVE-2025-4517 |  | CRITICAL | python | grype | no | - | package type sieve does not read (binary) |
| python-3.9.16-slim-buster | CVE-2026-19445 |  | CRITICAL | python | grype | no | - | package type sieve does not read (binary) |
| ubuntu-focal-20220426 | CVE-2011-10043 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2017-20230 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2019-1010022 |  | CRITICAL | libc-bin, libc6 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2021-33574 |  | CRITICAL | libc-bin, libc6 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2021-46848 |  | CRITICAL | libtasn1-6 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2025-13151 |  | CRITICAL | libtasn1-6 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2025-14831 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2025-69720 |  | CRITICAL | libncurses6, libncursesw6, libtinfo6 … | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2025-9820 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-12087 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-13221 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-33845 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-33846 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-3833 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-4176 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-42009 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-42010 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-42496 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-5260 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-5450 |  | CRITICAL | libc-bin, libc6 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-57432 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-57433 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-8376 |  | CRITICAL | perl-base | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-88647 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-focal-20220426 | CVE-2026-95210 |  | CRITICAL | libgnutls30 | grype, osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-2673 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-34181 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-34183 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-42764 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-42768 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-42769 |  | CRITICAL | libssl3 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |
| ubuntu-jammy-20220801 | CVE-2026-5419 |  | CRITICAL | libgnutls30 | osv-scanner | yes | yes | unknown: OSV lists this CVE for the installed version, sieve did not report it |

---

KEV catalog version 2026.10.16 (1748 entries). Reproduce: run the bench workflow, or see the top of `bench/run.py`.
