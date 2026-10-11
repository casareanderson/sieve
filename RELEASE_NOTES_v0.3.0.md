sieve 0.3.0 adds SBOMs, both directions: export what a scan found, and scan an SBOM that another tool made.

## New

- **`sieve <scan> --sbom cyclonedx|spdx`** — emit a CycloneDX 1.6 or SPDX 2.3 SBOM of exactly what the scan read: host, containers, a project directory (`sieve path`), or a remote machine (`sieve remote`). No OSV call needed for a plain export. Package URLs carry `distro=`, `upstream=` and the rpm epoch the way syft writes them, so other tools can read them. `--with-vulns` embeds the findings as CycloneDX `vulnerabilities` linked to their packages.
- **`sieve sbom FILE ...`** — scan an SBOM made by syft, trivy, cdxgen or GitHub's dependency graph (CycloneDX 1.4–1.6, SPDX 2.2/2.3 JSON) with sieve's usual OSV + CISA KEV + EPSS + malicious-package ranking. OS packages go back through the same distro mapping a host scan uses. Components it can't check (no package URL, no version, a type OSV doesn't cover) are counted and mark the scan partial — never silently dropped.

Still one runtime dependency (`requests`). The SBOM code is standard-library only and is loaded only when you ask for it, so a normal scan is unchanged. Output is validated against the official CycloneDX and SPDX schemas in CI.

## Upgrading

- The GitHub Action's `v1` tag now points at 0.3.0; pin `@v0.3.0` if you'd rather it didn't move.

178 tests. AGPL-3.0.
