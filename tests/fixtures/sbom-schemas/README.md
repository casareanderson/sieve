Official JSON schemas, vendored so the SBOM tests validate offline. Tests only: left out of the sdist (MANIFEST.in)
and the Docker image (.dockerignore excludes tests/).

- bom-1.6.schema.json, spdx.schema.json, jsf-0.82.schema.json: CycloneDX 1.6, from
  https://github.com/CycloneDX/specification (tag 1.6), Apache-2.0, (c) OWASP Foundation.
- spdx-schema.json: SPDX 2.3, from https://github.com/spdx/spdx-spec (tag v2.3), CC-BY-3.0, (c) The Linux Foundation
  and its contributors.
