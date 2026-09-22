# Release manifest — Counterfactual Immune Forge v0.3.0

Frozen 2026-09-22 from commit `9fc017a1704447533aafe989a383769b108efa13`. SHA-256 over every released source/configuration file. Build output (`dist/`), `node_modules/`, package tarballs, and the two self-referential digest files (`docs/SHA256SUMS.txt`, `docs/RELEASE-MANIFEST.md`) are excluded so the manifest verifies cleanly with `sha256sum -c docs/SHA256SUMS.txt`.

Files: 22

Manifest root (SHA-256 of the exact `hash  path` lines in `docs/SHA256SUMS.txt`, including the final newline): `e1f79fb2841e04d002bd0ec2026203f6b4e875ee9e2049bc61431a864de4c73a`

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `.github/workflows/ci.yml` | 609 | `02a7755b66be90e93f863ec54427ddfc5bc13256e2f29839470f3f2277684d73` |
| `.github/workflows/codeql.yml` | 631 | `2e782779d6fa0176b6e076e432b68b792e5bdda33698bc775dafcf15d500bcc8` |
| `.github/workflows/secrets.yml` | 516 | `45be75927339739cbcc4071cd20a9dba2e5fe4d33240cb69b5ab34b6b47d336b` |
| `.gitignore` | 26 | `e8e70120c7fb8891ed746bb896e739a62f7f6ea1df6225461506760c146f6614` |
| `CHANGELOG.md` | 9688 | `96a801b31a5f8ea7bfcb3f128842d3e662edbaed0e1d0b045a7f31dab9c058ff` |
| `LICENSE` | 1085 | `fc6632072900299a548580ac3a0fecce83708ac431962b4bbbb178a338eb884b` |
| `README.md` | 12878 | `5629421532e9b140ff35d734a8cd54660ac4811bdee81f3ea74525f1a6f64775` |
| `SPEC.md` | 3076 | `f471f235380d4e8f27b113bbe81a5f533b3553eaf481692c901cb44d5ed6c81c` |
| `docs/PROVENANCE.md` | 2583 | `036f410773ea0847aae6f1dd711536c8bb7b0875dc4c390ac4dbe98bc9df813f` |
| `docs/tenable-listing-draft.md` | 5727 | `1f638861278e3e6797f9817ef2b776e6675e5be29efc0a784b857e263a590c7a` |
| `package-lock.json` | 1633 | `7775ab0ead9f2f0d3c2d5116f796264d3235d0babe3df0f4fa968ca241c176af` |
| `package.json` | 1353 | `53065944b030ce4dd018fff45a5a14b1bf4a8d65eb04b22178fbc59a3ee8962a` |
| `src/adjudicate.ts` | 5172 | `32b437fd3765e5d19b62c5514335f9d9344bb1d156c1f5a5d7e3066f293f87c1` |
| `src/core.ts` | 31951 | `9f97fca1d6061fca32f61f554da4a25d160028d7972eb852691dcd17ac07afbc` |
| `src/index.ts` | 122 | `c4ea44b4029ec1a64f68e6b613c3a2f7351e14cfc6c798fee4e9bbfa8ae3820a` |
| `src/lineage.ts` | 5836 | `d2bf73df5169be536026c80dba4855e7fc14742b294581361dfd0d0f5d85b7eb` |
| `src/mcp-server.ts` | 27989 | `71485b513a04fc324171599e8f59ce05892639f1670eee5cfaecf7c749bd07df` |
| `tests/adjudicate.test.ts` | 11258 | `422b7b63a2753b3353b9aaf15069b98e7c866f2fcf22cb78812e5ffea76b7a27` |
| `tests/core.test.ts` | 26676 | `82b302651b62954db5e8591fd96966dd9cbc8fc310087168db7e5862bf8d7042` |
| `tests/disclosure.test.ts` | 2391 | `6b7c2be384764b551d3d9c1cef0b2c00a615dc3922ae7387ff2d5737348f7d49` |
| `tests/mcp-server.test.ts` | 22182 | `8a84cff8843fe33a4e8b7ef3fd6d9e6f6f412877f2d35b3b01944d42a2627d81` |
| `tsconfig.json` | 402 | `514b72ed77d5d3db2ce8f6128f2495453c1786c3f26fcf313215d731c0c0a788` |
