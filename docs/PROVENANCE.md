# Provenance and status — Counterfactual Immune Forge

## Invention and authorship
Invented, specified and authored by SHPBL (Kenneth E. Sweet Jr.). The public artifact is a clean-room
implementation written from the public behavioural specification (`SPEC.md`). No proprietary SHPBL library
bodies, harvested capability bodies, or third-party code are included in this package.

## Composition claim (what SHPBL contributes)
The Forge is a composition of capability shapes SHPBL had already proven separately — event replay, sandboxed
blast-radius screening, protected-behaviour regression authority, evolutionary fitness scoring, hash-sealed
evidence, and post-proof exploratory analysis — arranged into a single gate chain in which none of them can be
skipped and none can be reordered. The novelty is the enforced ordering plus the preservation of rejected
candidates, not any individual step.

## Public IP surface
Released publicly: the protocol shape (`CIF/0.3`), the gate ordering, the evidence-root construction, the
MCP tool surface, and this implementation. Not released: any SHPBL private engine, corpus, harvested body,
scoring internals, or catalog material. The public bytes were written for release; nothing was copied out of
the private library.

## Dependencies
Zero runtime dependencies. Platform imports limited to `node:crypto`. No application-level filesystem or network
access, subprocess spawning, or environment-variable reads anywhere in `src/`; the stdio server necessarily uses
stdin/stdout — asserted by `tests/disclosure.test.ts`.

## Verification
- `npm test` — build plus conformance, adversarial, boundary and MCP handshake tests.
- `npm run typecheck` — strict TypeScript, no emit.
- `docs/RELEASE-MANIFEST.md` — SHA-256 of every released file.

## Tenable status
Submitted to the Tenable CyberAgents Exchange on 2026-09-12 and initially merged as pull request #169
(<https://github.com/tenable/cyberagents-exchange/pull/169>). Tenable later removed the listing in pull request
#187 (<https://github.com/tenable/cyberagents-exchange/pull/187>) during its post-merge review. Version 0.2.0
closed the original candidate-neutralization gap; version 0.2.1 hardened transport and submission structure;
version 0.3.0 closes additional baseline-qualification, replay-binding, policy-margin, candidate-identity,
deep-immutability, lineage-state, and verification-anchor gaps found during adversarial review. The listing is not currently published by the Exchange. The public repository is
<https://github.com/SweetKenneth/shpbl-immune-forge>.
