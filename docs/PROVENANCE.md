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
Released publicly: the protocol shape (`CIF/0.1`), the gate ordering, the evidence-root construction, the
MCP tool surface, and this implementation. Not released: any SHPBL private engine, corpus, harvested body,
scoring internals, or catalog material. The public bytes were written for release; nothing was copied out of
the private library.

## Dependencies
Zero runtime dependencies. Platform imports limited to `node:crypto`. No filesystem, network, process, or
environment access anywhere in `src/` — asserted by `tests/disclosure.test.ts`.

## Verification
- `npm test` — build plus 30 conformance, adversarial, boundary and MCP handshake tests.
- `npm run typecheck` — strict TypeScript, no emit.
- `docs/RELEASE-MANIFEST.md` — SHA-256 of every released file.

## Tenable status
Prepared for submission to the Tenable CyberAgents Exchange. Submission does not imply review, approval,
certification, validation, endorsement, or acceptance by Tenable. No Contribution Agreement has been accepted
for this product, and no public repository or pull request has been created for it yet.
