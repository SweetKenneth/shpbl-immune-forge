# Changelog

## 0.2.0 — 2026-09-19

Hardening pass over the v0.1.0 release. Protocol bumped to `CIF/0.2` because the evidence root now covers an
additional field; `CIF/0.1` evidence is refused by verification rather than silently reported as tampered.

### Fixed

- **A candidate could be promoted while the attack still succeeded.** With the caller supplying a high fitness
  score, a mutation whose own replay reported `attackSucceeded: true` cleared the gates. A candidate that does
  not neutralize the sealed attack is now rejected as `ATTACK_NOT_NEUTRALIZED` before the regression gate, and
  the gate can only be waived explicitly through `requireAttackNeutralized: false`.
- **Non-finite numbers were hashed as `null`.** `canonical()` now refuses `NaN` and `±Infinity`, so two
  different observations can no longer share one evidence root. A non-finite fitness score is recorded as
  `NO_PROVEN_IMPROVEMENT` with no sealed score rather than crashing or passing.
- **Duplicate candidate observations silently overwrote each other.** Two observations of the same
  mutation/defense pair, or two candidates reusing one `mutation.id`, are now refused as ambiguous evidence.
- **The stdio transport raced itself.** Requests were dispatched concurrently per line, so replies could be
  reordered and lineage appends interleaved. Frames are now queued and answered strictly in arrival order, and
  an oversized frame no longer desynchronizes the reader.
- **Exported lineage entries were mutable.** `report()` now returns frozen entry copies.
- Conformance tests used `URL.pathname` as a filesystem path, which breaks on Windows.

### Added

- The effective gate settings are sealed inside the evidence root and returned as `evidence.policy`.
- Full JSON Schema for candidate observations in `tools/list`, plus `requireAttackNeutralized` in
  `describe_policy`.
- `repository` and `bugs` metadata, a `.gitignore`, and a GitHub Actions build/typecheck/test workflow.
- Ten new regression tests (44 total, from 34).
