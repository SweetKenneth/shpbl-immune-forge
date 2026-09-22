# Changelog

## 0.2.2 — 2026-09-22

Adversarial promotion-soundness hardening.

### Fixed

- **A reproduced baseline could enter mutation evaluation even when the attack had not succeeded.** With the default reproduction gate, the baseline must now both reproduce the event and report `attackSucceeded: true`; otherwise the episode is `INCONCLUSIVE` with `BASELINE_ATTACK_NOT_SUCCESSFUL`.
- **Data-driven candidate replay observations were associated with an episode but not cryptographically bound to its sealed scenario.** Candidate replays must now carry the sealed `scenarioId`; missing or mismatched bindings fail the replay gate. This binds the reporter's claim to the episode without claiming to prove an external harness was truthful.
- **Negative fitness margins could weaken the positive-improvement gate.** `requiredFitnessMargin` is now required to be finite and non-negative at both library and MCP boundaries.
- **Duplicate explicit mutation IDs were only rejected by the MCP parser.** The library adjudication API now enforces the same uniqueness invariant, preventing ambiguous `winnerId` values.

### Added

- Adversarial regressions covering baseline-not-defeated episodes, wrong scenario bindings, duplicate library mutation IDs, and negative policy margins.


## 0.2.1 — 2026-09-22

Submission-hardening release. Adjudication semantics and `CIF/0.2` evidence remain unchanged.

### Fixed

- Complete newline-delimited requests are separated before size enforcement, so an oversized request cannot
  swallow an adjacent valid request delivered in the same transport chunk.
- JSON-RPC batch arrays, wrong protocol versions, and malformed request envelopes now fail explicitly with
  `-32600` instead of being silently treated as notifications.
- Added the lockfile required for reproducible `npm ci` installation and changed CI to use it.
- Corrected stale provenance and Exchange-status wording; added the required Tenable `domains` field to the
  listing draft.

### Added

- Three transport regression tests (47 total).

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
