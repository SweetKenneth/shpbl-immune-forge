# Changelog

## 0.3.0 — 2026-09-22

Adversarial promotion-soundness hardening. Evidence protocol bumped to `CIF/0.3` because replay evidence now carries sealed-scenario binding semantics and verification enforces CIF semantics in addition to distinguishing internal consistency from optional external root anchoring. `CIF/0.2` evidence is intentionally refused rather than silently reinterpreted under the stronger contract.

### Fixed

- **A reproduced baseline could enter mutation evaluation even when the attack had not succeeded.** With CIF/0.3's mandatory reproduction gate, the baseline must now both reproduce the event and report `attackSucceeded: true`; otherwise the episode is `INCONCLUSIVE` with `BASELINE_ATTACK_NOT_SUCCESSFUL`.
- **Data-driven candidate replay observations were associated with an episode but not cryptographically bound to its sealed scenario.** Candidate replays must now carry the sealed `scenarioId`; missing or mismatched bindings fail the replay gate. This binds the reporter's claim to the episode without claiming to prove an external harness was truthful.
- **Negative fitness margins could weaken the positive-improvement gate.** `requiredFitnessMargin` is now required to be finite and non-negative at both library and MCP boundaries.
- **Candidate fitness was implicitly compared to `baselineReplay.securityScore`, even though adapters may use a different fitness scale.** CIF/0.3 now requires an explicit baseline fitness from the same evaluator-defined scoring policy used for candidate fitness; inconclusive baselines do not require a fitness score.
- **Duplicate explicit mutation IDs were only rejected by the MCP parser.** The library adjudication API now enforces the same uniqueness invariant, preventing ambiguous `winnerId` values.
- **Adapter outputs and post-proof DREAM evidence were only shallowly protected.** Scenario, replay, candidate,
  regression, policy and final evidence snapshots are now deeply immutable JSON-compatible values; DREAM receives
  the sealed snapshot and cannot rewrite or suppress the decision.
- **Core replay did not receive candidate identity.** Two mutations sharing one defense identity could be
  conflated by an adapter. Candidate replay now receives the candidate as context, while existing two-argument
  adapters remain compatible.
- **The 256-candidate limit was MCP-only.** The core library now enforces the same limit.
- **Returned lineage entries could mutate internal lineage state, and append accepted tampered evidence.**
  Appended evidence is integrity-checked and stored/returned as an immutable entry.
- **Self-consistent replacement artifacts could be mistaken for externally anchored integrity.** Evidence and
  lineage verification now optionally accept an independently retained expected root/head and report internal
  consistency separately from anchor matching.
- **Canonical sealing accepted non-JSON objects and could recurse through cycles.** The sealing/snapshot layer
  now rejects cyclic, non-finite, executable and non-plain-object values instead of collapsing or recursing them.
- **The data-driven library API retained caller-owned mutable objects across async boundaries.** Episodes are
  now deeply snapshotted before validation/evaluation so late caller mutations cannot change a sealed decision.
- **The core library trusted TypeScript-only adapter shapes at runtime.** Replay, impact, regression, scenario,
  defense and candidate values are now runtime-validated so JavaScript truthiness or malformed objects cannot
  clear proof gates or create malformed evidence.
- **Session lineage could grow beyond the verifier's advertised 10,000-entry limit.** Lineage storage is now
  capped at the same shared limit, so the server cannot export a report its own verifier refuses by size.
- **Complete whitespace-padded stdio frames could bypass the 1 MiB request limit because size was measured after
  trimming.** Raw frame bytes are now measured before whitespace normalization.
- **Unknown direct-library policy keys were silently ignored.** CIF/0.3 now rejects unsupported policy keys so a
  typo cannot make a caller believe a stricter gate was applied when the engine actually used defaults.
- **Direct-library verification accepted some distinct JavaScript representations with the same canonical hash.**
  Explicit `undefined` optional properties and sparse arrays could normalize to omission / `null` without
  changing the Merkle root. Verification now requires a strict JSON representation before semantic/hash checks.
- **A caller could recompute a Merkle root over semantically impossible CIF evidence and still obtain internal hash consistency.**
  Verification now enforces the CIF/0.3 state machine itself: mandatory policy values, baseline/verdict consistency,
  candidate gate sequencing, rejection reasons, winner selection, candidate identity uniqueness and score thresholds.
- **Transport-level oversized-frame errors could overtake an earlier slow queued response.** All stdio responses,
  including frame errors, now share one arrival-order queue; malformed JSON-RPC IDs and tool-call parameters also fail closed.
- **The MCP handshake accepted malformed initialize requests and advertised an older revision.** The stdio server now
  validates required initialize fields and targets the 2025-11-25 initialize-based MCP revision.
- **The secret-scan workflow could fail before scanning on pull requests.** Gitleaks now receives the repository's
  automatically issued read-scoped GitHub token required by the action's PR mode.
- **Baseline fitness was evaluated before baseline reproduction had authority.** A throwing or invalid fitness
  evaluator could suppress an episode that should have been `INCONCLUSIVE`. Fitness is now evaluated only after
  the baseline replay both reproduces the event and reports the attack succeeding; inconclusive evidence omits
  `baselineFitness` entirely.

### Added

- Adversarial regressions covering baseline-not-defeated episodes, wrong scenario bindings, duplicate library
  mutation IDs, negative policy margins, post-proof mutation attempts, contradictory regression results,
  candidate-ID collisions, non-JSON sealing, lineage mutation, core replay identity, and library candidate limits.


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
