# CIF/0.3 Behavioral Specification

## Required promotion properties

1. The triggering scenario is canonicalized and cryptographically identified before candidate evaluation.
2. Data-driven baseline evidence must identify the sealed scenario. The baseline must reproduce the relevant
   event **and report the attack succeeding** or the episode is INCONCLUSIVE. This gate is mandatory.
3. Candidate generation is replaceable and conveys no promotion authority.
4. Each candidate must pass an impact/sandbox screen.
5. Each surviving candidate is replayed against the same sealed scenario. Data-driven observations must carry that sealed scenario hash; a mismatched or missing binding cannot earn replay credit.
6. A candidate whose own replay still reports the attack succeeding is rejected as
   `ATTACK_NOT_NEUTRALIZED`. This gate is mandatory; fitness cannot override it.
7. Mandatory regression gates can reject a candidate even when the attack is stopped. A regression result that
   says `passed: true` while also reporting failures is treated as a failed gate.
8. Fitness must exceed baseline by the configured non-negative margin; negative margins are invalid policy.
9. Rejected candidates and reasons remain in episode evidence.
10. Promotion selects only among candidates that passed every gate. Candidate IDs are unique within an episode,
    and the core library evaluates at most 256 candidates per episode.
11. The decision evidence is cryptographically committed; covered mutation invalidates verification.
12. The gate settings in force are part of the committed evidence; baseline reproduction and candidate
    neutralization are fixed `true` in CIF/0.3 and cannot be weakened by caller policy. A verdict cannot be
    reinterpreted under gates it was not produced under. Non-finite numbers are never sealed, and duplicate observations of one
    mutation/defense pair are refused as ambiguous evidence. Explicit mutation IDs must also be unique within an episode.
13. DREAM, if used, runs only after the decision is sealed, receives deeply immutable evidence, and cannot
    modify or suppress the verdict or evidence root.

## Honest limits

- A compromised evaluator can fabricate inputs before sealing.
- A bad fitness/regression policy can faithfully produce a bad decision.
- Passing known tests does not establish universal security.
- One scenario proves improvement only for the evaluated evidence/policy scope.
- Hash/Merkle commitments prove integrity of covered bytes, not truth of their claims.
- Without an independently retained expected evidence root or lineage head, verification proves internal
  consistency only; it does not authenticate the historical artifact against replacement.
