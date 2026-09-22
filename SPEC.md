# CIF/0.2 Behavioral Specification

## Required promotion properties

1. The triggering scenario is canonicalized and cryptographically identified before candidate evaluation.
2. The baseline must reproduce the relevant event or the episode is INCONCLUSIVE.
3. Candidate generation is replaceable and conveys no promotion authority.
4. Each candidate must pass an impact/sandbox screen.
5. Each surviving candidate is replayed against the same sealed scenario.
6. A candidate whose own replay still reports the attack succeeding is rejected as
   `ATTACK_NOT_NEUTRALIZED` unless the operator explicitly disables that gate; fitness cannot override it.
7. Mandatory regression gates can reject a candidate even when the attack is stopped.
8. Fitness must exceed baseline by the configured positive margin.
9. Rejected candidates and reasons remain in episode evidence.
10. Promotion selects only among candidates that passed every gate.
11. The decision evidence is cryptographically committed; covered mutation invalidates verification.
12. The gate settings in force are part of the committed evidence; a verdict cannot be reinterpreted under
    gates it was not produced under. Non-finite numbers are never sealed, and duplicate observations of one
    mutation/defense pair are refused as ambiguous evidence.
13. DREAM, if used, runs only after the decision is sealed and cannot modify the verdict or evidence root.

## Honest limits

- A compromised evaluator can fabricate inputs before sealing.
- A bad fitness/regression policy can faithfully produce a bad decision.
- Passing known tests does not establish universal security.
- One scenario proves improvement only for the evaluated evidence/policy scope.
- Hash/Merkle commitments prove integrity of covered bytes, not truth of their claims.
