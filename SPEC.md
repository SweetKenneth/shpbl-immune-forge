# CIF/0.1 Behavioral Specification

## Required promotion properties

1. The triggering scenario is canonicalized and cryptographically identified before candidate evaluation.
2. The baseline must reproduce the relevant event or the episode is INCONCLUSIVE.
3. Candidate generation is replaceable and conveys no promotion authority.
4. Each candidate must pass an impact/sandbox screen.
5. Each surviving candidate is replayed against the same sealed scenario.
6. Mandatory regression gates can reject a candidate even when the attack is stopped.
7. Fitness must exceed baseline by the configured positive margin.
8. Rejected candidates and reasons remain in episode evidence.
9. Promotion selects only among candidates that passed every gate.
10. The decision evidence is cryptographically committed; covered mutation invalidates verification.
11. DREAM, if used, runs only after the decision is sealed and cannot modify the verdict or evidence root.

## Honest limits

- A compromised evaluator can fabricate inputs before sealing.
- A bad fitness/regression policy can faithfully produce a bad decision.
- Passing known tests does not establish universal security.
- One scenario proves improvement only for the evaluated evidence/policy scope.
- Hash/Merkle commitments prove integrity of covered bytes, not truth of their claims.
