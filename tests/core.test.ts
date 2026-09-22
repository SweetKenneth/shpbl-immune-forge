import test from "node:test";
import assert from "node:assert/strict";
import {
  CounterfactualImmuneForge,
  canonical,
  hash,
  merkleRoot,
  sealScenario,
  verifyEvidenceRoot,
  type ForgeAdapters,
  type Scenario,
} from "../src/core.js";

const scenario: Scenario = {
  kind: "observed-threat",
  payload: { vector: "fixture" },
  expectedSecurityProperty: "deny malicious action",
};
const baseline = { id: "base", version: "1" };

function adapters(mode: "good" | "regress" | "same" | "screen" | "noreplay" = "good"): ForgeAdapters {
  return {
    replay: async (_s, d) =>
      d.id === "base"
        ? { reproduced: true, attackSucceeded: true, securityScore: 0.2 }
        : mode === "noreplay"
          ? { reproduced: false, attackSucceeded: false, securityScore: 0.9 }
          : { reproduced: true, attackSucceeded: false, securityScore: 0.9 },
    diagnose: async () => ({ cause: "boundary bypass" }),
    generateCandidates: async () => [
      { mutation: { description: "tighten boundary", patch: { rule: "deny" } }, defense: { id: "candidate", version: "2" } },
    ],
    screen: async () => (mode === "screen" ? { safe: false, reasons: ["blast radius"] } : { safe: true, reasons: [], riskScore: 0.1 }),
    regress: async () => ({ passed: mode !== "regress", failures: mode === "regress" ? ["legitimate flow broken"] : [] }),
    fitness: () => (mode === "same" ? 0.2 : 0.9),
    dream: async (e) => [{ title: "Neighbor hypothesis", hypothesis: "Test adjacent boundary", evidenceRefs: [e.evidenceRoot] }],
  };
}

test("promotes only after every proof gate and seals evidence", async () => {
  const r = await new CounterfactualImmuneForge(adapters()).run({ scenario, baseline });
  assert.equal(r.verdict, "PROMOTED");
  assert.equal(r.reason, "PROOF_GATES_PASSED");
  assert.equal(verifyEvidenceRoot(r), true);
  assert.equal(r.dreamInsights?.length, 1);
});

test("attack defeat can still be rejected by the regression gate", async () => {
  const r = await new CounterfactualImmuneForge(adapters("regress")).run({ scenario, baseline });
  assert.equal(r.verdict, "REJECTED");
  assert.equal(r.candidates[0].rejectedReason, "REGRESSION_GATE_FAILED");
});

test("no positive fitness delta means rejection", async () => {
  const r = await new CounterfactualImmuneForge(adapters("same")).run({ scenario, baseline });
  assert.equal(r.candidates[0].rejectedReason, "NO_PROVEN_IMPROVEMENT");
});

test("impact screen rejects before any replay credit is recorded", async () => {
  const r = await new CounterfactualImmuneForge(adapters("screen")).run({ scenario, baseline });
  assert.equal(r.candidates[0].rejectedReason, "IMPACT_SCREEN_FAILED");
  assert.equal(r.candidates[0].replay, undefined);
});

test("candidate that cannot replay the sealed scenario is rejected", async () => {
  const r = await new CounterfactualImmuneForge(adapters("noreplay")).run({ scenario, baseline });
  assert.equal(r.candidates[0].rejectedReason, "SCENARIO_REPLAY_FAILED");
});

test("nonreproducible baseline is inconclusive and evaluates no candidate", async () => {
  const a = adapters();
  a.replay = async () => ({ reproduced: false, attackSucceeded: false, securityScore: 0.5 });
  const r = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(r.verdict, "INCONCLUSIVE");
  assert.equal(r.candidates.length, 0);
});

test("policy margin can refuse a marginal improvement", async () => {
  const a = adapters();
  a.fitness = () => 0.25;
  const strict = await new CounterfactualImmuneForge(a, { requiredFitnessMargin: 0.5 }).run({ scenario, baseline });
  assert.equal(strict.verdict, "REJECTED");
  const loose = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(loose.verdict, "PROMOTED");
});

test("non-finite fitness cannot clear the delta gate", async () => {
  const a = adapters();
  a.fitness = () => Number.NaN;
  const r = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(r.candidates[0].rejectedReason, "NO_PROVEN_IMPROVEMENT");
});

test("the highest qualifying fitness wins among several passing candidates", async () => {
  const a = adapters();
  a.generateCandidates = async () => [
    { mutation: { id: "low", description: "small", patch: {} }, defense: { id: "c1", version: "2" } },
    { mutation: { id: "high", description: "big", patch: {} }, defense: { id: "c2", version: "3" } },
  ];
  a.fitness = ({ replay }) => (replay.securityScore === 0.9 ? 0.9 : 0.5);
  a.replay = async (_s, d) =>
    d.id === "base"
      ? { reproduced: true, attackSucceeded: true, securityScore: 0.2 }
      : { reproduced: true, attackSucceeded: false, securityScore: d.id === "c2" ? 0.9 : 0.4 };
  const r = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(r.verdict, "PROMOTED");
  assert.equal(r.winnerId, "high");
});

test("dream insights are post-proof and outside the sealed root", async () => {
  const a = adapters();
  a.dream = async () => [{ title: "t", hypothesis: "h", evidenceRefs: [] }];
  const r = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  const withoutDream = { ...r };
  delete withoutDream.dreamInsights;
  assert.equal(verifyEvidenceRoot(withoutDream), true);
  assert.equal(verifyEvidenceRoot(r), true);
});

test("scenario sealing is deterministic, key-order stable and byte-sensitive", () => {
  assert.equal(sealScenario(scenario).id, sealScenario({ ...scenario }).id);
  assert.equal(
    sealScenario(scenario).id,
    sealScenario({ expectedSecurityProperty: scenario.expectedSecurityProperty, payload: { vector: "fixture" }, kind: scenario.kind }).id,
  );
  assert.notEqual(sealScenario(scenario).id, sealScenario({ ...scenario, payload: { vector: "fixture2" } }).id);
});

test("tampering with any covered field invalidates the evidence root", async () => {
  const r = await new CounterfactualImmuneForge(adapters()).run({ scenario, baseline });
  const reasonTampered = { ...r, reason: "tampered" };
  assert.equal(verifyEvidenceRoot(reasonTampered), false);
  const verdictTampered = { ...r, verdict: "REJECTED" as const };
  assert.equal(verifyEvidenceRoot(verdictTampered), false);
  const candidateTampered = { ...r, candidates: [{ ...r.candidates[0], fitness: 42 }] };
  assert.equal(verifyEvidenceRoot(candidateTampered), false);
});

test("identical episodes seal to identical roots", async () => {
  const a = await new CounterfactualImmuneForge(adapters()).run({ scenario, baseline });
  const b = await new CounterfactualImmuneForge(adapters()).run({ scenario, baseline });
  assert.equal(a.evidenceRoot, b.evidenceRoot);
});

test("merkle root handles odd leaf counts deterministically", () => {
  assert.equal(merkleRoot(["a", "b", "c"]), merkleRoot(["a", "b", "c"]));
  assert.notEqual(merkleRoot(["a", "b", "c"]), merkleRoot(["a", "c", "b"]));
  assert.equal(merkleRoot([]), hash(""));
});

test("merkle tree shapes are domain separated", () => {
  // An odd tail must not collide with the same leaf genuinely paired with itself.
  assert.notEqual(merkleRoot(["a", "b", "c"]), merkleRoot(["a", "b", "c", "c"]));
  assert.notEqual(merkleRoot(["a", "b"]), merkleRoot(["a", "b", "b"]));
});

test("a candidate that does not neutralize the sealed attack cannot be promoted on score", async () => {
  const a = adapters();
  a.replay = async (_s, d) => ({ reproduced: true, attackSucceeded: true, securityScore: d.id === "base" ? 0.2 : 0.99 });
  a.fitness = () => 0.99;
  const strict = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(strict.verdict, "REJECTED");
  assert.equal(strict.candidates[0].rejectedReason, "ATTACK_NOT_NEUTRALIZED");
  assert.equal(strict.candidates[0].regression, undefined);
  const relaxed = await new CounterfactualImmuneForge(a, { requireAttackNeutralized: false }).run({ scenario, baseline });
  assert.equal(relaxed.verdict, "PROMOTED");
  assert.equal(relaxed.policy.requireAttackNeutralized, false);
});

test("the gates in force are sealed with the decision", async () => {
  const r = await new CounterfactualImmuneForge(adapters(), { requiredFitnessMargin: 0.1 }).run({ scenario, baseline });
  assert.deepEqual(r.policy, {
    requiredFitnessMargin: 0.1,
    requireAttackReproduction: true,
    requireAttackNeutralized: true,
  });
  assert.equal(verifyEvidenceRoot(r), true);
  assert.equal(verifyEvidenceRoot({ ...r, policy: { ...r.policy, requiredFitnessMargin: 0 } }), false);
  const { policy: _dropped, ...withoutPolicy } = r;
  assert.equal(verifyEvidenceRoot(withoutPolicy as typeof r), false);
});

test("non-finite numbers cannot be sealed", () => {
  assert.throws(() => canonical(Number.NaN), /CIF_NON_FINITE_NUMBER/);
  assert.throws(() => hash({ score: Number.POSITIVE_INFINITY }), /CIF_NON_FINITE_NUMBER/);
  assert.equal(hash(0), hash(0));
});

test("a non-finite fitness score is never sealed into evidence", async () => {
  const a = adapters();
  a.fitness = () => Number.NaN;
  const r = await new CounterfactualImmuneForge(a).run({ scenario, baseline });
  assert.equal(r.candidates[0].rejectedReason, "NO_PROVEN_IMPROVEMENT");
  assert.equal(r.candidates[0].fitness, undefined);
  assert.equal(verifyEvidenceRoot(r), true);
});
