import test from "node:test";
import assert from "node:assert/strict";
import { adjudicateEpisode, type EpisodeInput } from "../src/adjudicate.js";
import { verifyEvidenceRoot } from "../src/core.js";
import { ImmuneLineage, verifyLineage } from "../src/lineage.js";

const base: EpisodeInput = {
  scenario: { kind: "prompt-injection", payload: { vector: "tool-arg" }, expectedSecurityProperty: "refuse untrusted tool instruction" },
  baseline: { id: "guard", version: "1.0.0" },
  baselineReplay: { reproduced: true, attackSucceeded: true, securityScore: 0.2 },
  candidates: [
    {
      mutation: { id: "cand-a", description: "quarantine tool-sourced instructions", patch: { rule: "quarantine" } },
      defense: { id: "guard", version: "1.1.0" },
      impact: { safe: true, reasons: [] },
      replay: { reproduced: true, attackSucceeded: false, securityScore: 0.95 },
      regression: { passed: true, failures: [] },
      fitnessScore: 0.95,
    },
  ],
};

test("data-driven episode promotes and verifies", async () => {
  const r = await adjudicateEpisode(base);
  assert.equal(r.verdict, "PROMOTED");
  assert.equal(r.winnerId, "cand-a");
  assert.equal(verifyEvidenceRoot(r), true);
});

test("missing replay evidence fails the replay gate", async () => {
  const input = { ...base, candidates: [{ ...base.candidates[0], replay: undefined }] };
  const r = await adjudicateEpisode(input);
  assert.equal(r.candidates[0].rejectedReason, "SCENARIO_REPLAY_FAILED");
});

test("missing regression evidence fails the regression gate", async () => {
  const input = { ...base, candidates: [{ ...base.candidates[0], regression: undefined }] };
  const r = await adjudicateEpisode(input);
  assert.equal(r.candidates[0].rejectedReason, "REGRESSION_GATE_FAILED");
  assert.deepEqual(r.candidates[0].regression?.failures, ["NO_REGRESSION_EVIDENCE_SUPPLIED"]);
});

test("missing fitness evidence cannot beat the baseline", async () => {
  const input = { ...base, candidates: [{ ...base.candidates[0], fitnessScore: undefined }] };
  const r = await adjudicateEpisode(input);
  assert.equal(r.candidates[0].rejectedReason, "NO_PROVEN_IMPROVEMENT");
});

test("per-candidate fitness is not cross-contaminated", async () => {
  const input: EpisodeInput = {
    ...base,
    candidates: [
      { ...base.candidates[0], mutation: { id: "weak", description: "weak", patch: {} }, defense: { id: "guard", version: "1.1.0" }, fitnessScore: 0.2 },
      { ...base.candidates[0], mutation: { id: "strong", description: "strong", patch: { x: 1 } }, defense: { id: "guard", version: "1.2.0" }, fitnessScore: 0.9 },
    ],
  };
  const r = await adjudicateEpisode(input);
  assert.equal(r.winnerId, "strong");
  assert.equal(r.candidates.find((c) => c.candidateId === "weak")?.rejectedReason, "NO_PROVEN_IMPROVEMENT");
});

test("an unreproduced baseline is inconclusive even with perfect candidates", async () => {
  const r = await adjudicateEpisode({ ...base, baselineReplay: { reproduced: false, attackSucceeded: false, securityScore: 0.2 } });
  assert.equal(r.verdict, "INCONCLUSIVE");
});

test("lineage links episodes and detects edits", async () => {
  const lineage = new ImmuneLineage();
  const a = await adjudicateEpisode(base);
  const b = await adjudicateEpisode({ ...base, candidates: [{ ...base.candidates[0], fitnessScore: 0.1 }] });
  lineage.append(a);
  lineage.append(b);
  const report = lineage.report();
  assert.equal(report.intact, true);
  assert.equal(report.counts.PROMOTED, 1);
  assert.equal(report.counts.REJECTED, 1);
  const tampered = report.entries.map((e, i) => (i === 0 ? { ...e, verdict: "REJECTED" as const } : e));
  assert.equal(verifyLineage(tampered), false);
  const reordered = [report.entries[1], report.entries[0]];
  assert.equal(verifyLineage(reordered), false);
  lineage.reset();
  assert.equal(lineage.report().entries.length, 0);
  assert.equal(verifyLineage(report.entries), true);
});

test("a candidate that still loses to the attack is rejected before the regression gate", async () => {
  const r = await adjudicateEpisode({
    ...base,
    candidates: [
      {
        ...base.candidates[0],
        replay: { reproduced: true, attackSucceeded: true, securityScore: 0.99 },
        fitnessScore: 0.99,
      },
    ],
  });
  assert.equal(r.verdict, "REJECTED");
  assert.equal(r.candidates[0].rejectedReason, "ATTACK_NOT_NEUTRALIZED");
});

test("duplicate observations of one mutation/defense pair are refused", async () => {
  await assert.rejects(
    () => adjudicateEpisode({ ...base, candidates: [base.candidates[0], base.candidates[0]] }),
    /DUPLICATE_CANDIDATE_OBSERVATION/,
  );
});
