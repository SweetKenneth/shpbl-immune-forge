import test from "node:test";
import assert from "node:assert/strict";
import { adjudicateEpisode, type EpisodeInput } from "../src/adjudicate.js";
import { hash, sealScenario, verifyEvidenceRoot } from "../src/core.js";
import { ImmuneLineage, verifyLineage } from "../src/lineage.js";

const episodeScenario = { kind: "prompt-injection", payload: { vector: "tool-arg" }, expectedSecurityProperty: "refuse untrusted tool instruction" };
const sealedScenarioId = sealScenario(episodeScenario).id!;

const base: EpisodeInput = {
  scenario: episodeScenario,
  baseline: { id: "guard", version: "1.0.0" },
  baselineReplay: { scenarioId: sealedScenarioId, reproduced: true, attackSucceeded: true, securityScore: 0.2 },
  baselineFitness: 0.2,
  candidates: [
    {
      mutation: { id: "cand-a", description: "quarantine tool-sourced instructions", patch: { rule: "quarantine" } },
      defense: { id: "guard", version: "1.1.0" },
      impact: { safe: true, reasons: [] },
      replay: { scenarioId: sealedScenarioId, reproduced: true, attackSucceeded: false, securityScore: 0.95 },
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
  const r = await adjudicateEpisode({ ...base, baselineReplay: { scenarioId: sealedScenarioId, reproduced: false, attackSucceeded: false, securityScore: 0.2 } });
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
        replay: { scenarioId: sealedScenarioId, reproduced: true, attackSucceeded: true, securityScore: 0.99 },
        fitnessScore: 0.99,
      },
    ],
  });
  assert.equal(r.verdict, "REJECTED");
  assert.equal(r.candidates[0].rejectedReason, "ATTACK_NOT_NEUTRALIZED");
});

test("duplicate observations of one mutation/defense pair are refused", async () => {
  const duplicateWithoutExplicitId = {
    ...base.candidates[0],
    mutation: { description: base.candidates[0].mutation.description, patch: base.candidates[0].mutation.patch },
  };
  await assert.rejects(
    () => adjudicateEpisode({ ...base, candidates: [duplicateWithoutExplicitId, duplicateWithoutExplicitId] }),
    /DUPLICATE_CANDIDATE_OBSERVATION/,
  );
});


test("a baseline that reproduced but was not defeated is inconclusive", async () => {
  const r = await adjudicateEpisode({
    ...base,
    baselineReplay: { scenarioId: sealedScenarioId, reproduced: true, attackSucceeded: false, securityScore: 0.2 },
  });
  assert.equal(r.verdict, "INCONCLUSIVE");
  assert.equal(r.reason, "BASELINE_ATTACK_NOT_SUCCESSFUL");
  assert.equal(r.candidates.length, 0);
});

test("candidate replay must claim the sealed scenario id", async () => {
  const r = await adjudicateEpisode({
    ...base,
    candidates: [{ ...base.candidates[0], replay: { ...base.candidates[0].replay!, scenarioId: "wrong-scenario" } }],
  });
  assert.equal(r.verdict, "REJECTED");
  assert.equal(r.candidates[0].rejectedReason, "SCENARIO_REPLAY_FAILED");
});

test("duplicate explicit mutation ids are refused by the library API", async () => {
  const second = {
    ...base.candidates[0],
    mutation: { id: "cand-a", description: "different mutation", patch: { rule: "different" } },
    defense: { id: "guard", version: "1.2.0" },
  };
  await assert.rejects(
    () => adjudicateEpisode({ ...base, candidates: [base.candidates[0], second] }),
    /DUPLICATE_MUTATION_ID/,
  );
});

test("negative required fitness margins are refused", async () => {
  await assert.rejects(
    () => adjudicateEpisode({ ...base, policy: { requiredFitnessMargin: -0.1 } }),
    /CIF_INVALID_POLICY/,
  );
});


test("baseline replay must claim the sealed scenario id", async () => {
  await assert.rejects(
    () => adjudicateEpisode({
      ...base,
      baselineReplay: { ...base.baselineReplay, scenarioId: "wrong-scenario" },
    }),
    /BASELINE_SCENARIO_BINDING_MISMATCH/,
  );
});


test("lineage rejects tampered evidence instead of blessing it with a new chain entry", async () => {
  const lineage = new ImmuneLineage();
  const evidence = await adjudicateEpisode(base);
  const tampered = { ...evidence, reason: "edited after sealing" };
  assert.throws(() => lineage.append(tampered), /INVALID_EPISODE_EVIDENCE/);
  assert.equal(lineage.report().entries.length, 0);
});

test("returned lineage entries cannot be mutated to corrupt internal state", async () => {
  const lineage = new ImmuneLineage();
  const evidence = await adjudicateEpisode(base);
  const entry = lineage.append(evidence);
  assert.equal(Object.isFrozen(entry), true);
  assert.throws(() => ((entry as any).verdict = "REJECTED"), TypeError);
  const report = lineage.report();
  assert.equal(report.intact, true);
  assert.equal(report.entries[0].verdict, "PROMOTED");
});


test("library caller mutations after adjudication starts cannot change the sealed decision", async () => {
  const mutable: EpisodeInput = JSON.parse(JSON.stringify(base));
  const pending = adjudicateEpisode(mutable);

  mutable.baselineReplay.attackSucceeded = false;
  mutable.baselineReplay.securityScore = 0.99;
  mutable.candidates[0].replay!.attackSucceeded = true;
  mutable.candidates[0].fitnessScore = 0;
  mutable.candidates[0].regression!.passed = false;
  mutable.candidates[0].regression!.failures.push("late mutation");

  const r = await pending;
  assert.equal(r.verdict, "PROMOTED");
  assert.equal(r.winnerId, "cand-a");
  assert.equal(r.baselineReplay.attackSucceeded, true);
  assert.equal(r.candidates[0].replay?.attackSucceeded, false);
  assert.equal(r.candidates[0].regression?.passed, true);
  assert.equal(verifyEvidenceRoot(r), true);
});


test("lineage cap prevents exporting more entries than the verifier accepts", async () => {
  const lineage = new ImmuneLineage(2);
  const evidence = await adjudicateEpisode(base);
  lineage.append(evidence);
  lineage.append(evidence);
  assert.throws(() => lineage.append(evidence), /LINEAGE_LIMIT_EXCEEDED/);
  const report = lineage.report();
  assert.equal(report.entries.length, 2);
  assert.equal(report.intact, true);
  assert.equal(verifyLineage(report.entries, report.headHash), true);
});


test("data-driven baseline fitness is independent of replay securityScore and controls the delta gate", async () => {
  const r = await adjudicateEpisode({
    ...base,
    baselineReplay: { ...base.baselineReplay, securityScore: 0.99 },
    baselineFitness: 10,
    candidates: [{ ...base.candidates[0], fitnessScore: 9 }],
  });
  assert.equal(r.baselineFitness, 10);
  assert.equal(r.verdict, "REJECTED");
  assert.equal(r.candidates[0].rejectedReason, "NO_PROVEN_IMPROVEMENT");
});


test("data-driven inconclusive episodes do not require baselineFitness", async () => {
  const r = await adjudicateEpisode({
    ...base,
    baselineFitness: undefined,
    baselineReplay: {
      scenarioId: sealedScenarioId,
      reproduced: false,
      attackSucceeded: false,
      securityScore: 0.2,
    },
  });
  assert.equal(r.verdict, "INCONCLUSIVE");
  assert.equal(r.baselineFitness, undefined);
  assert.equal(verifyEvidenceRoot(r), true);
});

test("data-driven qualifying baselines still require baselineFitness", async () => {
  await assert.rejects(
    () => adjudicateEpisode({ ...base, baselineFitness: undefined }),
    /INVALID_BASELINE_FITNESS/,
  );
});


test("lineage verification rejects a hash-consistent entry with impossible verdict semantics", async () => {
  const evidence = await adjudicateEpisode(base);
  const genesis = new ImmuneLineage().report().headHash;
  const forgedCore = {
    index: 0,
    scenarioId: evidence.scenarioId,
    verdict: "PROMOTED" as const,
    reason: "TRUST_ME",
    episodeRoot: evidence.evidenceRoot,
    previousEntryHash: genesis,
  };
  const forged = { ...forgedCore, entryHash: hash(forgedCore) };
  assert.equal(verifyLineage([forged]), false);
});


test("lineage verification rejects explicit undefined winner fields on non-promoted entries", async () => {
  const evidence = await adjudicateEpisode({ ...base, candidates: [] });
  const lineage = new ImmuneLineage();
  const entry = lineage.append(evidence);
  const forgedCore: any = { ...entry };
  delete forgedCore.entryHash;
  forgedCore.winnerId = undefined;
  const forged = { ...forgedCore, entryHash: hash(forgedCore) };
  assert.equal(verifyLineage([forged]), false);
});
