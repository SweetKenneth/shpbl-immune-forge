// Counterfactual Immune Forge — CIF/0.2 proof-gated defense promotion engine.
// SPDX-License-Identifier: MIT
import { createHash } from "node:crypto";

export const PROTOCOL = "CIF/0.2" as const;

export type Verdict = "PROMOTED" | "REJECTED" | "INCONCLUSIVE";
export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

export interface Scenario {
  id?: string;
  kind: string;
  payload: Json;
  expectedSecurityProperty: string;
}
export interface Defense {
  id: string;
  version: string;
  state?: Json;
}
export interface ReplayResult {
  reproduced: boolean;
  attackSucceeded: boolean;
  securityScore: number;
  state?: Json;
  trace?: Json;
}
export interface RegressionResult {
  passed: boolean;
  failures: string[];
  score?: number;
}
export interface ImpactResult {
  safe: boolean;
  reasons: string[];
  riskScore?: number;
}
export interface Mutation {
  id?: string;
  description: string;
  patch: Json;
}
export interface Candidate {
  mutation: Mutation;
  defense: Defense;
}
export interface DreamInsight {
  title: string;
  hypothesis: string;
  evidenceRefs: string[];
}

export interface ForgeAdapters {
  /** DEFENSE #1 / ECHO: reproduce the observed security event against a defense. */
  replay(scenario: Readonly<Scenario>, defense: Readonly<Defense>): Promise<ReplayResult>;
  /** DECODE: explain the observed failure. Evidence only; conveys no promotion authority. */
  diagnose?(scenario: Readonly<Scenario>, baseline: ReplayResult): Promise<Json>;
  /** ENGINEER/ENCODE/MEDIC/IMMUNE: candidate construction, freely replaceable. */
  generateCandidates(context: {
    scenario: Readonly<Scenario>;
    baseline: Readonly<Defense>;
    baselineReplay: ReplayResult;
    diagnosis?: Json;
  }): Promise<Candidate[]>;
  /** SANDBOX/SHADOW: bounded impact screen before anything is replayed for credit. */
  screen(
    candidate: Readonly<Candidate>,
    context: { scenario: Readonly<Scenario>; baseline: Readonly<Defense> },
  ): Promise<ImpactResult>;
  /** DEFENSE #2: protected-property/regression judgment. */
  regress(
    candidate: Readonly<Candidate>,
    replay: ReplayResult,
    context: { scenario: Readonly<Scenario>; baselineReplay: ReplayResult },
  ): Promise<RegressionResult>;
  /** EVOLUTION: policy-owned fitness. The Forge requires a positive delta; the adapter defines score semantics. */
  fitness(
    result: { replay: ReplayResult; regression: RegressionResult; impact: ImpactResult },
    context: { baselineReplay: ReplayResult },
  ): number;
  /** DREAM is post-proof and evidence-fed. It cannot alter the verdict or the evidence root. */
  dream?(evidence: Readonly<EpisodeEvidence>): Promise<DreamInsight[]>;
}

export type RejectionReason =
  | "IMPACT_SCREEN_FAILED"
  | "SCENARIO_REPLAY_FAILED"
  | "ATTACK_NOT_NEUTRALIZED"
  | "REGRESSION_GATE_FAILED"
  | "NO_PROVEN_IMPROVEMENT";

export interface CandidateEvidence {
  candidateId: string;
  mutationHash: string;
  defenseHash: string;
  impact: ImpactResult;
  replay?: ReplayResult;
  regression?: RegressionResult;
  fitness?: number;
  rejectedReason?: RejectionReason;
}

/** The gate settings actually in force for an episode. Sealed with the decision. */
export interface EffectivePolicy {
  requiredFitnessMargin: number;
  requireAttackReproduction: boolean;
  requireAttackNeutralized: boolean;
}

export interface EpisodeEvidence {
  protocol: typeof PROTOCOL;
  scenarioId: string;
  baselineHash: string;
  baselineReplay: ReplayResult;
  diagnosis?: Json;
  candidates: CandidateEvidence[];
  baselineFitness: number;
  winnerId?: string;
  verdict: Verdict;
  reason: string;
  /** Covered by the evidence root: a reader can see which gates the verdict was produced under. */
  policy: EffectivePolicy;
  dreamInsights?: DreamInsight[];
  evidenceRoot: string;
}

export interface ForgePolicy {
  /** Minimum fitness the candidate must exceed the baseline by. Default 0 (strictly greater). */
  requiredFitnessMargin?: number;
  /** When true (default) an episode whose baseline does not reproduce is INCONCLUSIVE. */
  requireAttackReproduction?: boolean;
  /**
   * When true (default) a candidate whose own replay still reports the attack succeeding is
   * rejected as ATTACK_NOT_NEUTRALIZED, whatever fitness the caller scored it. Set false only
   * when your fitness semantics deliberately reward partial mitigation.
   */
  requireAttackNeutralized?: boolean;
}

export function effectivePolicy(policy: ForgePolicy = {}): EffectivePolicy {
  return {
    requiredFitnessMargin: policy.requiredFitnessMargin ?? 0,
    requireAttackReproduction: policy.requireAttackReproduction ?? true,
    requireAttackNeutralized: policy.requireAttackNeutralized ?? true,
  };
}

export function canonical(value: unknown): string {
  if (value === undefined) return "null";
  if (typeof value === "number" && !Number.isFinite(value)) {
    // JSON.stringify would silently turn NaN/Infinity into "null" and let two different
    // observations share one hash. A sealing function must never accept that.
    throw new TypeError("CIF_NON_FINITE_NUMBER: non-finite numbers cannot be sealed");
  }
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`)
    .join(",")}}`;
}

export function hash(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export function sealScenario(s: Scenario): Readonly<Scenario> {
  return Object.freeze({
    ...s,
    id: hash({
      kind: s.kind,
      payload: s.payload,
      expectedSecurityProperty: s.expectedSecurityProperty,
    }),
  });
}

export function merkleRoot(leaves: string[]): string {
  if (!leaves.length) return hash("");
  // Leaf and interior nodes are domain-separated, and an odd tail is marked rather than
  // silently duplicated, so no tree shape can collide with a different tree shape.
  let level = leaves.map((x) => hash(`cif:leaf:${x}`));
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const right = level[i + 1];
      next.push(right === undefined ? hash(`cif:odd:${level[i]}`) : hash(`cif:node:${level[i]}:${right}`));
    }
    level = next;
  }
  return level[0];
}

type EpisodeCore = Omit<EpisodeEvidence, "evidenceRoot" | "dreamInsights">;

function episodeRoot(e: EpisodeCore): string {
  const leaves = [
    hash(e.protocol),
    hash(e.scenarioId),
    hash(e.baselineHash),
    hash(e.baselineReplay),
    hash(e.diagnosis ?? null),
    ...e.candidates.map(hash),
    hash(e.baselineFitness),
    hash(e.winnerId ?? null),
    hash(e.verdict),
    hash(e.reason),
    hash(e.policy),
  ];
  return merkleRoot(leaves);
}

export class CounterfactualImmuneForge {
  private readonly effective: EffectivePolicy;

  constructor(
    private readonly adapters: ForgeAdapters,
    policy: ForgePolicy = {},
  ) {
    this.effective = effectivePolicy(policy);
  }

  async run(input: { scenario: Scenario; baseline: Defense }): Promise<EpisodeEvidence> {
    const policy = this.effective;
    const scenario = sealScenario(input.scenario);
    const baselineHash = hash(input.baseline);
    const baselineReplay = await this.adapters.replay(scenario, Object.freeze({ ...input.baseline }));
    if (policy.requireAttackReproduction && !baselineReplay.reproduced) {
      return this.finish({
        protocol: PROTOCOL,
        scenarioId: scenario.id!,
        baselineHash,
        baselineReplay,
        candidates: [],
        baselineFitness: baselineReplay.securityScore,
        verdict: "INCONCLUSIVE",
        reason: "BASELINE_DID_NOT_REPRODUCE",
        policy,
      });
    }

    const diagnosis = this.adapters.diagnose
      ? await this.adapters.diagnose(scenario, baselineReplay)
      : undefined;
    const candidates = await this.adapters.generateCandidates({
      scenario,
      baseline: input.baseline,
      baselineReplay,
      diagnosis,
    });
    const baselineFitness = baselineReplay.securityScore;
    const evidence: CandidateEvidence[] = [];
    let best: { id: string; fitness: number } | undefined;

    for (const c of candidates) {
      const candidateId =
        c.mutation.id ?? hash({ parent: baselineHash, mutation: c.mutation, defense: c.defense });
      const ev: CandidateEvidence = {
        candidateId,
        mutationHash: hash(c.mutation),
        defenseHash: hash(c.defense),
        impact: { safe: false, reasons: ["NOT_SCREENED"] },
      };
      ev.impact = await this.adapters.screen(c, { scenario, baseline: input.baseline });
      if (!ev.impact.safe) {
        ev.rejectedReason = "IMPACT_SCREEN_FAILED";
        evidence.push(ev);
        continue;
      }
      // The same sealed scenario object is supplied for baseline and candidate replay:
      // callers cannot move the goalposts through the Forge.
      ev.replay = await this.adapters.replay(scenario, c.defense);
      if (!ev.replay.reproduced) {
        ev.rejectedReason = "SCENARIO_REPLAY_FAILED";
        evidence.push(ev);
        continue;
      }
      // A candidate that still lets the sealed attack succeed cannot be promoted on score alone.
      if (policy.requireAttackNeutralized && ev.replay.attackSucceeded) {
        ev.rejectedReason = "ATTACK_NOT_NEUTRALIZED";
        evidence.push(ev);
        continue;
      }
      ev.regression = await this.adapters.regress(c, ev.replay, { scenario, baselineReplay });
      if (!ev.regression.passed) {
        ev.rejectedReason = "REGRESSION_GATE_FAILED";
        evidence.push(ev);
        continue;
      }
      const scored = this.adapters.fitness(
        { replay: ev.replay, regression: ev.regression, impact: ev.impact },
        { baselineReplay },
      );
      // A non-finite score is recorded as an unproven improvement rather than sealed: it is not a
      // number the evidence root can commit to, and it must never read as a passing gate.
      if (Number.isFinite(scored)) ev.fitness = scored;
      if (!(Number.isFinite(scored) && scored > baselineFitness + policy.requiredFitnessMargin)) {
        ev.rejectedReason = "NO_PROVEN_IMPROVEMENT";
        evidence.push(ev);
        continue;
      }
      evidence.push(ev);
      if (!best || scored > best.fitness) best = { id: candidateId, fitness: scored };
    }

    const core: EpisodeCore = best
      ? {
          protocol: PROTOCOL,
          scenarioId: scenario.id!,
          baselineHash,
          baselineReplay,
          diagnosis,
          candidates: evidence,
          baselineFitness,
          winnerId: best.id,
          verdict: "PROMOTED",
          reason: "PROOF_GATES_PASSED",
          policy,
        }
      : {
          protocol: PROTOCOL,
          scenarioId: scenario.id!,
          baselineHash,
          baselineReplay,
          diagnosis,
          candidates: evidence,
          baselineFitness,
          verdict: "REJECTED",
          reason: "NO_CANDIDATE_CLEARED_PROOF_GATES",
          policy,
        };
    return this.finish(core);
  }

  private async finish(core: EpisodeCore): Promise<EpisodeEvidence> {
    const root = episodeRoot(core);
    let out: EpisodeEvidence = { ...core, evidenceRoot: root };
    // DREAM only receives sealed evidence and cannot alter the verdict or the root.
    if (this.adapters.dream) {
      out = { ...out, dreamInsights: await this.adapters.dream(Object.freeze(out)) };
    }
    return out;
  }
}

export function verifyEvidenceRoot(e: EpisodeEvidence): boolean {
  const { evidenceRoot: root, dreamInsights: _ignored, ...core } = e;
  // A missing or malformed policy block is a failed verification, never a pass: the gates the
  // verdict was produced under are part of what the root covers.
  if (!core.policy || typeof core.policy !== "object") return false;
  try {
    return episodeRoot(core) === root;
  } catch {
    return false;
  }
}
