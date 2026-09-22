// Counterfactual Immune Forge — CIF/0.3 proof-gated defense promotion engine.
// SPDX-License-Identifier: MIT
import { createHash } from "node:crypto";

export const PROTOCOL = "CIF/0.3" as const;
export const MAX_CANDIDATES_PER_EPISODE = 256 as const;

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
  /** Hash of the sealed scenario this observation claims to describe. Required for data-driven observations. */
  scenarioId?: string;
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
  replay(
    scenario: Readonly<Scenario>,
    defense: Readonly<Defense>,
    candidate?: Readonly<Candidate>,
  ): Promise<ReplayResult>;
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
    result: {
      candidate: Readonly<Candidate>;
      replay: ReplayResult;
      regression: RegressionResult;
      impact: ImpactResult;
    },
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
}

export function effectivePolicy(policy: ForgePolicy = {}): EffectivePolicy {
  const raw = policy as ForgePolicy & {
    requireAttackReproduction?: unknown;
    requireAttackNeutralized?: unknown;
  };
  if (raw.requireAttackReproduction !== undefined || raw.requireAttackNeutralized !== undefined) {
    throw new TypeError(
      "CIF_IMMUTABLE_PROOF_GATES: baseline reproduction and candidate neutralization are mandatory in CIF/0.3",
    );
  }
  const requiredFitnessMargin = policy.requiredFitnessMargin ?? 0;
  if (!Number.isFinite(requiredFitnessMargin) || requiredFitnessMargin < 0) {
    throw new RangeError("CIF_INVALID_POLICY: requiredFitnessMargin must be a finite non-negative number");
  }
  return {
    requiredFitnessMargin,
    requireAttackReproduction: true,
    requireAttackNeutralized: true,
  };
}

export function canonical(value: unknown): string {
  const ancestors = new WeakSet<object>();
  const walk = (v: unknown): string => {
    if (v === undefined) return "null";
    if (v === null) return "null";
    if (typeof v === "number") {
      if (!Number.isFinite(v)) {
        throw new TypeError("CIF_NON_FINITE_NUMBER: non-finite numbers cannot be sealed");
      }
      return JSON.stringify(v);
    }
    if (typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v !== "object") {
      throw new TypeError("CIF_UNSUPPORTED_VALUE: only JSON-compatible values can be sealed");
    }
    if (ancestors.has(v)) {
      throw new TypeError("CIF_CYCLIC_VALUE: cyclic values cannot be sealed");
    }
    ancestors.add(v);
    try {
      if (Array.isArray(v)) return `[${Array.from({ length: v.length }, (_, i) => walk(v[i] === undefined ? null : v[i])).join(",")}]`;
      const prototype = Object.getPrototypeOf(v);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("CIF_UNSUPPORTED_OBJECT: only plain JSON objects can be sealed");
      }
      const obj = v as Record<string, unknown>;
      return `{${Object.keys(obj)
        .sort()
        .filter((k) => obj[k] !== undefined)
        .map((k) => `${JSON.stringify(k)}:${walk(obj[k])}`)
        .join(",")}}`;
    } finally {
      ancestors.delete(v);
    }
  };
  return walk(value);
}

export function hash(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

export function immutableSnapshot<T>(value: T): T {
  const ancestors = new WeakSet<object>();
  const walk = (v: unknown): unknown => {
    if (v === undefined || v === null || typeof v === "string" || typeof v === "boolean") return v;
    if (typeof v === "number") {
      if (!Number.isFinite(v)) {
        throw new TypeError("CIF_NON_FINITE_NUMBER: non-finite numbers cannot be snapshotted");
      }
      return v;
    }
    if (typeof v !== "object") {
      throw new TypeError("CIF_UNSUPPORTED_VALUE: only JSON-compatible values can be snapshotted");
    }
    if (ancestors.has(v)) throw new TypeError("CIF_CYCLIC_VALUE: cyclic values cannot be snapshotted");
    ancestors.add(v);
    try {
      if (Array.isArray(v)) return Object.freeze(Array.from({ length: v.length }, (_, i) => walk(v[i] === undefined ? null : v[i])));
      const prototype = Object.getPrototypeOf(v);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new TypeError("CIF_UNSUPPORTED_OBJECT: only plain JSON objects can be snapshotted");
      }
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(v as Record<string, unknown>)) {
        if (item === undefined) continue;
        Object.defineProperty(out, key, {
          value: walk(item),
          enumerable: true,
          writable: false,
          configurable: false,
        });
      }
      return Object.freeze(out);
    } finally {
      ancestors.delete(v);
    }
  };
  return walk(value) as T;
}

function validateReplayResult(replay: ReplayResult, scenarioId: string): Readonly<ReplayResult> {
  const snapshot = immutableSnapshot(replay);
  if (
    typeof snapshot.reproduced !== "boolean" ||
    typeof snapshot.attackSucceeded !== "boolean" ||
    typeof snapshot.securityScore !== "number" ||
    !Number.isFinite(snapshot.securityScore)
  ) {
    throw new Error("INVALID_REPLAY_RESULT: reproduced and attackSucceeded must be booleans and securityScore finite");
  }
  if (snapshot.scenarioId !== undefined && (typeof snapshot.scenarioId !== "string" || snapshot.scenarioId.length === 0)) {
    throw new Error("INVALID_REPLAY_RESULT: scenarioId must be a non-empty string when supplied");
  }
  if (snapshot.scenarioId !== undefined && snapshot.scenarioId !== scenarioId) {
    throw new Error("REPLAY_SCENARIO_BINDING_MISMATCH: replay.scenarioId does not match the sealed scenario");
  }
  return immutableSnapshot({ ...snapshot, scenarioId });
}

function validateImpactResult(impact: ImpactResult): Readonly<ImpactResult> {
  const snapshot = immutableSnapshot(impact);
  if (
    typeof snapshot.safe !== "boolean" ||
    !Array.isArray(snapshot.reasons) ||
    !snapshot.reasons.every((reason) => typeof reason === "string") ||
    (snapshot.riskScore !== undefined &&
      (typeof snapshot.riskScore !== "number" || !Number.isFinite(snapshot.riskScore)))
  ) {
    throw new Error("INVALID_IMPACT_RESULT: safe must be boolean, reasons strings, and riskScore finite when supplied");
  }
  return snapshot;
}

function validateRegressionResult(regression: RegressionResult): Readonly<RegressionResult> {
  const snapshot = immutableSnapshot(regression);
  if (
    typeof snapshot.passed !== "boolean" ||
    !Array.isArray(snapshot.failures) ||
    !snapshot.failures.every((failure) => typeof failure === "string") ||
    (snapshot.score !== undefined && (typeof snapshot.score !== "number" || !Number.isFinite(snapshot.score)))
  ) {
    throw new Error("INVALID_REGRESSION_RESULT: passed must be boolean, failures strings, and score finite when supplied");
  }
  return snapshot;
}

function validateDefense(defense: Defense, field: string): Readonly<Defense> {
  const snapshot = immutableSnapshot(defense as unknown) as unknown;
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
    throw new Error(`INVALID_DEFENSE: ${field} must be an object`);
  }
  const d = snapshot as Record<string, unknown>;
  if (typeof d.id !== "string" || d.id.length === 0 || typeof d.version !== "string" || d.version.length === 0) {
    throw new Error(`INVALID_DEFENSE: ${field}.id and ${field}.version must be non-empty strings`);
  }
  return snapshot as Readonly<Defense>;
}

function validateCandidate(candidate: Candidate, index: number): Readonly<Candidate> {
  const snapshot = immutableSnapshot(candidate as unknown) as unknown;
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
    throw new Error(`INVALID_CANDIDATE: candidate[${index}] must be an object`);
  }
  const c = snapshot as Record<string, unknown>;
  if (typeof c.mutation !== "object" || c.mutation === null || Array.isArray(c.mutation)) {
    throw new Error(`INVALID_CANDIDATE: candidate[${index}].mutation must be an object`);
  }
  const mutation = c.mutation as Record<string, unknown>;
  if (typeof mutation.description !== "string" || mutation.description.length === 0) {
    throw new Error(`INVALID_CANDIDATE: candidate[${index}].mutation.description must be a non-empty string`);
  }
  if (mutation.id !== undefined && (typeof mutation.id !== "string" || mutation.id.length === 0)) {
    throw new Error(`INVALID_CANDIDATE: candidate[${index}].mutation.id must be a non-empty string when supplied`);
  }
  if (!Object.prototype.hasOwnProperty.call(mutation, "patch")) {
    throw new Error(`INVALID_CANDIDATE: candidate[${index}].mutation.patch is required`);
  }
  validateDefense(c.defense as Defense, `candidate[${index}].defense`);
  return snapshot as Readonly<Candidate>;
}

export function sealScenario(s: Scenario): Readonly<Scenario> {
  const source = immutableSnapshot(s as unknown) as unknown;
  if (typeof source !== "object" || source === null || Array.isArray(source)) {
    throw new Error("INVALID_SCENARIO: scenario must be an object");
  }
  const raw = source as Record<string, unknown>;
  if (typeof raw.kind !== "string" || raw.kind.length === 0) {
    throw new Error("INVALID_SCENARIO: scenario.kind must be a non-empty string");
  }
  if (typeof raw.expectedSecurityProperty !== "string" || raw.expectedSecurityProperty.length === 0) {
    throw new Error("INVALID_SCENARIO: scenario.expectedSecurityProperty must be a non-empty string");
  }
  if (!Object.prototype.hasOwnProperty.call(raw, "payload")) {
    throw new Error("INVALID_SCENARIO: scenario.payload is required");
  }
  const snapshot = immutableSnapshot({
    kind: raw.kind,
    payload: raw.payload as Json,
    expectedSecurityProperty: raw.expectedSecurityProperty,
  });
  return immutableSnapshot({
    ...snapshot,
    id: hash(snapshot),
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
    this.effective = immutableSnapshot(effectivePolicy(policy));
  }

  async run(input: { scenario: Scenario; baseline: Defense }): Promise<EpisodeEvidence> {
    const policy = this.effective;
    const scenario = sealScenario(input.scenario);
    const baseline = validateDefense(input.baseline, "baseline");
    const baselineHash = hash(baseline);
    const baselineReplay = validateReplayResult(await this.adapters.replay(scenario, baseline), scenario.id!);
    if (!baselineReplay.reproduced) {
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
    if (!baselineReplay.attackSucceeded) {
      return this.finish({
        protocol: PROTOCOL,
        scenarioId: scenario.id!,
        baselineHash,
        baselineReplay,
        candidates: [],
        baselineFitness: baselineReplay.securityScore,
        verdict: "INCONCLUSIVE",
        reason: "BASELINE_ATTACK_NOT_SUCCESSFUL",
        policy,
      });
    }

    const diagnosis = this.adapters.diagnose
      ? immutableSnapshot(await this.adapters.diagnose(scenario, baselineReplay))
      : undefined;
    const generatedCandidates = await this.adapters.generateCandidates({
      scenario,
      baseline,
      baselineReplay,
      diagnosis,
    });
    if (!Array.isArray(generatedCandidates)) {
      throw new Error("INVALID_CANDIDATE_SET: generateCandidates must return an array");
    }
    if (generatedCandidates.length > MAX_CANDIDATES_PER_EPISODE) {
      throw new Error(
        `CANDIDATE_LIMIT_EXCEEDED: at most ${MAX_CANDIDATES_PER_EPISODE} candidates may be evaluated per episode`,
      );
    }
    const candidates = generatedCandidates.map((candidate, index) => validateCandidate(candidate, index));
    const candidateIds = candidates.map(
      (c) => c.mutation.id ?? hash({ parent: baselineHash, mutation: c.mutation, defense: c.defense }),
    );
    if (new Set(candidateIds).size !== candidateIds.length) {
      throw new Error("DUPLICATE_CANDIDATE_ID: candidate IDs must be unique within an episode");
    }
    const baselineFitness = baselineReplay.securityScore;
    const evidence: CandidateEvidence[] = [];
    let best: { id: string; fitness: number } | undefined;

    for (let candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
      const c = candidates[candidateIndex];
      const candidateId = candidateIds[candidateIndex];
      const ev: CandidateEvidence = {
        candidateId,
        mutationHash: hash(c.mutation),
        defenseHash: hash(c.defense),
        impact: { safe: false, reasons: ["NOT_SCREENED"] },
      };
      ev.impact = validateImpactResult(await this.adapters.screen(c, { scenario, baseline }));
      if (!ev.impact.safe) {
        ev.rejectedReason = "IMPACT_SCREEN_FAILED";
        evidence.push(ev);
        continue;
      }
      // The same sealed scenario object is supplied for baseline and candidate replay:
      // callers cannot move the goalposts through the Forge.
      ev.replay = validateReplayResult(await this.adapters.replay(scenario, c.defense, c), scenario.id!);
      if (!ev.replay.reproduced) {
        ev.rejectedReason = "SCENARIO_REPLAY_FAILED";
        evidence.push(ev);
        continue;
      }
      // A candidate that still lets the sealed attack succeed cannot be promoted on score alone.
      if (ev.replay.attackSucceeded) {
        ev.rejectedReason = "ATTACK_NOT_NEUTRALIZED";
        evidence.push(ev);
        continue;
      }
      ev.regression = validateRegressionResult(await this.adapters.regress(c, ev.replay, { scenario, baselineReplay }));
      if (!ev.regression.passed || ev.regression.failures.length > 0) {
        ev.rejectedReason = "REGRESSION_GATE_FAILED";
        evidence.push(ev);
        continue;
      }
      const scored = this.adapters.fitness(
        { candidate: c, replay: ev.replay, regression: ev.regression, impact: ev.impact },
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
    const sealedCore = immutableSnapshot(core);
    const root = episodeRoot(sealedCore);
    const sealedEvidence = immutableSnapshot<EpisodeEvidence>({ ...sealedCore, evidenceRoot: root });
    if (!this.adapters.dream) return sealedEvidence;
    try {
      const dreamInsights = immutableSnapshot(await this.adapters.dream(sealedEvidence));
      return immutableSnapshot({ ...sealedEvidence, dreamInsights });
    } catch {
      // DREAM is explicitly post-proof and non-authoritative. A failed or malformed exploratory
      // hook must never suppress, rewrite, or invalidate the already-sealed decision.
      return sealedEvidence;
    }
  }
}

export function verifyEvidenceRoot(e: EpisodeEvidence, expectedRoot?: string): boolean {
  if (!e || typeof e !== "object" || Array.isArray(e)) return false;
  const allowedTopLevel = new Set([
    "protocol",
    "scenarioId",
    "baselineHash",
    "baselineReplay",
    "diagnosis",
    "candidates",
    "baselineFitness",
    "winnerId",
    "verdict",
    "reason",
    "policy",
    "dreamInsights",
    "evidenceRoot",
  ]);
  if (Object.keys(e as unknown as Record<string, unknown>).some((key) => !allowedTopLevel.has(key))) {
    return false;
  }
  if (e.protocol !== PROTOCOL) return false;
  if (!(e.verdict === "PROMOTED" || e.verdict === "REJECTED" || e.verdict === "INCONCLUSIVE")) return false;
  const { evidenceRoot: root, dreamInsights: _ignored, ...core } = e;
  // A missing or malformed policy block is a failed verification, never a pass: the gates the
  // verdict was produced under are part of what the root covers.
  if (!core.policy || typeof core.policy !== "object") return false;
  try {
    const internallyConsistent = episodeRoot(core) === root;
    if (!internallyConsistent) return false;
    return expectedRoot === undefined || root === expectedRoot;
  } catch {
    return false;
  }
}
