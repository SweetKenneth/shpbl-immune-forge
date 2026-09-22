// Data-driven adjudication: the caller's own tooling supplies observations; the Forge enforces the gates.
// SPDX-License-Identifier: MIT
import {
  CounterfactualImmuneForge,
  hash,
  sealScenario,
  type Candidate,
  type Defense,
  type EpisodeEvidence,
  type ForgeAdapters,
  type ForgePolicy,
  type ImpactResult,
  type Json,
  type RegressionResult,
  type ReplayResult,
  type Scenario,
} from "./core.js";

export interface CandidateObservation {
  mutation: { id?: string; description: string; patch: Json };
  defense: Defense;
  /** SANDBOX/SHADOW screen outcome recorded by the caller. */
  impact: ImpactResult;
  /** Same-scenario replay outcome. Absent evidence is a failed gate, never a pass. */
  replay?: ReplayResult;
  /** Protected-behaviour regression outcome. Absent evidence is a failed gate. */
  regression?: RegressionResult;
  /** Policy-owned fitness score. Absent evidence cannot clear the positive-delta gate. */
  fitnessScore?: number;
}

export interface EpisodeInput {
  scenario: Scenario;
  baseline: Defense;
  baselineReplay: ReplayResult;
  diagnosis?: Json;
  candidates: CandidateObservation[];
  policy?: ForgePolicy;
}

function candidateKey(c: { mutation: unknown; defense: unknown }): string {
  return hash({ mutation: c.mutation, defense: c.defense });
}

const MISSING_REPLAY: ReplayResult = {
  reproduced: false,
  attackSucceeded: false,
  securityScore: 0,
};
const MISSING_REGRESSION: RegressionResult = {
  passed: false,
  failures: ["NO_REGRESSION_EVIDENCE_SUPPLIED"],
};

/**
 * Adjudicate one episode from recorded observations. No candidate generation, no execution,
 * no network, no filesystem: only gate enforcement and evidence sealing.
 */
export async function adjudicateEpisode(input: EpisodeInput): Promise<EpisodeEvidence> {
  const expectedScenarioId = sealScenario(input.scenario).id!;
  if (input.baselineReplay.scenarioId !== expectedScenarioId) {
    throw new Error("BASELINE_SCENARIO_BINDING_MISMATCH: baselineReplay.scenarioId must equal the sealed scenario id");
  }
  const observations = new Map<string, CandidateObservation>();
  const mutationIds = new Set<string>();
  for (const o of input.candidates) {
    if (o.mutation.id !== undefined) {
      if (mutationIds.has(o.mutation.id)) {
        throw new Error("DUPLICATE_MUTATION_ID: each explicit mutation.id must be unique within an episode");
      }
      mutationIds.add(o.mutation.id);
    }
    const key = candidateKey(o);
    // Two observations of the same mutation-and-defense pair are ambiguous evidence: one would
    // silently overwrite the other and both would be adjudicated from the survivor's numbers.
    if (observations.has(key)) {
      throw new Error("DUPLICATE_CANDIDATE_OBSERVATION: each mutation/defense pair may be supplied once");
    }
    observations.set(key, o);
  }

  let inFlight: CandidateObservation | undefined;

  const adapters: ForgeAdapters = {
    // The baseline replay happens before any candidate is screened, so an unset in-flight
    // candidate identifies the baseline. Once screening fixes a candidate, that candidate's own
    // recorded replay is used — never another candidate that happens to share a defense version.
    replay: async (sealedScenario, defense) => {
      if (inFlight) {
        const observed = inFlight.replay ?? MISSING_REPLAY;
        if (observed.scenarioId !== sealedScenario.id) return MISSING_REPLAY;
        return observed;
      }
      if (defense.id === input.baseline.id && defense.version === input.baseline.version) {
        return input.baselineReplay;
      }
      return MISSING_REPLAY;
    },
    diagnose: input.diagnosis === undefined ? undefined : async () => input.diagnosis as Json,
    generateCandidates: async () =>
      input.candidates.map<Candidate>((o) => ({ mutation: o.mutation, defense: o.defense })),
    // screen runs first for every candidate, so it also fixes which observation is in flight.
    screen: async (candidate) => {
      inFlight = observations.get(candidateKey(candidate));
      return (
        inFlight?.impact ?? { safe: false, reasons: ["NO_IMPACT_EVIDENCE_SUPPLIED"] }
      );
    },
    regress: async (candidate) =>
      observations.get(candidateKey(candidate))?.regression ?? MISSING_REGRESSION,
    // An unsupplied or non-finite score falls back to the baseline and therefore cannot clear the delta gate.
    fitness: (_result, context) => {
      const score = inFlight?.fitnessScore;
      return typeof score === "number" && Number.isFinite(score)
        ? score
        : context.baselineReplay.securityScore;
    },
  };

  return new CounterfactualImmuneForge(adapters, input.policy ?? {}).run({
    scenario: input.scenario,
    baseline: input.baseline,
  });
}
