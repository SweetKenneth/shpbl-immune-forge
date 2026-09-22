#!/usr/bin/env node
// Counterfactual Immune Forge — zero-dependency stdio MCP server.
// No filesystem, no network, no process spawning, no environment reads.
// SPDX-License-Identifier: MIT
import { adjudicateEpisode, type CandidateObservation, type EpisodeInput } from "./adjudicate.js";
import {
  MAX_CANDIDATES_PER_EPISODE,
  PROTOCOL,
  verifyEvidenceRoot,
  type EpisodeEvidence,
  type ImpactResult,
  type Json,
  type RegressionResult,
  type ReplayResult,
} from "./core.js";
import {
  ImmuneLineage,
  MAX_LINEAGE_ENTRIES,
  summarizeLineage,
  verifyLineage,
  type LineageEntry,
  type LineageReport,
} from "./lineage.js";

export const SERVER_NAME = "shpbl-counterfactual-immune-forge";
export const SERVER_VERSION = "0.3.0";
const MCP_PROTOCOL_VERSION = "2025-11-25";

export const POLICY = {
  protocol: PROTOCOL,
  lineageProtocol: "CIF-LINEAGE/0.1",
  hash: "sha256",
  defaultRequiredFitnessMargin: 0,
  requireAttackReproduction: true,
  requireAttackNeutralized: true,
  maxCandidatesPerEpisode: MAX_CANDIDATES_PER_EPISODE,
  maxLineageEntries: MAX_LINEAGE_ENTRIES,
  maxRequestBytes: 1_048_576,
  rejectionReasons: [
    "IMPACT_SCREEN_FAILED",
    "SCENARIO_REPLAY_FAILED",
    "ATTACK_NOT_NEUTRALIZED",
    "REGRESSION_GATE_FAILED",
    "NO_PROVEN_IMPROVEMENT",
  ],
  verdicts: ["PROMOTED", "REJECTED", "INCONCLUSIVE"],
  sideEffects: "none: the server never reads files, opens sockets, spawns processes or reads environment variables",
} as const;

class InputError extends Error {}

function obj(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new InputError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}
function exactObj(value: unknown, field: string, allowed: readonly string[]): Record<string, unknown> {
  const r = obj(value, field);
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(r).find((key) => !allowedSet.has(key));
  if (unknown !== undefined) throw new InputError(`${field}.${unknown} is not supported`);
  return r;
}
function str(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new InputError(`${field} must be a non-empty string`);
  if (value.length > 4096) throw new InputError(`${field} exceeds 4096 characters`);
  return value;
}
function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new InputError(`${field} must be a finite number`);
  return value;
}
function bool(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") throw new InputError(`${field} must be a boolean`);
  return value;
}
function strArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) throw new InputError(`${field} must be an array of strings`);
  return value.map((v, i) => str(v, `${field}[${i}]`));
}
function json(value: unknown, field: string): Json {
  const seen = new Set<unknown>();
  const walk = (v: unknown, path: string, depth: number): Json => {
    if (depth > 32) throw new InputError(`${path} nests deeper than 32 levels`);
    if (v === null || typeof v === "boolean" || typeof v === "string") return v;
    if (typeof v === "number") return num(v, path);
    if (Array.isArray(v)) {
      if (seen.has(v)) throw new InputError(`${path} is cyclic`);
      seen.add(v);
      return v.map((item, i) => walk(item, `${path}[${i}]`, depth + 1));
    }
    if (typeof v === "object") {
      if (seen.has(v)) throw new InputError(`${path} is cyclic`);
      seen.add(v);
      const out: { [k: string]: Json } = {};
      for (const [k, item] of Object.entries(v as Record<string, unknown>)) {
        if (item === undefined) continue;
        Object.defineProperty(out, k, {
          value: walk(item, `${path}.${k}`, depth + 1),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return out;
    }
    throw new InputError(`${path} is not JSON data`);
  };
  return walk(value, field, 0);
}

function replay(value: unknown, field: string): ReplayResult {
  const r = exactObj(value, field, ["scenarioId", "reproduced", "attackSucceeded", "securityScore", "state", "trace"]);
  return {
    ...(r.scenarioId === undefined ? {} : { scenarioId: str(r.scenarioId, `${field}.scenarioId`) }),
    reproduced: bool(r.reproduced, `${field}.reproduced`),
    attackSucceeded: bool(r.attackSucceeded, `${field}.attackSucceeded`),
    securityScore: num(r.securityScore, `${field}.securityScore`),
    ...(r.state === undefined ? {} : { state: json(r.state, `${field}.state`) }),
    ...(r.trace === undefined ? {} : { trace: json(r.trace, `${field}.trace`) }),
  };
}
function impact(value: unknown, field: string): ImpactResult {
  const r = exactObj(value, field, ["safe", "reasons", "riskScore"]);
  return {
    safe: bool(r.safe, `${field}.safe`),
    reasons: strArray(r.reasons, `${field}.reasons`),
    ...(r.riskScore === undefined ? {} : { riskScore: num(r.riskScore, `${field}.riskScore`) }),
  };
}
function regression(value: unknown, field: string): RegressionResult {
  const r = exactObj(value, field, ["passed", "failures", "score"]);
  return {
    passed: bool(r.passed, `${field}.passed`),
    failures: strArray(r.failures, `${field}.failures`),
    ...(r.score === undefined ? {} : { score: num(r.score, `${field}.score`) }),
  };
}

export function parseEpisodeInput(raw: unknown): EpisodeInput {
  const a = exactObj(raw, "arguments", ["scenario", "baseline", "baselineReplay", "baselineFitness", "diagnosis", "candidates", "policy"]);
  const scenarioRaw = exactObj(a.scenario, "scenario", ["kind", "payload", "expectedSecurityProperty"]);
  const baselineRaw = exactObj(a.baseline, "baseline", ["id", "version", "state"]);
  const candidatesRaw = a.candidates ?? [];
  if (!Array.isArray(candidatesRaw)) throw new InputError("candidates must be an array");
  if (candidatesRaw.length > POLICY.maxCandidatesPerEpisode) {
    throw new InputError(`candidates exceeds ${POLICY.maxCandidatesPerEpisode} entries`);
  }
  const candidates: CandidateObservation[] = candidatesRaw.map((c, i) => {
    const cr = exactObj(c, `candidates[${i}]`, ["mutation", "defense", "impact", "replay", "regression", "fitnessScore"]);
    const mr = exactObj(cr.mutation, `candidates[${i}].mutation`, ["id", "description", "patch"]);
    const dr = exactObj(cr.defense, `candidates[${i}].defense`, ["id", "version", "state"]);
    if (!Object.prototype.hasOwnProperty.call(mr, "patch")) {
      throw new InputError(`candidates[${i}].mutation.patch is required`);
    }
    return {
      mutation: {
        ...(mr.id === undefined ? {} : { id: str(mr.id, `candidates[${i}].mutation.id`) }),
        description: str(mr.description, `candidates[${i}].mutation.description`),
        patch: json(mr.patch, `candidates[${i}].mutation.patch`),
      },
      defense: {
        id: str(dr.id, `candidates[${i}].defense.id`),
        version: str(dr.version, `candidates[${i}].defense.version`),
        ...(dr.state === undefined ? {} : { state: json(dr.state, `candidates[${i}].defense.state`) }),
      },
      impact: impact(cr.impact, `candidates[${i}].impact`),
      ...(cr.replay === undefined ? {} : { replay: replay(cr.replay, `candidates[${i}].replay`) }),
      ...(cr.regression === undefined
        ? {}
        : { regression: regression(cr.regression, `candidates[${i}].regression`) }),
      ...(cr.fitnessScore === undefined
        ? {}
        : { fitnessScore: num(cr.fitnessScore, `candidates[${i}].fitnessScore`) }),
    };
  });
  const seenPair = new Set<string>();
  const seenId = new Set<string>();
  candidates.forEach((c, i) => {
    const pair = `${JSON.stringify(c.mutation)}|${JSON.stringify(c.defense)}`;
    if (seenPair.has(pair)) throw new InputError(`candidates[${i}] duplicates an earlier mutation/defense pair`);
    seenPair.add(pair);
    if (c.mutation.id !== undefined) {
      if (seenId.has(c.mutation.id)) throw new InputError(`candidates[${i}].mutation.id is not unique`);
      seenId.add(c.mutation.id);
    }
  });
  const policyRaw = a.policy === undefined ? {} : exactObj(a.policy, "policy", ["requiredFitnessMargin"]);
  for (const key of Object.keys(policyRaw)) {
    if (key !== "requiredFitnessMargin") {
      throw new InputError(`policy.${key} is not supported; CIF/0.3 proof gates are mandatory`);
    }
  }
  return {
    scenario: {
      kind: str(scenarioRaw.kind, "scenario.kind"),
      payload: (() => {
        if (!Object.prototype.hasOwnProperty.call(scenarioRaw, "payload")) {
          throw new InputError("scenario.payload is required");
        }
        return json(scenarioRaw.payload, "scenario.payload");
      })(),
      expectedSecurityProperty: str(
        scenarioRaw.expectedSecurityProperty,
        "scenario.expectedSecurityProperty",
      ),
    },
    baseline: {
      id: str(baselineRaw.id, "baseline.id"),
      version: str(baselineRaw.version, "baseline.version"),
      ...(baselineRaw.state === undefined ? {} : { state: json(baselineRaw.state, "baseline.state") }),
    },
    baselineReplay: replay(a.baselineReplay, "baselineReplay"),
    ...(a.baselineFitness === undefined ? {} : { baselineFitness: num(a.baselineFitness, "baselineFitness") }),
    ...(a.diagnosis === undefined ? {} : { diagnosis: json(a.diagnosis, "diagnosis") }),
    candidates,
    policy: {
      ...(policyRaw.requiredFitnessMargin === undefined
        ? {}
        : { requiredFitnessMargin: (() => {
            const margin = num(policyRaw.requiredFitnessMargin, "policy.requiredFitnessMargin");
            if (margin < 0) throw new InputError("policy.requiredFitnessMargin must be non-negative");
            return margin;
          })() }),
    },
  };
}

export function parseEvidence(raw: unknown): EpisodeEvidence {
  const a = obj(raw, "arguments");
  const e = obj(a.evidence, "evidence");
  if (e.protocol !== PROTOCOL) throw new InputError(`evidence.protocol must be ${PROTOCOL}`);
  if (typeof e.evidenceRoot !== "string") throw new InputError("evidence.evidenceRoot must be a string");
  // Walk the payload as JSON data: bounded depth, no cycles, no non-JSON values reach the hasher.
  return json(e, "evidence") as unknown as EpisodeEvidence;
}

function verdict(value: unknown, field: string): LineageEntry["verdict"] {
  const v = str(value, field);
  if (!(POLICY.verdicts as readonly string[]).includes(v)) {
    throw new InputError(`${field} must be one of ${POLICY.verdicts.join(", ")}`);
  }
  return v as LineageEntry["verdict"];
}

function parseLineageEntries(raw: unknown): LineageEntry[] {
  const a = obj(raw, "arguments");
  const entries = a.entries;
  if (!Array.isArray(entries)) throw new InputError("entries must be an array");
  if (entries.length > POLICY.maxLineageEntries) {
    throw new InputError(`entries exceeds ${POLICY.maxLineageEntries} items`);
  }
  return entries.map((e, i) => {
    const r = obj(e, `entries[${i}]`);
    return {
      index: num(r.index, `entries[${i}].index`),
      scenarioId: str(r.scenarioId, `entries[${i}].scenarioId`),
      verdict: verdict(r.verdict, `entries[${i}].verdict`),
      reason: str(r.reason, `entries[${i}].reason`),
      ...(r.winnerId === undefined ? {} : { winnerId: str(r.winnerId, `entries[${i}].winnerId`) }),
      episodeRoot: str(r.episodeRoot, `entries[${i}].episodeRoot`),
      previousEntryHash: str(r.previousEntryHash, `entries[${i}].previousEntryHash`),
      entryHash: str(r.entryHash, `entries[${i}].entryHash`),
    };
  });
}

export const TOOLS = [
  {
    name: "adjudicate_defensive_mutation",
    description:
      "Adjudicate one defensive-mutation episode from recorded observations: impact screen, same-scenario replay, mandatory regression gates and positive fitness delta, then seal the decision as a Merkle evidence root. Executes nothing and promotes nothing on its own.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["scenario", "baseline", "baselineReplay"],
      properties: {
        scenario: {
          type: "object",
          additionalProperties: false,
          required: ["kind", "expectedSecurityProperty"],
          properties: {
            kind: { type: "string", minLength: 1, maxLength: 4096 },
            payload: {},
            expectedSecurityProperty: { type: "string", minLength: 1, maxLength: 4096 },
          },
        },
        baseline: {
          type: "object",
          additionalProperties: false,
          required: ["id", "version"],
          properties: { id: { type: "string", minLength: 1, maxLength: 4096 }, version: { type: "string", minLength: 1, maxLength: 4096 }, state: {} },
        },
        baselineReplay: {
          type: "object",
          additionalProperties: false,
          required: ["scenarioId", "reproduced", "attackSucceeded", "securityScore"],
          properties: {
            scenarioId: { type: "string", minLength: 1, maxLength: 4096 },
            reproduced: { type: "boolean" },
            attackSucceeded: { type: "boolean" },
            securityScore: { type: "number" },
            state: {},
            trace: {},
          },
        },
        baselineFitness: { type: "number" },
        diagnosis: {},
        candidates: {
          type: "array",
          maxItems: POLICY.maxCandidatesPerEpisode,
          items: {
            type: "object",
            additionalProperties: false,
            required: ["mutation", "defense", "impact"],
            properties: {
              mutation: {
                type: "object",
                additionalProperties: false,
                required: ["description"],
                properties: {
                  id: { type: "string", minLength: 1, maxLength: 4096 },
                  description: { type: "string", minLength: 1, maxLength: 4096 },
                  patch: {},
                },
              },
              defense: {
                type: "object",
                additionalProperties: false,
                required: ["id", "version"],
                properties: {
                  id: { type: "string", minLength: 1, maxLength: 4096 },
                  version: { type: "string", minLength: 1, maxLength: 4096 },
                  state: {},
                },
              },
              impact: {
                type: "object",
                additionalProperties: false,
                required: ["safe", "reasons"],
                properties: {
                  safe: { type: "boolean" },
                  reasons: { type: "array", items: { type: "string" } },
                  riskScore: { type: "number" },
                },
              },
              replay: {
                type: "object",
                additionalProperties: false,
                required: ["scenarioId", "reproduced", "attackSucceeded", "securityScore"],
                properties: {
                  scenarioId: { type: "string", minLength: 1, maxLength: 4096 },
                  reproduced: { type: "boolean" },
                  attackSucceeded: { type: "boolean" },
                  securityScore: { type: "number" },
                  state: {},
                  trace: {},
                },
              },
              regression: {
                type: "object",
                additionalProperties: false,
                required: ["passed", "failures"],
                properties: {
                  passed: { type: "boolean" },
                  failures: { type: "array", items: { type: "string" } },
                  score: { type: "number" },
                },
              },
              fitnessScore: { type: "number" },
            },
          },
        },
        policy: {
          type: "object",
          additionalProperties: false,
          properties: {
            requiredFitnessMargin: { type: "number", minimum: 0 },
          },
        },
      },
    },
  },
  {
    name: "verify_episode_evidence",
    description:
      "Recompute the Merkle evidence root of a sealed episode. Optionally compare it to an independently retained expected root; without one, verification proves internal consistency only.",
    inputSchema: {
      type: "object",
      required: ["evidence"],
      properties: {
        evidence: { type: "object" },
        expectedRoot: { type: "string" },
      },
    },
  },
  {
    name: "export_immune_lineage_report",
    description:
      "Export the hash-linked lineage of every episode adjudicated in this session, with verdict counts and an integrity flag.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "verify_immune_lineage",
    description:
      "Verify an exported lineage entry list link by link. Optionally compare the computed head to an independently retained expected head hash.",
    inputSchema: {
      type: "object",
      required: ["entries"],
      properties: {
        entries: { type: "array", items: { type: "object" } },
        expectedHeadHash: { type: "string" },
      },
    },
  },
  {
    name: "describe_policy",
    description:
      "Return the protocol versions, hash algorithm, default gate thresholds, input limits, rejection reasons and the declared absence of side effects.",
    inputSchema: { type: "object", properties: {} },
  },
  {
    name: "reset_state",
    description: "Clear this session's lineage. Previously exported reports remain independently verifiable.",
    inputSchema: { type: "object", properties: {} },
  },
] as const;

export interface CallResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
}

export function createHandler(lineage: ImmuneLineage = new ImmuneLineage()) {
  return async function callTool(name: string, args: unknown): Promise<CallResult> {
    const ok = (value: unknown): CallResult => ({
      content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    });
    try {
      switch (name) {
        case "adjudicate_defensive_mutation": {
          const evidence = await adjudicateEpisode(parseEpisodeInput(args));
          const entry = lineage.append(evidence);
          return ok({ evidence, lineageEntry: entry });
        }
        case "verify_episode_evidence": {
          const evidence = parseEvidence(args);
          const raw = obj(args, "arguments");
          const expectedRoot = raw.expectedRoot === undefined ? undefined : str(raw.expectedRoot, "expectedRoot");
          const internallyConsistent = verifyEvidenceRoot(evidence);
          const matchesExpectedRoot =
            expectedRoot === undefined ? undefined : evidence.evidenceRoot === expectedRoot;
          return ok({
            evidenceRoot: evidence.evidenceRoot,
            internallyConsistent,
            ...(expectedRoot === undefined ? {} : { expectedRoot, matchesExpectedRoot }),
            intact: verifyEvidenceRoot(evidence, expectedRoot),
          });
        }
        case "export_immune_lineage_report": {
          const report: LineageReport = lineage.report();
          return ok(report);
        }
        case "verify_immune_lineage": {
          const entries = parseLineageEntries(args);
          const raw = obj(args, "arguments");
          const expectedHeadHash =
            raw.expectedHeadHash === undefined ? undefined : str(raw.expectedHeadHash, "expectedHeadHash");
          const summary = summarizeLineage(entries);
          const internallyConsistent = verifyLineage(entries);
          const matchesExpectedHeadHash =
            expectedHeadHash === undefined ? undefined : summary.headHash === expectedHeadHash;
          return ok({
            entryCount: entries.length,
            headHash: summary.headHash,
            counts: summary.counts,
            internallyConsistent,
            ...(expectedHeadHash === undefined ? {} : { expectedHeadHash, matchesExpectedHeadHash }),
            intact: verifyLineage(entries, expectedHeadHash),
          });
        }
        case "describe_policy":
          return ok({ server: SERVER_NAME, version: SERVER_VERSION, ...POLICY, tools: TOOLS.map((t) => t.name) });
        case "reset_state":
          lineage.reset();
          return ok({ reset: true });
        default:
          return { content: [{ type: "text", text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      const message =
        error instanceof InputError
          ? error.message
          : error instanceof Error && /^[A-Z_]+:/.test(error.message)
            ? error.message
            : "invalid request";
      return { content: [{ type: "text", text: `Rejected: ${message}` }], isError: true };
    }
  };
}


function validInitializeParams(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const p = value as Record<string, unknown>;
  if (typeof p.protocolVersion !== "string" || p.protocolVersion.length === 0) return false;
  if (typeof p.capabilities !== "object" || p.capabilities === null || Array.isArray(p.capabilities)) return false;
  if (typeof p.clientInfo !== "object" || p.clientInfo === null || Array.isArray(p.clientInfo)) return false;
  const info = p.clientInfo as Record<string, unknown>;
  return (
    typeof info.name === "string" &&
    info.name.length > 0 &&
    typeof info.version === "string" &&
    info.version.length > 0
  );
}

interface RpcRequest {
  jsonrpc?: string;
  id?: number | string | null;
  method?: string;
  params?: Record<string, unknown>;
}

export async function handleRpc(
  request: unknown,
  callTool: ReturnType<typeof createHandler>,
): Promise<Record<string, unknown> | undefined> {
  if (typeof request !== "object" || request === null || Array.isArray(request)) {
    return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "invalid request" } };
  }
  const rpc = request as RpcRequest;
  const idIsValid =
    rpc.id === undefined ||
    rpc.id === null ||
    typeof rpc.id === "string" ||
    (typeof rpc.id === "number" && Number.isFinite(rpc.id));
  if (rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string" || !idIsValid) {
    const invalidId =
      typeof rpc.id === "string" || (typeof rpc.id === "number" && Number.isFinite(rpc.id)) || rpc.id === null
        ? rpc.id
        : null;
    return { jsonrpc: "2.0", id: invalidId, error: { code: -32600, message: "invalid request" } };
  }
  const { id, method, params } = rpc;
  if (id === undefined) return undefined; // notification
  const reply = (result: unknown) => ({ jsonrpc: "2.0", id, result });
  switch (method) {
    case "initialize":
      if (!validInitializeParams(params)) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "invalid initialize params" } };
      }
      return reply({
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: TOOLS });
    // Declared empty so clients that probe these surfaces on connect do not report an error.
    case "resources/list":
      return reply({ resources: [] });
    case "prompts/list":
      return reply({ prompts: [] });
    case "tools/call": {
      if (typeof params !== "object" || params === null || Array.isArray(params)) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "invalid tools/call params" } };
      }
      const name = typeof params.name === "string" && params.name.length > 0 ? params.name : "";
      const args = params.arguments ?? {};
      if (!name || typeof args !== "object" || args === null || Array.isArray(args)) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "invalid tools/call params" } };
      }
      return reply(await callTool(name, args));
    }
    default:
      return { jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } };
  }
}

/**
 * Frames newline-delimited JSON-RPC and answers strictly in arrival order. Requests are queued
 * rather than raced, so a slow adjudication cannot reorder replies or interleave lineage appends.
 */
export function createLineProcessor(
  callTool: ReturnType<typeof createHandler>,
  write: (line: string) => void,
) {
  let buffer = "";
  let chain: Promise<void> = Promise.resolve();
  const emit = (value: unknown) => write(JSON.stringify(value) + "\n");
  const queueResponse = (value: unknown): void => {
    chain = chain.then(async () => {
      emit(value);
    });
  };
  const queue = (line: string): void => {
    chain = chain.then(async () => {
      let response: Record<string, unknown> | undefined;
      try {
        response = await handleRpc(JSON.parse(line), callTool);
      } catch {
        response = { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } };
      }
      if (response) emit(response);
    });
  };
  return {
    push(chunk: string): void {
      buffer += chunk;
      let index = buffer.indexOf("\n");
      while (index !== -1) {
        const rawLine = buffer.slice(0, index);
        buffer = buffer.slice(index + 1);
        const line = rawLine.trim();
        if (line) {
          if (Buffer.byteLength(rawLine, "utf8") > POLICY.maxRequestBytes) {
            queueResponse({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "request too large" } });
          } else {
            queue(line);
          }
        }
        index = buffer.indexOf("\n");
      }
      if (Buffer.byteLength(buffer, "utf8") > POLICY.maxRequestBytes) {
        buffer = "";
        queueResponse({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "request too large" } });
      }
    },
    drain(): Promise<void> {
      return chain;
    },
  };
}

export function startStdioServer(): void {
  const processor = createLineProcessor(createHandler(), (line) => process.stdout.write(line));
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => processor.push(chunk));
}

const entry = process.argv[1] ?? "";
// Only run the transport when this module is the process entry point, never when imported by tests.
const invokedDirectly = /(^|[\\/])mcp-server\.js$/.test(entry);
if (invokedDirectly) startStdioServer();
