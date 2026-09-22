// Immune lineage: a hash-linked ledger of sealed episode decisions.
// SPDX-License-Identifier: MIT
import { hash, verifyEvidenceRoot, type EpisodeEvidence, type Verdict } from "./core.js";

export interface LineageEntry {
  index: number;
  scenarioId: string;
  verdict: Verdict;
  reason: string;
  winnerId?: string;
  episodeRoot: string;
  previousEntryHash: string;
  entryHash: string;
}

export interface LineageReport {
  protocol: "CIF-LINEAGE/0.1";
  entries: readonly LineageEntry[];
  counts: Readonly<Record<Verdict, number>>;
  headHash: string;
  intact: boolean;
}

const GENESIS = hash("CIF-LINEAGE/0.1:genesis");
export const MAX_LINEAGE_ENTRIES = 10_000 as const;

export class ImmuneLineage {
  private readonly entries: LineageEntry[] = [];

  constructor(private readonly maxEntries: number = MAX_LINEAGE_ENTRIES) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_LINEAGE_ENTRIES) {
      throw new Error(`INVALID_LINEAGE_LIMIT: maxEntries must be an integer from 1 to ${MAX_LINEAGE_ENTRIES}`);
    }
  }

  append(evidence: EpisodeEvidence): LineageEntry {
    if (this.entries.length >= this.maxEntries) {
      throw new Error(`LINEAGE_LIMIT_EXCEEDED: lineage is capped at ${this.maxEntries} entries`);
    }
    if (!verifyEvidenceRoot(evidence)) {
      throw new Error("INVALID_EPISODE_EVIDENCE: lineage accepts only internally consistent sealed evidence");
    }
    const previousEntryHash = this.entries.length
      ? this.entries[this.entries.length - 1].entryHash
      : GENESIS;
    const core = {
      index: this.entries.length,
      scenarioId: evidence.scenarioId,
      verdict: evidence.verdict,
      reason: evidence.reason,
      winnerId: evidence.winnerId,
      episodeRoot: evidence.evidenceRoot,
      previousEntryHash,
    };
    const entry: LineageEntry = Object.freeze({ ...core, entryHash: hash(core) });
    this.entries.push(entry);
    return entry;
  }

  report(): LineageReport {
    const summary = summarizeLineage(this.entries);
    const entries = Object.freeze(this.entries.map((e) => Object.freeze({ ...e })));
    return Object.freeze({
      protocol: "CIF-LINEAGE/0.1",
      entries,
      counts: Object.freeze({ ...summary.counts }),
      headHash: summary.headHash,
      intact: verifyLineage(this.entries),
    });
  }

  reset(): void {
    this.entries.length = 0;
  }
}

export function summarizeLineage(entries: readonly LineageEntry[]): {
  counts: Record<Verdict, number>;
  headHash: string;
} {
  const counts: Record<Verdict, number> = { PROMOTED: 0, REJECTED: 0, INCONCLUSIVE: 0 };
  for (const e of entries) {
    if (e.verdict in counts) counts[e.verdict] += 1;
  }
  return {
    counts,
    headHash: entries.length ? entries[entries.length - 1].entryHash : GENESIS,
  };
}

export function verifyLineage(entries: readonly LineageEntry[], expectedHeadHash?: string): boolean {
  try {
    const allowed = new Set([
      "index",
      "scenarioId",
      "verdict",
      "reason",
      "winnerId",
      "episodeRoot",
      "previousEntryHash",
      "entryHash",
    ]);
    const hex64 = (value: unknown): value is string =>
      typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
    let previous = GENESIS;
    for (let i = 0; i < entries.length; i += 1) {
      const e = entries[i];
      if (!e || typeof e !== "object" || Array.isArray(e)) return false;
      if (Object.keys(e as unknown as Record<string, unknown>).some((key) => !allowed.has(key))) return false;
      if (!(e.verdict === "PROMOTED" || e.verdict === "REJECTED" || e.verdict === "INCONCLUSIVE")) return false;
      if (!Number.isInteger(e.index) || e.index !== i) return false;
      if (!hex64(e.scenarioId) || !hex64(e.episodeRoot) || !hex64(e.previousEntryHash) || !hex64(e.entryHash)) return false;
      if (typeof e.reason !== "string" || e.reason.length === 0) return false;
      if (e.winnerId !== undefined && (typeof e.winnerId !== "string" || e.winnerId.length === 0)) return false;
      if (e.previousEntryHash !== previous) return false;
      const { entryHash, ...core } = e;
      if (hash(core) !== entryHash) return false;
      previous = entryHash;
    }
    if (expectedHeadHash !== undefined && !hex64(expectedHeadHash)) return false;
    return expectedHeadHash === undefined || previous === expectedHeadHash;
  } catch {
    return false;
  }
}
