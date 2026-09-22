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

export class ImmuneLineage {
  private readonly entries: LineageEntry[] = [];

  append(evidence: EpisodeEvidence): LineageEntry {
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
    let previous = GENESIS;
    for (let i = 0; i < entries.length; i += 1) {
      const e = entries[i];
      if (!(e.verdict === "PROMOTED" || e.verdict === "REJECTED" || e.verdict === "INCONCLUSIVE")) return false;
      if (e.index !== i || e.previousEntryHash !== previous) return false;
      const { entryHash, ...core } = e;
      if (hash(core) !== entryHash) return false;
      previous = entryHash;
    }
    return expectedHeadHash === undefined || previous === expectedHeadHash;
  } catch {
    return false;
  }
}
