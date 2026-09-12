// Immune lineage: a hash-linked ledger of sealed episode decisions.
// SPDX-License-Identifier: MIT
import { hash, type EpisodeEvidence, type Verdict } from "./core.js";

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
  entries: LineageEntry[];
  counts: Record<Verdict, number>;
  headHash: string;
  intact: boolean;
}

const GENESIS = hash("CIF-LINEAGE/0.1:genesis");

export class ImmuneLineage {
  private readonly entries: LineageEntry[] = [];

  append(evidence: EpisodeEvidence): LineageEntry {
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
    const entry: LineageEntry = { ...core, entryHash: hash(core) };
    this.entries.push(entry);
    return entry;
  }

  report(): LineageReport {
    const counts: Record<Verdict, number> = { PROMOTED: 0, REJECTED: 0, INCONCLUSIVE: 0 };
    for (const e of this.entries) counts[e.verdict] += 1;
    return {
      protocol: "CIF-LINEAGE/0.1",
      entries: [...this.entries],
      counts,
      headHash: this.entries.length ? this.entries[this.entries.length - 1].entryHash : GENESIS,
      intact: verifyLineage(this.entries),
    };
  }

  reset(): void {
    this.entries.length = 0;
  }
}

export function verifyLineage(entries: readonly LineageEntry[]): boolean {
  let previous = GENESIS;
  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];
    if (e.index !== i || e.previousEntryHash !== previous) return false;
    const { entryHash, ...core } = e;
    if (hash(core) !== entryHash) return false;
    previous = entryHash;
  }
  return true;
}
