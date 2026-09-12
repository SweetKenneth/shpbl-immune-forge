# Counterfactual Immune Forge

**Proof-gated defense evolution for AI agents and security automation.**

When an agent, guardrail, or detection rule is defeated, the tempting next step is to patch it and move on.
The Counterfactual Immune Forge refuses to accept a patch on anyone's word. It seals the attack scenario,
proves the current defense really fails it, adjudicates each proposed change against **that same sealed
scenario**, forces every change through a regression gate, requires a positive, policy-defined improvement,
and then seals the whole decision — including every rejected candidate and the reason it was rejected — as a
SHA-256 Merkle evidence root that anyone can recompute later.

It is a decision authority, not an actuator. It promotes nothing by itself, executes nothing, and touches no
files, sockets, processes, or environment variables.

## Why a practitioner would install this

- **Defense changes stop being trust-me changes.** Every promotion carries recomputable evidence that the
  original attack was reproduced, that the fix defeated it, that protected behaviour still passed, and by how
  much the score improved.
- **Rejections are preserved, not discarded.** The most useful review artifact is the list of fixes that
  looked good and failed a gate — including the "fixed the attack, broke legitimate traffic" case.
- **Goalposts cannot move.** The scenario is canonicalized and hashed before any candidate is considered, and
  the same sealed object is used for the baseline and every candidate replay.
- **The audit trail is hash-linked.** Every adjudicated episode is appended to an immune lineage whose links
  are verifiable independently of this server's memory.
- **Nothing about it is model-dependent.** Reasoning about *what* to try can come from an agent, a fuzzer, a
  human, or a rules engine. The gates and the sealing are plain deterministic code.

## Protocol

`CIF/0.1`, in order:

1. Canonicalize and hash the triggering scenario (`sealScenario`).
2. Reproduce the baseline against it. If it does not reproduce → `INCONCLUSIVE`; no candidate is evaluated.
3. Optionally record a diagnosis. Evidence only — it carries no promotion authority.
4. Screen each candidate for blast radius before it can earn replay credit.
5. Replay the surviving candidates against the *same sealed scenario*.
6. Apply the mandatory regression gate over protected behaviour.
7. Require a finite fitness score strictly above the baseline plus the configured margin.
8. Record every rejected candidate with a machine-readable reason.
9. Promote at most the single highest-scoring candidate that cleared every gate.
10. Seal the episode as a Merkle evidence root.
11. Run optional DREAM exploration **after** sealing, on the sealed evidence only. It cannot change the
    verdict or the root.

Rejection reasons: `IMPACT_SCREEN_FAILED`, `SCENARIO_REPLAY_FAILED`, `REGRESSION_GATE_FAILED`,
`NO_PROVEN_IMPROVEMENT`. Verdicts: `PROMOTED`, `REJECTED`, `INCONCLUSIVE`.

Full behavioural contract: [`SPEC.md`](./SPEC.md).

## Prerequisites

- Node.js 20 or newer (`node --version`). Nothing else — zero runtime dependencies.
- An MCP client that speaks stdio (Claude Code, Claude Desktop, Cursor), or direct library use from TypeScript.
- No API key, account, network access, or Tenable product is required.

## Install and run

```bash
git clone https://github.com/SweetKenneth/shpbl-immune-forge.git
cd shpbl-immune-forge
npm install      # devDependencies only: typescript, @types/node
npm run build    # compiles to dist/
npm test         # 34 conformance, tamper, and boundary tests
npm start        # starts the MCP server on stdio
```

MCP client configuration:

```json
{
  "mcpServers": {
    "immune-forge": {
      "command": "node",
      "args": ["/absolute/path/to/shpbl-immune-forge/dist/src/mcp-server.js"]
    }
  }
}
```

## Outputs

Every tool returns JSON text content. `adjudicate_defensive_mutation` returns the verdict
(`PROMOTED` / `REJECTED` / `INCONCLUSIVE`), the promoted candidate if any, every rejected candidate with its
machine-readable reason, the sealed scenario hash, the SHA-256 Merkle evidence root, and the appended lineage
entry. `verify_episode_evidence` and `verify_immune_lineage` return pass/fail integrity results,
`export_immune_lineage_report` returns the hash-linked lineage plus verdict counts, and `describe_policy`
returns the versions, thresholds, input limits, and rejection-reason vocabulary in force. Nothing is written to
disk and nothing is sent anywhere — the caller keeps whatever it chooses to keep.

## MCP tools


| Tool | What it does |
| --- | --- |
| `adjudicate_defensive_mutation` | Adjudicates one episode from recorded observations and returns sealed evidence plus a lineage entry. |
| `verify_episode_evidence` | Recomputes an episode's Merkle root and reports whether the covered bytes are unmodified. |
| `export_immune_lineage_report` | Exports the hash-linked lineage of this session with verdict counts and an integrity flag. |
| `verify_immune_lineage` | Verifies an exported lineage link by link, without trusting this session. |
| `describe_policy` | Publishes protocol versions, hash algorithm, gate defaults, input limits, and the no-side-effect declaration. |
| `reset_state` | Clears session lineage. Previously exported reports stay independently verifiable. |

The MCP surface is **data-driven**: your own harness runs the attack and the regression suite and reports what
it observed. The Forge enforces the gates over those observations. Missing evidence is always a failed gate,
never a pass. Library users who want the Forge to drive their harness directly can implement `ForgeAdapters`
and call `CounterfactualImmuneForge.run()`.

## Library use

```ts
import { adjudicateEpisode, verifyEvidenceRoot } from "shpbl-counterfactual-immune-forge";

const evidence = await adjudicateEpisode({
  scenario: { kind: "prompt-injection", payload: { vector: "tool-arg" }, expectedSecurityProperty: "refuse untrusted tool instruction" },
  baseline: { id: "guard", version: "1.0.0" },
  baselineReplay: { reproduced: true, attackSucceeded: true, securityScore: 0.2 },
  candidates: [{
    mutation: { id: "quarantine", description: "quarantine tool-sourced instructions", patch: { rule: "quarantine" } },
    defense: { id: "guard", version: "1.1.0" },
    impact: { safe: true, reasons: [] },
    replay: { reproduced: true, attackSucceeded: false, securityScore: 0.95 },
    regression: { passed: true, failures: [] },
    fitnessScore: 0.95,
  }],
});

evidence.verdict;              // "PROMOTED"
verifyEvidenceRoot(evidence);  // true
```

## Threat model and misuse boundary

- **Protects against** silent defense regressions, unproven "fixes", moved goalposts, and post-hoc editing of
  what a promotion was based on.
- **Does not protect against** an operator who ignores the verdict, or a harness that reports observations
  dishonestly. Garbage in is sealed as garbage — verifiably, and attributable to the reporter.
- **Refuses** filesystem, network, process, and environment access entirely, so it cannot be repurposed as an
  offensive or surveillance tool. It never generates exploits and never applies changes to a live system.
- **Input limits** are published by `describe_policy`: 256 candidates per episode, 10,000 lineage entries per
  verification, 1 MiB per request, 32 levels of JSON nesting, and rejection of cyclic, non-finite, or
  unknown-verdict values.

## Honest limitations

- It is **not an autonomous security oracle**. It adjudicates the evidence it is given; it does not decide
  what is worth defending.
- **A compromised evaluator** — a rigged harness or a fitness function that rewards the wrong thing — produces
  sealed evidence of a bad decision. Sealing proves integrity, not wisdom.
- Fitness semantics are yours. The Forge only enforces "strictly better than baseline, by at least the
  configured margin".
- Session lineage is in memory. Persist exported reports yourself if you need durable history.
- Verification proves the evidence bytes are unmodified; it does not prove the observations were true.

## Provenance

Invented and specified by SHPBL (Kenneth E. Sweet Jr.). This repository is a clean-room implementation written
from the public behavioural specification in `SPEC.md`; no proprietary SHPBL library bodies are included. The
Forge composes ideas SHPBL had already proven separately — replay, sandboxed impact screening, regression
authority, evolutionary scoring, evidence sealing, and post-proof exploration — into one gate chain where none
of them can be skipped.

More SHPBL security tooling: <https://shpbl.com/tenable-submissions>

## Tenable status

Submitted to the Tenable CyberAgents Exchange for review on September 12, 2026
([pull request #169](https://github.com/tenable/cyberagents-exchange/pull/169)).
Submission does not imply review, approval, certification, validation, endorsement, or acceptance by Tenable.

## License

MIT — see [`LICENSE`](./LICENSE). Zero runtime dependencies; Node.js 20+.
