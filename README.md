# Counterfactual Immune Forge

**Proof-gated defense evolution for AI agents and security automation.**

When an agent, guardrail, or detection rule is defeated, the tempting next step is to patch it and move on.
The Counterfactual Immune Forge refuses to accept a patch from an incomplete observation record. It seals the
supplied attack scenario, requires the reported baseline replay to show the current defense failing it,
adjudicates each proposed change against **that same sealed scenario record**, forces every change through a
regression gate, requires a positive, policy-defined reported improvement,
and then seals the whole decision — including every rejected candidate and the reason it was rejected — as a
SHA-256 Merkle evidence root that anyone can recompute later.

It is a decision authority, not an actuator. It promotes nothing by itself, executes no candidate, reads no
files, opens no network sockets, spawns no subprocesses, and reads no environment variables. Its stdio transport
necessarily uses the host process's stdin/stdout.

## Why a practitioner would install this

- **Defense changes stop being undocumented trust-me changes.** Every `PROMOTED` verdict carries recomputable
  evidence of what the caller reported: baseline reproduction, candidate neutralization, protected-behaviour
  regression status, and score improvement.
- **Rejections are preserved, not discarded.** The most useful review artifact is the list of fixes that
  looked good and failed a gate — including the "fixed the attack, broke legitimate traffic" case.
- **The scenario identity cannot move inside the Forge.** The scenario is canonicalized and hashed before any
  candidate is considered. Data-driven baseline and candidate replay observations must claim that same sealed
  hash; direct adapters receive the same sealed scenario object for every replay.
- **The audit trail is hash-linked.** Every adjudicated episode is appended to an immune lineage whose links
  are verifiable independently of this server's memory.
- **Nothing about it is model-dependent.** Reasoning about *what* to try can come from an agent, a fuzzer, a
  human, or a rules engine. The gates and the sealing are plain deterministic code.

## Protocol

`CIF/0.3`, in order:

1. Canonicalize and hash the triggering scenario (`sealScenario`).
2. Reproduce the baseline against it. Data-driven baseline evidence must carry the sealed scenario hash. The
   baseline must both reproduce **and report the attack succeeding**; otherwise → `INCONCLUSIVE` and no candidate
   is evaluated. This proof gate is mandatory in `CIF/0.3`.
3. Optionally record a diagnosis. Evidence only — it carries no promotion authority.
4. Screen each candidate for blast radius before it can earn replay credit.
5. Require each survivor's supplied replay observation to carry the hash of the *same sealed scenario*. A missing or mismatched binding fails the replay gate.
6. Reject any candidate whose own replay still reports the attack succeeding. This proof gate is mandatory
   in `CIF/0.3`; a high score cannot buy promotion for a change that did not stop the attack.
7. Apply the mandatory regression gate over protected behaviour.
8. Score the baseline and each candidate on the same caller-defined fitness scale, then require a finite candidate score strictly above the explicit baseline fitness plus the configured margin.
9. Record every rejected candidate with a machine-readable reason.
10. Return `PROMOTED` for at most the single highest-scoring candidate that cleared every gate.
11. Seal the episode as a Merkle evidence root.
12. Run optional DREAM exploration **after** sealing, on the sealed evidence only. It cannot change the
    verdict or the root.

Rejection reasons: `IMPACT_SCREEN_FAILED`, `SCENARIO_REPLAY_FAILED`, `ATTACK_NOT_NEUTRALIZED`,
`REGRESSION_GATE_FAILED`, `NO_PROVEN_IMPROVEMENT`. Verdicts: `PROMOTED`, `REJECTED`, `INCONCLUSIVE`.

The effective policy is sealed inside the evidence root. `requiredFitnessMargin` is configurable and
non-negative; `requireAttackReproduction` and `requireAttackNeutralized` are recorded as `true` and cannot be
disabled in `CIF/0.3`, so a reader can see exactly which invariants produced the verdict.

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
npm test         # conformance, tamper, adversarial, and boundary tests
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
entry. `verify_episode_evidence` and `verify_immune_lineage` report internal hash consistency and can optionally
compare against an independently retained expected evidence root / lineage head. `export_immune_lineage_report`
returns the hash-linked lineage plus verdict counts, and `describe_policy`
returns the versions, thresholds, input limits, and rejection-reason vocabulary in force. Nothing is written to
disk and nothing is sent anywhere — the caller keeps whatever it chooses to keep.

## MCP tools


| Tool | What it does |
| --- | --- |
| `adjudicate_defensive_mutation` | Adjudicates one episode from recorded observations and returns sealed evidence plus a lineage entry. |
| `verify_episode_evidence` | Recomputes an episode's Merkle root; optionally anchors it to an independently retained expected root. |
| `export_immune_lineage_report` | Exports the hash-linked lineage of this session with verdict counts and an integrity flag. |
| `verify_immune_lineage` | Verifies lineage links and can optionally require an independently retained expected head hash. |
| `describe_policy` | Publishes protocol versions, hash algorithm, gate defaults, input limits, and the no-side-effect declaration. |
| `reset_state` | Clears session lineage. Previously exported reports stay independently verifiable. |

The MCP surface is **data-driven**: your own harness runs the attack and the regression suite and reports what
it observed. Both baseline and candidate replay observations must include the sealed scenario hash returned by
`sealScenario`; this binds the reporter's claim to the episode but does not prove that an external harness was honest. The Forge enforces the gates over those observations. Missing evidence is always a failed gate,
never a pass. Library users who want the Forge to drive their harness directly can implement `ForgeAdapters`
and call `CounterfactualImmuneForge.run()`.

## Library use

```ts
import { adjudicateEpisode, sealScenario, verifyEvidenceRoot } from "shpbl-counterfactual-immune-forge";

const scenario = {
  kind: "prompt-injection",
  payload: { vector: "tool-arg" },
  expectedSecurityProperty: "refuse untrusted tool instruction",
};
const scenarioId = sealScenario(scenario).id!;

const evidence = await adjudicateEpisode({
  scenario,
  baseline: { id: "guard", version: "1.0.0" },
  baselineReplay: { scenarioId, reproduced: true, attackSucceeded: true, securityScore: 0.2 },
  baselineFitness: 0.2,
  candidates: [{
    mutation: { id: "quarantine", description: "quarantine tool-sourced instructions", patch: { rule: "quarantine" } },
    defense: { id: "guard", version: "1.1.0" },
    impact: { safe: true, reasons: [] },
    replay: { scenarioId, reproduced: true, attackSucceeded: false, securityScore: 0.95 },
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
- **Refuses** application-level filesystem reads/writes, network sockets, subprocess spawning, and environment-variable
  reads, so it cannot be repurposed as an offensive or surveillance tool. The stdio transport uses only stdin/stdout.
  It never generates exploits and never applies changes to a live system.
- **Input limits** are published by `describe_policy`: 256 candidates per episode, 10,000 lineage entries per
  verification, 1 MiB per request, 32 levels of JSON nesting, and rejection of cyclic, non-finite, or
  unknown-verdict values. Duplicate observations of one mutation/defense pair and duplicate explicit mutation IDs are refused rather than
  collapsed, and requests are answered strictly in arrival order.

## Honest limitations

- It is **not an autonomous security oracle**. It adjudicates the evidence it is given; it does not decide
  what is worth defending.
- **A compromised evaluator** — a rigged harness or a fitness function that rewards the wrong thing — produces
  sealed evidence of a bad decision. Sealing proves integrity, not wisdom.
- Fitness semantics are yours. The data-driven API requires an explicit `baselineFitness`, and direct adapters
  provide `baselineFitness()`, so the baseline and candidate scores share the evaluator-defined scale. The Forge
  enforces only "strictly better than baseline, by at least the configured margin".
- Session lineage is in memory. Persist exported reports yourself if you need durable history.
- Hash verification without an independently retained expected root/head proves **internal consistency**, not
  historical authenticity: someone who can replace both an artifact and its embedded hash can recompute a new
  self-consistent artifact. Supply `expectedRoot` / `expectedHeadHash` when you need an external anchor.
- Verification never proves the reported observations were true.

## Provenance

Invented and specified by SHPBL (Kenneth E. Sweet Jr.). This repository is a clean-room implementation written
from the public behavioural specification in `SPEC.md`; no proprietary SHPBL library bodies are included. The
Forge composes ideas SHPBL had already proven separately — replay, sandboxed impact screening, regression
authority, evolutionary scoring, evidence sealing, and post-proof exploration — into one gate chain where none
of them can be skipped.

More SHPBL security tooling: <https://shpbl.com/tenable-submissions>

## Tenable status

Submitted to the Tenable CyberAgents Exchange on September 12, 2026 and initially merged as
[pull request #169](https://github.com/tenable/cyberagents-exchange/pull/169). Tenable later removed the listing
in [pull request #187](https://github.com/tenable/cyberagents-exchange/pull/187) during its post-merge review. The
listing is not currently published by the Exchange. Version 0.2.0 closed the original candidate-neutralization defect; version 0.2.1 added transport and submission-structure hardening; version 0.2.2 closes additional baseline-qualification, replay-binding, policy-margin, candidate-identity,
immutability, lineage-state, and verification-anchor gaps found during adversarial review.
Past or future listing status does not imply review, approval, certification, validation, or endorsement of
this software by Tenable.

## License

MIT — see [`LICENSE`](./LICENSE). Zero runtime dependencies; Node.js 20+.
