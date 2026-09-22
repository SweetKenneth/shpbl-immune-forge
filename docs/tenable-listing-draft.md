---
name: "Counterfactual Immune Forge"
author: "SweetKenneth"
github_url: "https://github.com/SweetKenneth/shpbl-immune-forge"
description: "Adjudicates reported defensive-change observations through reproduction, impact, same-scenario, regression and improvement gates, then seals the decision record and every rejection as a recomputable Merkle evidence root."
license: "MIT"
tags: ["ai-agent-security", "detection-engineering", "regression-gate", "evidence", "change-control", "deterministic", "provenance", "mcp"]
domains: ["ai-security", "security-operations"]
tier: "contributed"
integrations: []
date_added: 2026-09-12
contribution_agreement_date: 2026-09-12T01:50:00Z
works_with_tenable_hexa_mcp: false
transport: "stdio"
runtime: "node"
auth_method: "none"
compatible_clients: ["Claude Code", "Claude Desktop", "Cursor"]
tools_exposed:
  - name: "adjudicate_defensive_mutation"
    description: "Adjudicate one defensive-mutation episode from recorded observations and return sealed evidence plus a lineage entry; executes nothing and promotes nothing on its own"
  - name: "verify_episode_evidence"
    description: "Recompute an episode's Merkle evidence root and report whether the covered bytes are unmodified"
  - name: "export_immune_lineage_report"
    description: "Export the hash-linked lineage of every episode adjudicated in this session with verdict counts and an integrity flag"
  - name: "verify_immune_lineage"
    description: "Verify an exported lineage entry list link by link without trusting this session's state"
  - name: "describe_policy"
    description: "Return protocol versions, hash algorithm, default gate thresholds, input limits, rejection reasons and the declared absence of side effects"
  - name: "reset_state"
    description: "Clear this session's lineage; previously exported reports remain independently verifiable"
resources_exposed: []
prompts_exposed: []
---

When a guardrail, agent policy or detection rule is defeated, the patch that follows is usually accepted on trust. This server refuses to accept it on trust. It seals the attack scenario first, then makes every proposed change earn promotion against that same sealed scenario — and preserves the ones that failed.

## What it does

The operator's own harness runs the attack and the regression suite; the server adjudicates the observations that harness supplies. An episode is `INCONCLUSIVE` unless the reported baseline replay shows the current defense failing the sealed scenario. Each candidate change is screened for blast radius before it can earn replay credit, checked against the identical sealed scenario, rejected outright if its reported replay says the attack still succeeds, put through a mandatory protected-behaviour regression gate, and required to score finitely and strictly above the baseline by at least the configured margin. At most one candidate — the highest scoring one that cleared every gate — receives a `PROMOTED` verdict. Every rejected candidate is preserved with a machine-readable reason (`IMPACT_SCREEN_FAILED`, `SCENARIO_REPLAY_FAILED`, `ATTACK_NOT_NEUTRALIZED`, `REGRESSION_GATE_FAILED`, `NO_PROVEN_IMPROVEMENT`). The decision record is sealed as a SHA-256 Merkle evidence root and appended to a hash-linked lineage that can be exported and verified independently of the server's memory. The server never executes a candidate or independently verifies that harness observations are truthful.

## How it works

A zero-runtime-dependency stdio MCP server (`node:crypto` only) written from a public behaviour specification. Missing evidence is a failed gate, never a pass: an absent replay, regression or fitness observation cannot clear a gate. The scenario is canonicalized with sorted keys and hashed before any candidate is considered, and one sealed scenario is bound to all observations in that episode. Optional exploratory "dream" analysis runs only after sealing, receives only sealed evidence, and cannot alter the verdict or the root. The source contains no filesystem, network, process-spawning or environment access; a static conformance test checks that declared boundary. Forty-seven tests cover each gate, promotion selection among competing candidates, tamper detection on every covered field, lineage reordering and edits, malformed and cyclic input rejection, transport boundaries, and the MCP handshake.

Known limitations, stated verbatim in the repository: it is not an autonomous security oracle, and a compromised evaluator — a rigged harness or a fitness function rewarding the wrong thing — yields sealed evidence of a bad decision. Sealing proves integrity, not wisdom. Session lineage is in memory; exported reports are the durable artifact.
