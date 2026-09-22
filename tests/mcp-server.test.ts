import test from "node:test";
import assert from "node:assert/strict";
import { createHandler, createLineProcessor, handleRpc, SERVER_VERSION, TOOLS, POLICY } from "../src/mcp-server.js";
import { ImmuneLineage } from "../src/lineage.js";

const episode = {
  scenario: { kind: "prompt-injection", payload: { vector: "tool-arg" }, expectedSecurityProperty: "refuse untrusted tool instruction" },
  baseline: { id: "guard", version: "1.0.0" },
  baselineReplay: { reproduced: true, attackSucceeded: true, securityScore: 0.2 },
  candidates: [
    {
      mutation: { id: "cand-a", description: "quarantine tool-sourced instructions", patch: { rule: "quarantine" } },
      defense: { id: "guard", version: "1.1.0" },
      impact: { safe: true, reasons: [] },
      replay: { reproduced: true, attackSucceeded: false, securityScore: 0.95 },
      regression: { passed: true, failures: [] },
      fitnessScore: 0.95,
    },
  ],
};

function parse(result: { content: { text: string }[] }): any {
  return JSON.parse(result.content[0].text);
}

test("initialize, ping and tools/list answer the MCP handshake", async () => {
  const call = createHandler();
  const init: any = await handleRpc({ jsonrpc: "2.0", id: 1, method: "initialize" }, call);
  assert.equal(init.result.serverInfo.name, "shpbl-counterfactual-immune-forge");
  assert.deepEqual(Object.keys(init.result.capabilities), ["tools"]);
  const ping: any = await handleRpc({ jsonrpc: "2.0", id: 2, method: "ping" }, call);
  assert.deepEqual(ping.result, {});
  const list: any = await handleRpc({ jsonrpc: "2.0", id: 3, method: "tools/list" }, call);
  assert.equal(list.result.tools.length, TOOLS.length);
  for (const tool of list.result.tools) {
    assert.ok(tool.description.length > 40, `${tool.name} needs a real description`);
    assert.equal(tool.inputSchema.type, "object");
  }
});

test("notifications get no response and unknown methods error", async () => {
  const call = createHandler();
  assert.equal(await handleRpc({ jsonrpc: "2.0", method: "notifications/initialized" }, call), undefined);
  const bad: any = await handleRpc({ jsonrpc: "2.0", id: 9, method: "does/not/exist" }, call);
  assert.equal(bad.error.code, -32601);
});

test("adjudication through the tool interface promotes, records lineage and verifies", async () => {
  const lineage = new ImmuneLineage();
  const call = createHandler(lineage);
  const out = parse(await call("adjudicate_defensive_mutation", episode));
  assert.equal(out.evidence.verdict, "PROMOTED");
  assert.equal(out.lineageEntry.index, 0);
  const verified = parse(await call("verify_episode_evidence", { evidence: out.evidence }));
  assert.equal(verified.intact, true);
  const tampered = parse(await call("verify_episode_evidence", { evidence: { ...out.evidence, reason: "edited" } }));
  assert.equal(tampered.intact, false);
  const report = parse(await call("export_immune_lineage_report", {}));
  assert.equal(report.intact, true);
  const reverified = parse(await call("verify_immune_lineage", { entries: report.entries }));
  assert.equal(reverified.intact, true);
  const cleared = parse(await call("reset_state", {}));
  assert.equal(cleared.reset, true);
  assert.equal(parse(await call("export_immune_lineage_report", {})).entries.length, 0);
});

test("duplicate candidate observations are refused as ambiguous evidence", async () => {
  const call = createHandler();
  const duplicated = await call("adjudicate_defensive_mutation", {
    ...episode,
    candidates: [episode.candidates[0], episode.candidates[0]],
  });
  assert.equal(duplicated.isError, true);
  assert.match(duplicated.content[0].text, /duplicates an earlier mutation\/defense pair/);
  const sameId = await call("adjudicate_defensive_mutation", {
    ...episode,
    candidates: [
      episode.candidates[0],
      { ...episode.candidates[0], defense: { id: "guard", version: "1.2.0" } },
    ],
  });
  assert.equal(sameId.isError, true);
  assert.match(sameId.content[0].text, /mutation\.id is not unique/);
});

test("queued requests are answered in arrival order", async () => {
  const written: string[] = [];
  const processor = createLineProcessor(createHandler(), (line) => written.push(line.trim()));
  processor.push(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "adjudicate_defensive_mutation", arguments: episode } }) + "\n");
  processor.push(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }) + "\n{"); // trailing partial line
  processor.push(JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" }).slice(1) + "\n");
  await processor.drain();
  assert.deepEqual(written.map((line) => JSON.parse(line).id), [1, 2, 3]);
  const first = JSON.parse(written[0]);
  assert.equal(JSON.parse(first.result.content[0].text).evidence.verdict, "PROMOTED");
});

test("an oversized frame is refused without desynchronising the reader", async () => {
  const written: string[] = [];
  const processor = createLineProcessor(createHandler(), (line) => written.push(line.trim()));
  processor.push("x".repeat(POLICY.maxRequestBytes + 1));
  processor.push(JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }) + "\n");
  await processor.drain();
  assert.equal(JSON.parse(written[0]).error.code, -32600);
  assert.equal(JSON.parse(written[1]).id, 7);
});

test("describe_policy publishes limits and the no-side-effect declaration", async () => {
  const policy = parse(await createHandler()("describe_policy", {}));
  assert.equal(policy.protocol, POLICY.protocol);
  assert.equal(policy.hash, "sha256");
  assert.ok(policy.sideEffects.startsWith("none"));
  assert.equal(policy.defaultRequireAttackNeutralized, true);
  assert.ok(policy.rejectionReasons.includes("ATTACK_NOT_NEUTRALIZED"));
  assert.equal(policy.tools.length, TOOLS.length);
});

test("malformed input is rejected with a shaped message, never a crash", async () => {
  const call = createHandler();
  const cases: [string, unknown][] = [
    ["missing scenario", { baseline: { id: "a", version: "1" }, baselineReplay: episode.baselineReplay }],
    ["bad replay type", { ...episode, baselineReplay: { reproduced: "yes", attackSucceeded: false, securityScore: 1 } }],
    ["non-finite score", { ...episode, baselineReplay: { reproduced: true, attackSucceeded: true, securityScore: Number.POSITIVE_INFINITY } }],
    ["candidate without impact", { ...episode, candidates: [{ mutation: { description: "d", patch: {} }, defense: { id: "x", version: "2" } }] }],
    ["too many candidates", { ...episode, candidates: new Array(POLICY.maxCandidatesPerEpisode + 1).fill(episode.candidates[0]) }],
  ];
  for (const [label, args] of cases) {
    const result = await call("adjudicate_defensive_mutation", args);
    assert.equal(result.isError, true, label);
    assert.match(result.content[0].text, /^Rejected: /, label);
  }
  const unknown = await call("no_such_tool", {});
  assert.equal(unknown.isError, true);
  const wrongProtocol = await call("verify_episode_evidence", { evidence: { protocol: "OTHER/1", evidenceRoot: "x" } });
  assert.equal(wrongProtocol.isError, true);
});

test("deeply nested or cyclic payloads are refused", async () => {
  const call = createHandler();
  let deep: any = "leaf";
  for (let i = 0; i < 40; i += 1) deep = { deep };
  const nested = await call("adjudicate_defensive_mutation", { ...episode, scenario: { ...episode.scenario, payload: deep } });
  assert.equal(nested.isError, true);
  const cyclic: any = { a: 1 };
  cyclic.self = cyclic;
  const looped = await call("adjudicate_defensive_mutation", { ...episode, scenario: { ...episode.scenario, payload: cyclic } });
  assert.equal(looped.isError, true);
});

test("resources/list and prompts/list answer empty instead of erroring", async () => {
  const call = createHandler();
  const resources: any = await handleRpc({ jsonrpc: "2.0", id: 11, method: "resources/list" }, call);
  assert.deepEqual(resources.result, { resources: [] });
  const prompts: any = await handleRpc({ jsonrpc: "2.0", id: 12, method: "prompts/list" }, call);
  assert.deepEqual(prompts.result, { prompts: [] });
});

test("lineage entries with an unknown verdict are rejected, not counted", async () => {
  const call = createHandler();
  const report = parse(await call("export_immune_lineage_report", {}));
  const forged = await call("verify_immune_lineage", {
    entries: [
      {
        index: 0,
        scenarioId: "s",
        verdict: "APPROVED_BY_ME",
        reason: "r",
        episodeRoot: "e",
        previousEntryHash: report.headHash,
        entryHash: "h",
      },
    ],
  });
  assert.equal(forged.isError, true);
  assert.match(forged.content[0].text, /verdict must be one of/);
});

test("candidates that share a defense version are judged on their own replay", async () => {
  const call = createHandler();
  const out = parse(
    await call("adjudicate_defensive_mutation", {
      ...episode,
      candidates: [
        {
          mutation: { id: "cand-weak", description: "log only", patch: { rule: "log" } },
          defense: { id: "guard", version: "1.1.0" },
          impact: { safe: true, reasons: [] },
          replay: { reproduced: true, attackSucceeded: true, securityScore: 0.2 },
          regression: { passed: true, failures: [] },
          fitnessScore: 0.2,
        },
        episode.candidates[0],
      ],
    }),
  );
  const weak = out.evidence.candidates.find((c: any) => c.candidateId === "cand-weak");
  assert.equal(weak.replay.attackSucceeded, true);
  assert.equal(weak.rejectedReason, "ATTACK_NOT_NEUTRALIZED");
  assert.equal(out.evidence.winnerId, "cand-a");
});
