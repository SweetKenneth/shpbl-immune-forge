import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const srcDir = new URL("../../src/", import.meta.url).pathname;
const sources = readdirSync(srcDir).filter((f) => f.endsWith(".ts"));

test("the implementation performs no filesystem, network, process or environment access", () => {
  const forbidden = [
    "node:fs", "node:net", "node:http", "node:https", "node:dns", "node:child_process", "node:os",
    "child_process", "process.env", "fetch(", "XMLHttpRequest", "WebSocket", "eval(", "new Function",
  ];
  for (const file of sources) {
    const text = readFileSync(join(srcDir, file), "utf8");
    for (const token of forbidden) {
      assert.equal(text.includes(token), false, `${file} must not reference ${token}`);
    }
  }
});

test("only node:crypto is imported from the platform and no dependency is declared", () => {
  const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url).pathname, "utf8"));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.license, "MIT");
  const imports = new Set<string>();
  for (const file of sources) {
    const text = readFileSync(join(srcDir, file), "utf8");
    for (const match of text.matchAll(/from "(node:[^"]+)"/g)) imports.add(match[1]);
  }
  assert.deepEqual([...imports], ["node:crypto"]);
});

test("documentation states the honest limits and claims no Tenable endorsement", () => {
  const readme = readFileSync(new URL("../../README.md", import.meta.url).pathname, "utf8").replace(/\s+/g, " ");
  for (const phrase of [
    "does not imply review, approval, certification, validation, endorsement, or acceptance by Tenable",
    "not an autonomous security oracle",
    "A compromised evaluator",
  ]) {
    assert.ok(readme.includes(phrase), `README must state: ${phrase}`);
  }
});
