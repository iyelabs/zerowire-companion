import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, readdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import worker from "../src/index.ts";
import { handlePublicRequest } from "../src/public/handler.ts";
import { consumeBoundedBody, PUBLIC_LIMITS } from "../src/public/limits.ts";
import { handleScheduledIngestion } from "../src/ingestion/scheduled.ts";

function binding(success = true) {
  const keys = [];
  return { keys, PUBLIC_RATE_LIMITER: { async limit({ key }) { keys.push(key); return { success }; } } };
}
function request(path = "/mcp", options = {}) {
  return new Request(`https://deployment.example${path}`, {
    method: "POST",
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    ...options,
    headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.24", accept:"application/json, text/event-stream", ...options.headers },
  });
}

test("public entrypoint cannot write, access ingestion settings, fetch upstream or waitUntil", async t => {
  let egress = 0;
  t.mock.method(globalThis, "fetch", async () => { egress++; throw new Error("forbidden egress"); });
  const limiter = binding();
  const env = new Proxy({}, { get(_target, key) {
    if (key === "PUBLIC_RATE_LIMITER") return limiter.PUBLIC_RATE_LIMITER;
    if (key === "DB") return {prepare(sql) { assert.match(sql, /^SELECT /); throw new Error("unexpected query"); }};
    throw new Error(`public path accessed forbidden capability ${String(key)}`);
  } });
  const context = new Proxy({}, { get() { throw new Error("public path attempted background work"); } });
  for (const input of [request(), new Request("https://deployment.example/health"), request("/sync"), request("/admin/sync")]) {
    const response = await worker.fetch(input, env, context);
    assert.ok([200, 404, 503].includes(response.status));
  }
  assert.equal(egress, 0);
  assert.match(limiter.keys[0], /^mcp:[a-f0-9]{64}$/);
  assert.ok(!limiter.keys[0].includes("192.0.2.24"));
});

test("MCP lists read-only tools through the protocol", async () => {
  const result = await handlePublicRequest(request(), { ...binding(), queries: {} });
  assert.equal(result.status, 200);
  const payload = await result.json();
  assert.ok(payload.result.tools.some(tool => tool.name === "match_briefings"));
  assert.ok(payload.result.tools.every(tool => tool.annotations.readOnlyHint));
});

test("rate-limit denial and missing/broken limiter fail closed without exposing errors", async () => {
  const denied = await handlePublicRequest(request(), binding(false));
  assert.equal(denied.status, 429);
  assert.equal(denied.headers.get("retry-after"), "60");
  const broken = await handlePublicRequest(request(), { PUBLIC_RATE_LIMITER: { async limit() { throw new Error("secret-value"); } } });
  assert.equal(broken.status, 503);
  assert.ok(!(await broken.text()).includes("secret-value"));
  assert.equal((await handlePublicRequest(request(), {})).status, 503);
});

test("health and unknown paths also obey rate-limit denial and fail closed", async t => {
  const logs=[];t.mock.method(console,"log",value=>logs.push(JSON.parse(value)));
  for (const input of [new Request("https://deployment.example/health"),new Request("https://deployment.example/unknown"),request("/"+"x".repeat(2050))]) {
    const response=await handlePublicRequest(input,{...binding(false),queries:{}});
    assert.equal(response.status,429);assert.equal(response.headers.get("retry-after"),"60");
  }
  assert.equal((await handlePublicRequest(new Request("https://deployment.example/health"),{queries:{}})).status,503);
  assert.deepEqual(logs.map(x=>x.route),["health","unknown","unknown","health"]);
});

test("cross-origin, unsupported encodings, methods and content types are rejected", async () => {
  assert.equal((await handlePublicRequest(request("/mcp", { headers: { origin: "https://untrusted.example" } }), binding())).status, 403);
  assert.equal((await handlePublicRequest(request("/mcp", { headers: { "content-encoding": "gzip" } }), binding())).status, 415);
  assert.equal((await handlePublicRequest(new Request("https://deployment.example/mcp"), binding())).status, 405);
  assert.equal((await handlePublicRequest(request("/mcp", { headers: { "content-type": "text/plain" } }), binding())).status, 415);
  assert.equal((await handlePublicRequest(request("/" + "x".repeat(2050)), binding())).status, 414);
});

test("streamed body is byte-bounded with absent or false Content-Length", async () => {
  for (const headers of [{}, { "content-length": "1" }, { "content-length": "17000" }]) {
    const response = await handlePublicRequest(request("/mcp", { body: "x".repeat(PUBLIC_LIMITS.requestBytes + 1), headers }), binding());
    assert.equal(response.status, 413);
  }
  assert.equal((await handlePublicRequest(request("/mcp", { headers: { "content-length": "-1" } }), binding())).status, 400);
  await consumeBoundedBody(new Request("https://deployment.example", { method: "POST", body: "é".repeat(8) }), 16);
  await assert.rejects(() => consumeBoundedBody(new Request("https://deployment.example", { method: "POST", body: "é".repeat(9) }), 16), error => error.status === 413);
});

test("a stalled body has a deadline and is cancelled", async () => {
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  await assert.rejects(() => consumeBoundedBody(new Request("https://deployment.example", { method: "POST", body, duplex: "half" }), 16, 20), error => error.status === 408);
  assert.equal(cancelled, true);
});

test("operational logs exclude watchlists, request URLs, IPs and exception contents", async t => {
  const logs = [];
  t.mock.method(console, "log", value => logs.push(value));
  await handlePublicRequest(request("/mcp?token=private-query", { body: '{"technology":"PrivateStack"}' }), binding());
  const output = logs.join("\n");
  for (const sensitive of ["PrivateStack", "private-query", "192.0.2.24", "deployment.example"]) assert.ok(!output.includes(sensitive));
  const parsed = JSON.parse(logs[0]);
  assert.equal(parsed.event, "public_request");
  assert.equal(parsed.route, "mcp");
  assert.equal(typeof parsed.duration_ms, "number");
});

test("disabled scheduled ingestion performs no source request", async t => {
  const logs = [];
  t.mock.method(console, "log", value => logs.push(JSON.parse(value)));
  t.mock.method(globalThis, "fetch", async () => { throw new Error("unexpected fetch"); });
  await handleScheduledIngestion({ INGESTION_ENABLED: "false", DB: {} });
  assert.equal(logs[0].event, "scheduled_disabled");
});

test("public module dependency graph has no ingestion, source or write capability", async () => {
  const root = fileURLToPath(new URL("../", import.meta.url));
  const visited = new Set();
  async function visit(path) {
    if (visited.has(path)) return;
    visited.add(path);
    const source = await readFile(path, "utf8");
    assert.ok(!/\b(?:fetch|batch|exec)\s*\(/.test(source), `${path} introduces network/write capability`);
    if (path.endsWith("queries.ts")) for (const query of source.matchAll(/db\.prepare\("([^"]+)"\)/g)) assert.match(query[1], /^SELECT /);
    for (const match of source.matchAll(/^import\s+(?!type\b).*?from\s+["']([^"']+)["']/gm)) {
      const dependency = match[1];
      if (!dependency.startsWith(".")) { assert.ok(dependency.startsWith("@modelcontextprotocol/sdk/") || dependency === "zod"); continue; }
      const target = resolve(dirname(path), dependency);
      assert.ok(!/\/(ingestion|sources|migrations)\//.test(target));
      await visit(target);
    }
  }
  for (const entry of await readdir(resolve(root, "src/public"))) if (entry.endsWith(".ts")) await visit(resolve(root, "src/public", entry));
});
