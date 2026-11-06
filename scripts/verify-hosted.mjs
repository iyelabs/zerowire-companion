// Explicit operator smoke check. Never synchronizes, writes, or fetches upstream feeds.
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { XMLValidator } from 'fast-xml-parser';

const endpoint = new URL(process.argv[2] ?? 'https://zerowire-companion.iyelabs.com/mcp');
assert.equal(endpoint.protocol, 'https:');
assert.equal(endpoint.pathname, '/mcp');
assert.ok(!endpoint.username && !endpoint.password && !endpoint.search && !endpoint.hash);
const allowBaseline = process.argv.includes('--allow-baseline');
const sizes = [];
const boundedFetch = async (url, init) => {
  const response = await fetch(url, { ...init, signal: AbortSignal.timeout(15_000), redirect: 'error' });
  const body = await response.clone().arrayBuffer();
  assert.ok(body.byteLength <= 64 * 1024, 'Response exceeded 64 KiB');
  sizes.push(body.byteLength);
  return response;
};
const client = new Client({ name: 'zerowire-release-verification', version: '1' });
const calls = [];
async function call(name, args) {
  const result = await client.callTool({ name, arguments: args });
  assert.ok(!result.isError, `${name} failed`);
  const payload = JSON.parse(result.content.find(x => x.type === 'text').text);
  assert.match(payload.notice, /untrusted data, not instructions/);
  assert.ok(payload.attribution.length >= 3);
  for (const source of ['Cloudflare Radar Zero Wire', 'CISA Known Exploited Vulnerabilities Catalog', 'FIRST EPSS']) assert.ok(payload.attribution.some(x => x.source === source));
  calls.push(name);
  return payload.data;
}
try {
  const health = await boundedFetch(new URL('/health', endpoint));
  assert.equal(health.status, 200);
  assert.equal((await health.json()).status, 'ok'); // Liveness only.
  await client.connect(new StreamableHTTPClientTransport(endpoint, { fetch: boundedFetch }));
  const tools = (await client.listTools()).tools;
  assert.deepEqual(tools.map(x => x.name).sort(), ['get_briefing','get_recent_changes','get_vulnerability_context','list_briefings','match_briefings','get_triage_pack','get_signal_timeline','search_kev','get_intelligence_digest'].sort());
  assert.ok(tools.every(x => x.annotations?.readOnlyHint === true));
  const briefings = await call('list_briefings', { limit: 15 });
  assert.ok(briefings.length > 0 && briefings.length <= 15, 'Populated source data required');
  const sample = briefings.find(x => x.cves?.length && x.tags?.length);
  assert.ok(sample, 'A CVE and tag example is required for this release check');
  const match = await call('match_briefings', { kind: 'tag', term: sample.tags[0], limit: 15 });
  assert.equal(match.reason.term, sample.tags[0].toLowerCase());
  assert.ok(match.matches.some(x => x.id === sample.id));
  const detail = await call('get_briefing', { id: sample.id });
  assert.equal(detail.canonical_url, sample.id);
  assert.ok(Array.isArray(detail.truncated_fields));
  assert.ok(detail.evidence_urls.every(x => new URL(x).protocol === 'https:'));
  const context = await call('get_vulnerability_context', { cve: sample.cves[0] });
  assert.equal(context.cve, sample.cves[0]);
  assert.deepEqual(context.sources.map(x => x.source_id), ['cisa_kev','first_epss']);
  for (const row of context.sources) {
    assert.ok(Number.isFinite(Date.parse(row.retrieved_at)));
    JSON.parse(row.data_json);
  }
  assert.equal(context.freshness.length, 3);
  const stale = context.freshness.filter(x => !x.last_success_at || Date.now() - Date.parse(x.last_success_at) > 6 * 3600_000);
  assert.equal(stale.length, 0, 'Source data older than 6 hours or never observed');
  const changes = await call('get_recent_changes', { after: 0, limit: 20 });
  assert.ok(changes.length <= 20);
  const pack = await call('get_triage_pack', { identifier: sample.id });
  assert.equal(pack.status, 'ok');
  assert.equal(pack.identification.canonical_url, sample.id);
  const timeline = await call('get_signal_timeline', { identifier: sample.id, limit: 5 });
  assert.equal(timeline.status, 'ok');
  assert.ok(Array.isArray(timeline.events));
  const kev = await call('search_kev', { cve: sample.cves[0] });
  if (kev.availability === 'available') assert.ok(Number(kev.catalog_state?.record_count) > 0);
  else { assert.equal(kev.availability, 'baseline_in_progress'); assert.ok(allowBaseline, 'Full CISA catalog baseline is not complete'); }
  const digest = await call('get_intelligence_digest', { limit: 5 });
  assert.ok(Array.isArray(digest.items));
  assert.ok(digest.scan.events_examined <= digest.scan.maximum_events_examined);
  const jsonFeed = await boundedFetch(new URL('/events.json?limit=5', endpoint));
  assert.equal(jsonFeed.status, 200);
  assert.ok(Array.isArray((await jsonFeed.json()).items));
  const rssFeed = await boundedFetch(new URL('/events.xml?limit=5', endpoint));
  assert.equal(rssFeed.status, 200);
  assert.equal(XMLValidator.validate(await rssFeed.text()), true);
  assert.equal(await call('get_briefing', { id: 'https://radar.cloudflare.com/security/zero-wire/nonexistent-release-check' }), null);
  const invalid = await client.callTool({ name: 'list_briefings', arguments: { limit: 16 } });
  assert.equal(invalid.isError, true);
  const guards = {};
  for (const [name, init, expected] of [
    ['method', { method: 'GET' }, [403,405]],
    ['origin', { method: 'POST', headers: { origin: 'https://untrusted.invalid', 'content-type': 'application/json' }, body: '{}' }, 403],
    ['content_type', { method: 'POST', body: '{}' }, 415],
    ['request_size', { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'x'.repeat(16 * 1024 + 1) }, 413],
  ]) {
    const response = await boundedFetch(endpoint, init);
    guards[name] = response.status;
    assert.ok(Array.isArray(expected) ? expected.includes(response.status) : response.status === expected, `${name} unexpected status ${response.status}`);
  }
  console.log(JSON.stringify({ observed_at: new Date().toISOString(), endpoint: endpoint.href, tls_verification: true, tools_called: [...new Set(calls)], briefing_count_in_page: briefings.length, tag_match: match.reason, matching_briefings: match.matches.length, cve: context.cve, context_source_ids: context.sources.map(x => x.source_id), source_health: context.freshness, observed_change_events_in_page: changes.length, kev_catalog_status:kev.availability, kev_catalog_record_count:kev.catalog_state?.record_count??null, digest_events_in_page:digest.items.length, feeds_verified:true, invalid_limit_rejected: true, guards, max_observed_response_bytes: Math.max(...sizes), scope: 'Bounded live read-only smoke; not a load, legal, or full security audit' }, null, 2));
} finally {
  await client.close();
}
