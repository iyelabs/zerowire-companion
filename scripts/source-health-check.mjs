import assert from 'node:assert/strict';

// Health of sampled records only: absence of sampled errors is not proof of complete coverage.
export function checkGhsa(feed, now=Date.now()) {
  assert.ok(feed?.last_success_at, 'GHSA discovery has no successful observation');
  assert.ok(Object.hasOwn(feed, 'retry_suspended'), 'GHSA retry policy health is not exposed');
  assert.ok(!feed.last_error_code, `GHSA discovery error: ${feed.last_error_code}`);
  assert.notEqual(feed.retry_suspended, 1, `GHSA retry suspended: ${feed.retry_reason}`);
  assert.ok(now - Date.parse(feed.last_success_at) <= 12 * 3600_000 && Number.isFinite(Date.parse(feed.last_success_at)), 'GHSA discovery is stale');
}
export function checkOsv(pack, cve, now=Date.now()) {
  const states = [pack.affected_software?.source_state, ...(pack.exploitation_intelligence?.cves ?? []).filter(x => x.cve === cve).map(x => x.affected_software?.source_state), pack.package_source_state].flatMap(x => x ?? []).filter(x => String(x.source).startsWith('osv'));
  assert.ok(states.length, `OSV status not available for sampled ${cve}`);
  for (const row of states) {
    assert.ok(!row.last_error_code || ['record_not_found','record_withdrawn','record_no_affected_data'].includes(row.last_error_code), `OSV ${cve}/${row.source} error: ${row.last_error_code}`);
    assert.ok(row.last_success_at && Number.isFinite(Date.parse(row.last_success_at)) && now - Date.parse(row.last_success_at) <= 48 * 3600_000, `OSV ${cve}/${row.source} stale or not checked`);
  }
  return states;
}
