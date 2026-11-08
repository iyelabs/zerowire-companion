import {test} from 'node:test';
import assert from 'node:assert/strict';
import {checkGhsa,checkOsv} from '../scripts/source-health-check.mjs';
const now=Date.parse('2026-11-08T15:00:00Z');
test('smoke rejects suspended, failing or stale GHSA even with old successful data',()=>{
 const ok={last_success_at:'2026-11-08T14:00:00Z',last_error_code:null,retry_suspended:0};
 checkGhsa(ok,now);
 for(const row of [{...ok,last_error_code:'source_http_403'},{...ok,retry_suspended:1},{...ok,last_success_at:'2026-11-01T00:00:00Z'},null])assert.throws(()=>checkGhsa(row,now));
});
test('smoke checks OSV sample honestly including missing and failed states',()=>{
 const state={source:'osv_native_cve',last_success_at:'2026-11-08T14:00:00Z',last_error_code:'record_not_found'};
 checkOsv({affected_software:{source_state:[state]}},'CVE-2021-44228',now);
 checkOsv({exploitation_intelligence:{cves:[{cve:'CVE-2021-44228',affected_software:{source_state:[state]}}]}},'CVE-2021-44228',now);
 assert.throws(()=>checkOsv({affected_software:{source_state:[{...state,last_error_code:'source_http_429'}]}},'CVE-2021-44228',now));
 assert.throws(()=>checkOsv({},'CVE-2021-44228',now));
 assert.throws(()=>checkOsv({affected_software:{source_state:[{...state,last_success_at:null}]}},'CVE-2021-44228',now));
});
