import {test} from 'node:test';import assert from 'node:assert/strict';import {normalizeGhsa,normalizeOsv,normalizeOsvCve,normalizeOsvRustsec} from '../src/intelligence/package-advisories.ts';
const cve='CVE-2021-44228',id='GHSA-jfh8-c2jp-5v3q';
test('normalizes linked GHSA and OSV package evidence while preserving independent sources',()=>{const ghsa=normalizeGhsa([{ghsa_id:id,cve_id:cve,vulnerabilities:[{package:{ecosystem:'maven',name:'log4j-core'},vulnerable_version_range:'< 2.15',first_patched_version:'2.15'}]}],cve)[0];const osv=normalizeOsv({id,aliases:[cve],affected:[{package:{ecosystem:'Maven',name:'log4j-core'},database_specific:{source:`https://github.com/github/advisory-database/blob/main/advisories/${id}/${id}.json`},ranges:[{type:'ECOSYSTEM',events:[{introduced:'0'},{fixed:'2.15'}]}]}]},cve,id);assert.equal(ghsa.source,'ghsa');assert.equal(osv.source,'osv');assert.equal(ghsa.packages[0].first_patched_version,'2.15');assert.equal(osv.packages[0].ranges[0].events[1].fixed,'2.15');});
test('rejects unrelated and malformed aliases rather than merging vulnerabilities',()=>{assert.throws(()=>normalizeGhsa([{ghsa_id:id,cve_id:'CVE-2099-1234',vulnerabilities:[]}],cve));assert.throws(()=>normalizeOsv({id,aliases:['CVE-2099-1234'],affected:[]},cve,id));assert.throws(()=>normalizeOsv({id:'bad',aliases:[cve],affected:[]},cve,'bad'));});

test('rejects OSV records without an allowed attributable source',()=>{assert.throws(()=>normalizeOsv({id,aliases:[cve],affected:[{package:{name:'x'}}]},cve,id),/rights_unverified/)});
test('native OSV CVE accepts only exact verified conversion provenance and preserves valid aliases',()=>{
 const source=`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`;
 const value={id:cve,aliases:[id,'CVE-2099-1234','../../arbitrary'],affected:[{database_specific:{source},ranges:[]}]};
 const out=normalizeOsvCve(value,cve);assert.deepEqual(out.aliases,[id]);assert.equal(out.upstream_source,source);
 assert.throws(()=>normalizeOsvCve({...value,id:'CVE-2099-1234'},cve),/invalid_osv_cve/);
 assert.throws(()=>normalizeOsvCve({...value,affected:[{database_specific:{source:'https://attacker.invalid/source'}}]},cve),/rights_unverified/);
 assert.throws(()=>normalizeOsvCve({...value,withdrawn:'2026-11-01T00:00:00Z'},cve),/withdrawn/);
});
test('withdrawn GHSA and OSV advisories remain attributed without active package claims',()=>{
 const at='2026-11-05T00:00:00Z',source=`https://github.com/github/advisory-database/blob/main/advisories/${id}/${id}.json`;
 const ghsa=normalizeGhsa([{ghsa_id:id,cve_id:cve,withdrawn_at:at,vulnerabilities:[{package:{ecosystem:'npm',name:'example'},vulnerable_version_range:'< 2.0'}]}],cve)[0];assert.equal(ghsa.withdrawn_at,at);assert.deepEqual(ghsa.packages,[]);
 const osv=normalizeOsv({id,aliases:[cve],withdrawn:at,affected:[{database_specific:{source},package:{name:'example'},ranges:[]}]},cve,id);assert.equal(osv.withdrawn_at,at);assert.deepEqual(osv.packages,[]);assert.equal(osv.upstream_source,source);
 assert.throws(()=>normalizeGhsa([{ghsa_id:id,cve_id:cve,withdrawn_at:'bad',vulnerabilities:[]}],cve),/withdrawal/);assert.throws(()=>normalizeOsv({id,aliases:[cve],withdrawn:'bad',affected:[]},cve,id),/withdrawal/);
});
test('RustSec OSV alias requires the tracked CVE and verified upstream source',()=>{
 const id='RUSTSEC-2022-0103',cve='CVE-2021-20319',source=`https://github.com/rustsec/advisory-db/blob/osv/crates/${id}.json`;
 const value={id,aliases:[cve,'GHSA-3r3g-g73x-g593'],affected:[{package:{ecosystem:'crates.io',name:'coreos-installer'},database_specific:{source},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'0.10.0'}]}]}]};
 const out=normalizeOsvRustsec(value,cve,id);assert.equal(out.upstream_source,source);assert.equal(out.packages[0].name,'coreos-installer');assert.ok(out.aliases.includes(cve));
 assert.throws(()=>normalizeOsvRustsec({...value,aliases:['CVE-2099-11111']},cve,id),/invalid_rustsec/);assert.throws(()=>normalizeOsvRustsec({...value,id:'RUSTSEC-2022-'+('1'.repeat(200))},cve,'RUSTSEC-2022-'+('1'.repeat(200))),/invalid_rustsec/);assert.throws(()=>normalizeOsvRustsec({...value,affected:[{database_specific:{source:'https://attacker.invalid/x'}}]},cve,id),/rights_unverified/);
 const withdrawn=normalizeOsvRustsec({...value,withdrawn:'2026-11-05T00:00:00Z',affected:[]},cve,id);assert.deepEqual(withdrawn.packages,[]);
});
