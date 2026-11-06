import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateKevCatalog } from '../src/intelligence/kev.ts';
const row=(cveID)=>({cveID,vendorProject:'Vendor',product:'Product',dateAdded:'2026-10-31',shortDescription:'Source text',knownRansomwareCampaignUse:'Unknown'});
const catalog=(vulnerabilities)=>({catalogVersion:'2026.11.05',dateReleased:'2026-11-05T00:00:00Z',count:vulnerabilities.length,vulnerabilities});
test('validates and deterministically orders source records without discarding source fields',()=>{
 const input=catalog([row('cve-2021-44228'),row('CVE-2020-12345')]);
 const result=validateKevCatalog(input);
 assert.deepEqual(result.records.map(x=>x.cveID),['CVE-2020-12345','CVE-2021-44228']);
 assert.equal(result.records[1].knownRansomwareCampaignUse,'Unknown');
 assert.equal(input.vulnerabilities[0].cveID,'cve-2021-44228');
});
test('rejects invalid counts, duplicate identifiers and invalid required fields',()=>{
 assert.throws(()=>validateKevCatalog({...catalog([]),count:1}),/invalid_kev_catalog/);
 assert.throws(()=>validateKevCatalog(catalog([])),/invalid_kev_catalog/);
 assert.throws(()=>validateKevCatalog(catalog([row('CVE-2021-44228'),row('cve-2021-44228')])),/duplicate_kev_record/);
 assert.throws(()=>validateKevCatalog(catalog([{...row('CVE-2021-44228'),dateAdded:'2026-02-30'}])),/invalid_kev_record/);
 assert.throws(()=>validateKevCatalog(catalog([{...row('CVE-2021-44228'),product:''}])),/invalid_kev_record/);
});
test('canonical record JSON is independent of key order and retains substantive values',async()=>{
 const {canonicalKevJson}=await import('../src/intelligence/kev.ts');
 assert.equal(canonicalKevJson({b:1,a:{y:2,x:3}}),canonicalKevJson({a:{x:3,y:2},b:1}));
 assert.notEqual(canonicalKevJson({b:1}),canonicalKevJson({b:2}));
});
