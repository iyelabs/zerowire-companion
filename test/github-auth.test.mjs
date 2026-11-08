import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readJsonSource} from '../src/ingestion/enrichment.ts';

test('GitHub credential is sent only to exact advisory endpoint and redirects remain disabled',async()=>{
 const original=globalThis.fetch; const seen=[];
 globalThis.fetch=async(url,init)=>{seen.push({url,init});return new Response('{}',{status:200,headers:{'content-type':'application/json'}})};
 try{
  for(const url of ['https://api.github.com/advisories?per_page=10','https://api.osv.dev/v1/vulns/example','https://api.github.com/user','https://api.github.com.evil.invalid/advisories','https://api.github.com:444/advisories']) await readJsonSource(url,'fixture-token');
  assert.equal(seen[0].init.headers.authorization,'Bearer fixture-token');
  for(const item of seen.slice(1))assert.equal(item.init.headers.authorization,undefined);
  assert.ok(seen.every(x=>x.init.redirect==='manual'));
  await readJsonSource('https://api.github.com/advisories?per_page=10');assert.equal(seen.at(-1).init.headers.authorization,undefined);
 }finally{globalThis.fetch=original}
});
