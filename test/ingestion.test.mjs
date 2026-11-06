import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { handleScheduledIngestion } from "../src/ingestion/scheduled.ts";
function database() {
 const sql = new DatabaseSync(":memory:"); sql.exec("PRAGMA foreign_keys=ON"); sql.exec(readFileSync(new URL("../migrations/0001_intelligence_foundation.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0002_enrichment.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0003_enrichment_progress.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0004_ingestion_lease.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0005_signal_history.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0006_timeline_indexes.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0007_kev_catalog.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0008_epss_series.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0009_package_intelligence.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0010_osv_cve_state.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0011_epss_series_attempts.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0012_cross_source_timeline_indexes.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0013_osv_alias_queue.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0014_osv_alias_scan.sql",import.meta.url),"utf8")); sql.exec(readFileSync(new URL("../migrations/0015_ghsa_retry_policy.sql",import.meta.url),"utf8"));
 const adapter = { prepare(query) { let params=[]; return { bind(...v) { params=v; return this; }, async first() { return sql.prepare(query).get(...params) ?? null; }, async all() { return {results:sql.prepare(query).all(...params)}; }, async run() { return sql.prepare(query).run(...params); } }; }, async batch(statements) { sql.exec("BEGIN"); try { for (const stmt of statements) await stmt.run(); sql.exec("COMMIT"); } catch(e) { sql.exec("ROLLBACK"); throw e; } } };
 return {sql, adapter};
}
const item=(slug,title,cve="")=>`<item><title>${title}</title><link>https://radar.cloudflare.com/security/zero-wire/${slug}</link>${cve ? `<category>${cve}</category>` : ""}</item>`;
const feed=(...items)=>`<rss><channel>${items.join("")}</channel></rss>`;
test("baseline, subsequent changes, idempotence, reversion and outage preserve state",async t=>{
 const {sql,adapter}=database(); t.after(()=>sql.close()); let body=feed(item("a","Original","CVE-2099-10001"));
 t.mock.method(globalThis,"fetch",async()=>new Response(body,{status:200}));
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:"true",DB:adapter});
 await run(); assert.equal(sql.prepare("SELECT count(*) n FROM change_events").get().n,0);
 body=feed(item("a","Changed","CVE-2099-10002"),item("b","New")); await run();
 assert.equal(sql.prepare("SELECT count(*) n FROM change_events").get().n,2);
 const diff=JSON.parse(sql.prepare("SELECT diff_json FROM change_events WHERE event_kind='changed'").get().diff_json); assert.deepEqual(diff.set_changes.cves,{added:["CVE-2099-10002"],removed:["CVE-2099-10001"]});
 assert.equal(sql.prepare("SELECT cve_id FROM briefing_cves").get().cve_id,"CVE-2099-10002");
 await run(); assert.equal(sql.prepare("SELECT count(*) n FROM change_events").get().n,2);
 body=feed(item("a","Original","CVE-2099-10001")); await run();
 assert.equal(sql.prepare("SELECT count(*) n FROM change_events").get().n,3);
 assert.equal(sql.prepare("SELECT count(*) n FROM briefing_snapshots WHERE briefing_id LIKE '%/a'").get().n,3);
 assert.equal(sql.prepare("SELECT count(*) n FROM briefings").get().n,2);
 body="invalid"; await assert.rejects(run); assert.equal(sql.prepare("SELECT count(*) n FROM change_events").get().n,3);
 assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='zero_wire'").get().last_error_code,"ingestion_failed");
});

test("KEV and EPSS preserve source meaning and old context during outage",async t=>{
 const {sql,adapter}=database(); t.after(()=>sql.close()); let fail=false;
 const advisory=feed(item("a","Briefing","CVE-2099-10001"));
 t.mock.method(globalThis,"fetch",async url=>{
  if(String(url).includes("zero-wire")) return new Response(advisory);
  if(fail) return new Response("unavailable",{status:503});
  if(String(url).includes("cisa.gov")) return Response.json({catalogVersion:"1",dateReleased:"2099-01-01",count:1,vulnerabilities:[{cveID:"CVE-2099-19000",vendorProject:"Other",product:"Other",dateAdded:"2099-01-01"}]});
  return Response.json({status:"OK",total:1,data:[{cve:"CVE-2099-10001",epss:"0.12000",percentile:"0.80000",date:"2099-01-01"}]});
 });
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:"true",DB:adapter}); await run();
 const context=sql.prepare("SELECT source_id,data_json FROM vulnerability_context ORDER BY source_id").all();
 assert.equal(JSON.parse(context[0].data_json).listed,false); assert.equal(JSON.parse(context[1].data_json).record.epss,"0.12000");
 fail=true; await run(); assert.deepEqual(sql.prepare("SELECT source_id,data_json FROM vulnerability_context ORDER BY source_id").all(),context);
 assert.equal(sql.prepare("SELECT count(*) n FROM source_state WHERE last_error_code='enrichment_failed'").get().n,2);
});

test("enrichment rotates beyond 500 and failed sources do not advance",async t=>{
 const {sql,adapter}=database(); t.after(()=>sql.close()); let epssFail=true;
 sql.prepare("INSERT INTO briefings VALUES (?,?,?,?)").run("id","https://radar.cloudflare.com/security/zero-wire/example","t","t");
 const insert=sql.prepare("INSERT INTO briefing_cves VALUES (?,?)"); for(let n=10000;n<10501;n++)insert.run("id",`CVE-2099-${n}`);
 t.mock.method(globalThis,"fetch",async url=>{
  if(String(url).includes("cisa.gov")) return Response.json({catalogVersion:"1",dateReleased:"2099-01-01",count:1,vulnerabilities:[{cveID:"CVE-2099-19000",vendorProject:"Other",product:"Other",dateAdded:"2099-01-01"}]});
  if(epssFail) return new Response("unavailable",{status:503});
  return Response.json({status:"OK",total:0,data:[]});
 });
 sql.prepare("INSERT INTO ingestion_lease VALUES (?,?,?)").run("scheduled","test-owner","9999-01-01T00:00:00.000Z");
 const {enrich}=await import("../src/ingestion/enrichment.ts"); await enrich(adapter,"test-owner");
 assert.equal(sql.prepare("SELECT COUNT(*) n FROM vulnerability_context WHERE source_id='cisa_kev'").get().n,500);
 assert.equal(sql.prepare("SELECT COUNT(*) n FROM enrichment_progress WHERE source_id='first_epss'").get().n,0);
 epssFail=false; await enrich(adapter,"test-owner");
 assert.equal(sql.prepare("SELECT COUNT(*) n FROM vulnerability_context WHERE source_id='cisa_kev'").get().n,501);
 assert.equal(sql.prepare("SELECT COUNT(*) n FROM vulnerability_context WHERE source_id='first_epss'").get().n,500);
 await enrich(adapter,"test-owner"); assert.equal(sql.prepare("SELECT COUNT(*) n FROM vulnerability_context WHERE source_id='first_epss'").get().n,501);
});

test("concurrent ingestion skips the second run and releases its lease",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let calls=0;let unblock;const gate=new Promise(resolve=>{unblock=resolve});let entered;const ready=new Promise(resolve=>{entered=resolve});
 t.mock.method(globalThis,"fetch",async()=>{calls++;entered();await gate;return new Response(feed(item("locked","Safe")));});
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:"true",DB:adapter});const first=run();await ready;await run();assert.equal(calls,1);unblock();await first;
 assert.equal(sql.prepare("SELECT count(*) n FROM briefings").get().n,1);assert.equal(sql.prepare("SELECT count(*) n FROM ingestion_lease").get().n,0);
});

test("stale ingestion owner is fenced from writing after lease takeover",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let unblock;const gate=new Promise(resolve=>{unblock=resolve});let entered;const ready=new Promise(resolve=>{entered=resolve});
 t.mock.method(globalThis,"fetch",async()=>{entered();await gate;return new Response(feed(item("stale","Should not persist")));});
 const run=handleScheduledIngestion({INGESTION_ENABLED:"true",DB:adapter});await ready;
 sql.prepare("UPDATE ingestion_lease SET owner=?,expires_at=? WHERE name='scheduled'").run("replacement","9999-01-01T00:00:00.000Z");unblock();await assert.rejects(run,/CHECK constraint/);
 assert.equal(sql.prepare("SELECT count(*) n FROM briefings").get().n,0);assert.equal(sql.prepare("SELECT owner FROM ingestion_lease").get().owner,"replacement");
});

test("guidance changes preserve observed prior and current text",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let text="Apply patch A";
 const body=()=>feed(item("guidance","Advisory").replace("</item>",`<content:encoded><![CDATA[<h2>What to do now</h2><p>${text}</p><h2>Evidence and sources</h2><a href="https://vendor.example/a">source</a>]]></content:encoded></item>`));
 t.mock.method(globalThis,"fetch",async()=>new Response(body()));const run=()=>handleScheduledIngestion({INGESTION_ENABLED:"true",DB:adapter});await run();text="Apply patch B";await run();
 const diff=JSON.parse(sql.prepare("SELECT diff_json FROM change_events").get().diff_json);assert.ok(diff.changed_fields.includes("recommended_actions"));assert.equal(diff.guidance.previous,"Apply patch A");assert.equal(diff.guidance.current,"Apply patch B");
});

test("semantic changes ignore formatting and checked dates but preserve unknown sections and reversions",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let version=0;
 const contents=[
  '<p>Last checked: November 1, 2099</p><h2>What to do now</h2><p>Apply patch.</p><h2>Evidence and sources</h2><a href="https://vendor.example/a">Vendor</a><h2>Unexpected section</h2><p>Version A. Apply patching.</p>',
  '<div>Last checked: November 2, 2099</div><h2>What to do now</h2><div>Apply <strong>patch</strong>.</div><h2>Evidence and sources</h2><p><a class="new" href="https://vendor.example/a">Vendor</a></p><h2>Unexpected section</h2><p>Version A. Apply patch<strong>ing</strong>.</p>',
  '<p>Last checked: November 2, 2099</p><h2>What to do now</h2><p>Apply patch.</p><h2>Evidence and sources</h2><a href="https://vendor.example/a">Vendor</a><h2>Unexpected section</h2><p>Version B. Apply patching.</p>'
 ];
 const body=()=>feed(item('semantic','Title','CVE-2099-10001').replace('</item>',`<content:encoded><![CDATA[${contents[version]}]]></content:encoded></item>`));
 t.mock.method(globalThis,'fetch',async url=>String(url).includes('zero-wire')?new Response(body()):new Response('down',{status:503}));
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();version=1;await run();
 assert.equal(sql.prepare('SELECT count(*) n FROM change_events').get().n,0);
 assert.equal(sql.prepare('SELECT count(*) n FROM briefing_snapshots').get().n,2);
 assert.equal(sql.prepare('SELECT source_last_checked_date FROM briefing_snapshots ORDER BY revision DESC LIMIT 1').get().source_last_checked_date,'November 2, 2099');
 version=2;await run();version=0;await run();await run();
 const events=sql.prepare('SELECT diff_json FROM change_events ORDER BY sequence').all().map(x=>JSON.parse(x.diff_json));
 assert.equal(events.length,2);assert.ok(events.every(x=>x.classifications.includes('briefing.unclassified_content_changed')));
});

test("CVE, guidance and reference changes receive evidence-based classifications",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let changed=false;
 const body=()=>feed(item('classes','Title',changed?'CVE-2099-10002':'CVE-2099-10001').replace('</item>',`<content:encoded><![CDATA[<h2>What to do now</h2><p>${changed?'Patch B':'Patch A'}</p><h2>Evidence and sources</h2><a href="https://vendor.example/${changed?'b':'a'}">Vendor</a>]]></content:encoded></item>`));
 t.mock.method(globalThis,'fetch',async url=>String(url).includes('zero-wire')?new Response(body()):new Response('down',{status:503}));
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();changed=true;await run();
 const diff=JSON.parse(sql.prepare('SELECT diff_json FROM change_events').get().diff_json);
 for(const kind of ['briefing.cve_added','briefing.cve_removed','briefing.guidance_changed','briefing.evidence_changed'])assert.ok(diff.classifications.includes(kind),kind);
 assert.deepEqual(diff.set_changes.cves,{added:['CVE-2099-10002'],removed:['CVE-2099-10001']});
});

test("normalizer upgrade suppresses parser-only changes but retains a simultaneous source change",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let title='First';
 t.mock.method(globalThis,'fetch',async url=>String(url).includes('zero-wire')?new Response(feed(item('old',title))):new Response('down',{status:503}));
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();
 sql.prepare("UPDATE briefing_snapshots SET normalizer_version='2' WHERE revision=1").run();await run();
 assert.equal(sql.prepare('SELECT count(*) n FROM briefing_snapshots').get().n,2);assert.equal(sql.prepare('SELECT count(*) n FROM change_events').get().n,0);
 sql.prepare("UPDATE briefing_snapshots SET normalizer_version='2' WHERE revision=2").run();title='Changed during upgrade';await run();
 assert.equal(sql.prepare('SELECT count(*) n FROM change_events').get().n,1);
 assert.ok(JSON.parse(sql.prepare('SELECT diff_json FROM change_events').get().diff_json).changed_fields.includes('title'));
});

test("independent refresh retains verified KEV and EPSS transitions across feed and source failures",async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let feedFailed=false,kevFailed=false,listed=false,score='0.10000',date='2099-01-01',missing=false;
 t.mock.method(globalThis,'fetch',async url=>{
  if(String(url).includes('zero-wire'))return feedFailed?new Response('down',{status:503}):new Response(feed(item('signals','Signals','CVE-2099-10001')));
  if(String(url).includes('cisa.gov')){if(kevFailed)return new Response('down',{status:503});const vulns=listed?[{cveID:'CVE-2099-10001',vendorProject:'Vendor',product:'Product',dateAdded:'2099-01-02'}]:[{cveID:'CVE-2099-19000',vendorProject:'Other',product:'Other',dateAdded:'2099-01-01'}];return Response.json({catalogVersion:listed?'2':'1',dateReleased:date,count:vulns.length,vulnerabilities:vulns});}
  return Response.json({status:'OK',total:missing?0:1,data:missing?[]:[{cve:'CVE-2099-10001',epss:score,percentile:'0.80000',date}]});
 });
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();
 assert.equal(sql.prepare('SELECT count(*) n FROM signal_events').get().n,0);
 feedFailed=true;listed=true;score='0.20000';date='2099-01-02';await assert.rejects(run,/feed_http_error/);
 assert.deepEqual(sql.prepare('SELECT event_kind FROM signal_events ORDER BY event_kind').all().map(x=>x.event_kind),['epss_significant_change','kev_membership_changed']);
 assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='zero_wire'").get().last_error_code,'ingestion_failed');
 assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='cisa_kev'").get().last_error_code,null);
 kevFailed=true;missing=true;date='2099-01-03';await assert.rejects(run,/feed_http_error/);
 assert.equal(sql.prepare("SELECT count(*) n FROM signal_events WHERE event_kind='kev_membership_changed'").get().n,1);
 assert.equal(JSON.parse(sql.prepare("SELECT data_json FROM vulnerability_context WHERE source_id='cisa_kev'").get().data_json).listed,true);
 assert.deepEqual(JSON.parse(sql.prepare("SELECT data_json FROM vulnerability_context WHERE source_id='first_epss'").get().data_json),{available:false});
 assert.equal(sql.prepare("SELECT count(*) n FROM enrichment_observations WHERE source_id='first_epss'").get().n,3);
 await assert.rejects(run,/feed_http_error/);assert.equal(sql.prepare('SELECT count(*) n FROM signal_events').get().n,2);
 assert.equal(sql.prepare("SELECT count(*) n FROM enrichment_observations WHERE source_id='first_epss'").get().n,3);
 missing=false;score='0.35000';date='2099-01-04';await assert.rejects(run,/feed_http_error/);
 assert.equal(sql.prepare("SELECT count(*) n FROM signal_events WHERE event_kind='epss_significant_change'").get().n,2);
 const latest=sql.prepare("SELECT previous_json FROM signal_events WHERE event_kind='epss_significant_change' ORDER BY sequence DESC LIMIT 1").get();assert.equal(JSON.parse(latest.previous_json).record.epss,'0.20000');
 await assert.rejects(run,/feed_http_error/);assert.equal(sql.prepare('SELECT count(*) n FROM signal_events').get().n,3);
});

test("additive history migration backfills only actual last observations without changing existing records",()=>{
 const db=new DatabaseSync(':memory:');try{
  for(const name of ['0001_intelligence_foundation.sql','0002_enrichment.sql','0003_enrichment_progress.sql','0004_ingestion_lease.sql'])db.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
  const value=JSON.stringify({available:true,record:{epss:'0.2',percentile:'0.9',date:'2099-01-01'}});
  db.prepare('INSERT INTO vulnerability_context VALUES (?,?,?,?,?)').run('CVE-2099-10001','first_epss','2099-01-02T00:00:00Z','2099-01-02',value);
  const id='https://radar.cloudflare.com/security/zero-wire/legacy';db.prepare('INSERT INTO briefings VALUES (?,?,?,?)').run(id,id,'2099-01-01T00:00:00Z','2099-01-02T00:00:00Z');
  db.prepare('INSERT INTO briefing_snapshots(briefing_id,revision,normalizer_version,semantic_hash,normalized_json,observed_at) VALUES(?,?,?,?,?,?)').run(id,1,'2','a'.repeat(64),JSON.stringify({cves:['CVE-2099-10001']}),'2099-01-01T00:00:00Z');
  db.prepare('INSERT INTO briefing_snapshots(briefing_id,revision,normalizer_version,semantic_hash,normalized_json,observed_at) VALUES(?,?,?,?,?,?)').run(id,2,'2','b'.repeat(64),JSON.stringify({cves:[]}),'2099-01-02T00:00:00Z');
  db.prepare('INSERT INTO briefing_cves VALUES (?,?)').run(id,'CVE-2099-10001');db.prepare('INSERT INTO briefing_tags VALUES (?,?,?)').run(id,'php','PHP');
  db.prepare('INSERT INTO change_events(event_id,briefing_id,from_revision,to_revision,event_kind,observed_at,diff_json) VALUES(?,?,?,?,?,?,?)').run('old-event',id,1,2,'changed','2099-01-02T00:00:00Z','{}');
  db.prepare('INSERT INTO source_state(source_id,source_url,last_success_at) VALUES (?,?,?)').run('zero_wire','https://radar.cloudflare.com/security/zero-wire/rss','2099-01-02T00:00:00Z');
  db.exec(readFileSync(new URL('../migrations/0005_signal_history.sql',import.meta.url),'utf8'));
  db.exec(readFileSync(new URL('../migrations/0006_timeline_indexes.sql',import.meta.url),'utf8'));
  assert.equal(db.prepare('SELECT cve_id FROM briefing_cve_history WHERE briefing_id=?').get(id).cve_id,'CVE-2099-10001');
  for(const table of ['briefings','briefing_cves','briefing_tags','change_events','source_state'])assert.equal(db.prepare(`SELECT count(*) n FROM ${table}`).get().n,1,table);
  assert.equal(db.prepare('SELECT count(*) n FROM briefing_snapshots').get().n,2);
  assert.equal(db.prepare('SELECT data_json FROM vulnerability_context').get().data_json,value);
  const observation=db.prepare('SELECT * FROM enrichment_observations').get();assert.equal(observation.data_json,value);assert.equal(observation.source_date,'2099-01-01');assert.equal(observation.observed_at,'2099-01-02T00:00:00Z');
  assert.equal(db.prepare('SELECT count(*) n FROM signal_events').get().n,0);
 }finally{db.close();}
});

test('malformed KEV catalog cannot create a false not-listed transition',async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let malformed=false;
 t.mock.method(globalThis,'fetch',async url=>{
  if(String(url).includes('zero-wire'))return new Response(feed(item('kev','Tracked','CVE-2099-10001')));
  if(String(url).includes('cisa.gov'))return Response.json({catalogVersion:'1',dateReleased:'2099-01-01',count:1,vulnerabilities:[malformed?{unexpected:'bad'}:{cveID:'CVE-2099-10001',vendorProject:'Vendor',product:'Product',dateAdded:'2099-01-01'}]});
  return Response.json({status:'OK',total:0,data:[]});
 });
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();malformed=true;await run();
 assert.equal(JSON.parse(sql.prepare("SELECT data_json FROM vulnerability_context WHERE source_id='cisa_kev'").get().data_json).listed,true);
 assert.equal(sql.prepare('SELECT count(*) n FROM signal_events').get().n,0);
 assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='cisa_kev'").get().last_error_code,'enrichment_failed');
});

test('incomparable old parser snapshot fails closed without inventing a source event',async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());
 t.mock.method(globalThis,'fetch',async url=>String(url).includes('zero-wire')?new Response(feed(item('incomplete','Title'))):new Response('down',{status:503}));
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();
 sql.prepare("UPDATE briefing_snapshots SET normalizer_version='2', normalized_json=? WHERE revision=1").run(JSON.stringify({title:'legacy without necessary fields'}));
 await assert.rejects(run,/normalizer_comparison_unavailable/);assert.equal(sql.prepare('SELECT count(*) n FROM briefing_snapshots').get().n,1);assert.equal(sql.prepare('SELECT count(*) n FROM change_events').get().n,0);assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='zero_wire'").get().last_error_code,'ingestion_failed');
});

test('long guidance differences preserve Unicode code points when clipped',async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let version='A';const old='a'.repeat(1499)+'🔒'+'A';
 const body=()=>feed(item('unicode','Unicode').replace('</item>',`<content:encoded><![CDATA[<h2>What to do now</h2><p>${version==='A'?old:'b'.repeat(1499)+'🔒B'}</p>]]></content:encoded></item>`));
 t.mock.method(globalThis,'fetch',async url=>String(url).includes('zero-wire')?new Response(body()):new Response('down',{status:503}));const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();version='B';await run();
 const guidance=JSON.parse(sql.prepare('SELECT diff_json FROM change_events').get().diff_json).guidance;assert.equal(guidance.truncated,true);assert.ok(guidance.previous.endsWith('🔒'));assert.ok(guidance.current.endsWith('🔒'));assert.ok(!guidance.previous.includes('�'));
});

test('known EPSS model changes are not presented as exploitation-probability shifts',async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let model='v1',score='0.1',date='2099-01-01';
 t.mock.method(globalThis,'fetch',async url=>{const u=String(url);if(u.includes('zero-wire'))return new Response(feed(item('model','Model test','CVE-2099-10001')));if(u.includes('cisa.gov'))return Response.json({catalogVersion:'v1',dateReleased:date,count:1,vulnerabilities:[{cveID:'CVE-2099-19000',vendorProject:'Other',product:'Other',dateAdded:'2099-01-01'}]});return Response.json({status:'OK',total:1,data:[{cve:'CVE-2099-10001',epss:score,percentile:'0.5',date,model_version:model}]});});
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();model='v2';score='0.9';date='2099-01-02';await run();assert.equal(sql.prepare("SELECT count(*) n FROM signal_events WHERE event_kind='epss_significant_change'").get().n,0);
 score='0.7';date='2099-01-03';await run();assert.equal(sql.prepare("SELECT count(*) n FROM signal_events WHERE event_kind='epss_significant_change'").get().n,1);
});

test('empty or partially malformed KEV catalog never produces false negative membership',async t=>{
 const {sql,adapter}=database();t.after(()=>sql.close());let mode='valid';
 t.mock.method(globalThis,'fetch',async url=>{const u=String(url);if(u.includes('zero-wire'))return new Response(feed(item('kev-validation','Tracked','CVE-2099-10001')));if(u.includes('cisa.gov')){const rows=mode==='valid'?[{cveID:'CVE-2099-10001',vendorProject:'Vendor',product:'Product',dateAdded:'2099-01-01'}]:mode==='empty'?[]:[{cveID:'CVE-2099-10002',vendorProject:'Vendor',dateAdded:'2099-01-01'}];return Response.json({catalogVersion:'1',dateReleased:'2099-01-01',count:rows.length,vulnerabilities:rows})}return Response.json({status:'OK',total:0,data:[]});});
 const run=()=>handleScheduledIngestion({INGESTION_ENABLED:'true',DB:adapter});await run();assert.equal(JSON.parse(sql.prepare("SELECT data_json FROM vulnerability_context WHERE source_id='cisa_kev'").get().data_json).listed,true);
 for(mode of ['empty','partial']){await run();assert.equal(JSON.parse(sql.prepare("SELECT data_json FROM vulnerability_context WHERE source_id='cisa_kev'").get().data_json).listed,true);assert.equal(sql.prepare("SELECT last_error_code FROM source_state WHERE source_id='cisa_kev'").get().last_error_code,'enrichment_failed');assert.equal(sql.prepare('SELECT count(*) n FROM signal_events').get().n,0);}
});
