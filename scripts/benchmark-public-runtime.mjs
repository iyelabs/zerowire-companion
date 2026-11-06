// Isolated local workerd/D1 benchmark with synthetic events. Never targets production.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { Miniflare } from 'miniflare';

const output=new URL('../.cloudflare/output/v0/workers/default/',import.meta.url);
const config=JSON.parse(readFileSync(new URL('worker.config.json',output),'utf8'));
const bundle=readFileSync(new URL('bundle/index.js',output),'utf8');
config.env.DB.id='00000000-0000-0000-0000-000000000097';
config.env.INGESTION_ENABLED.value='false';
config.manifest={mainModule:'index.js',modulesRoot:'/',modules:{'index.js':{type:'esm',contents:bundle}}};
let egress=0;
const directory=mkdtempSync(join(tmpdir(),'zwc-public-benchmark-'));
const runtime=new Miniflare({cf:false,telemetry:{enabled:false},enableDevRegistry:false,resourcePersistencePath:directory,workers:[{config,dev:{outboundService:{type:'fetcher',handler(){egress++;throw Error('unexpected egress')}}}}]});
try{
 const db=await runtime.getD1Database('DB');
 const migrations=readdirSync(new URL('../migrations/',import.meta.url)).filter(x=>x.endsWith('.sql')).sort().map(x=>readFileSync(new URL(`../migrations/${x}`,import.meta.url),'utf8')).join('\n');
 await db.batch(migrations.replace(/^--.*$/gm,'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>db.prepare(x)));
 const now=new Date().toISOString();
 for(let start=0;start<12000;start+=500){
  const rows=Array.from({length:500},(_,i)=>({cve:`CVE-2099-${10000+start+i}`}));
  await db.prepare("INSERT INTO kev_catalog_events(cve_id,event_kind,observed_at,catalog_version,source_date,previous_json,current_json) SELECT json_extract(value,'$.cve'),'kev.first_observed',?,'fixture','2099-01-01',NULL,'{}' FROM json_each(?)").bind(now,JSON.stringify(rows)).run();
 }
 const before=(await db.prepare('SELECT count(*) n FROM kev_catalog_events').first()).n;
 const durations=[];
 for(let i=0;i<20;i++){
  const started=performance.now();
  const response=await runtime.dispatchFetch('https://local.example/events.json?source=cisa_kev&cve=CVE-2099-99999&limit=10');
  const data=await response.json();durations.push(performance.now()-started);
  assert.equal(response.status,200);assert.equal(data.items.length,0);assert.equal(data.scan.events_examined,50);assert.ok(data.next_cursor);
 }
 const after=(await db.prepare('SELECT count(*) n FROM kev_catalog_events').first()).n;
 assert.equal(before,12000);assert.equal(after,before);assert.equal(egress,0);
 durations.sort((a,b)=>a-b);
 console.log(JSON.stringify({scope:'Synthetic data in isolated local workerd/D1 only; not production throughput, CPU or billing evidence.',events:before,requests:durations.length,p50_wall_ms:Math.round(durations[9]*100)/100,p95_wall_ms:Math.round(durations[18]*100)/100,max_wall_ms:Math.round(durations.at(-1)*100)/100,public_egress:egress,observed_event_mutation:after-before}));
}finally{await runtime.dispose();rmSync(directory,{recursive:true,force:true});}
