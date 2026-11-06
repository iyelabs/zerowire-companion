import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";

test("built Worker and migration run in local workerd/D1 with external egress denied", async () => {
  const directory = mkdtempSync(join(tmpdir(), "zwc-runtime-"));
  const output = new URL("../.cloudflare/output/v0/workers/default/", import.meta.url);
  const config = JSON.parse(readFileSync(new URL("worker.config.json", output), "utf8"));
  const bundle = readFileSync(new URL("bundle/index.js", output), "utf8");
  assert.equal(config.env.PUBLIC_RATE_LIMITER.simple.limit, 60);
  assert.equal(config.env.INGESTION_ENABLED.value, "false");
  assert.equal(config.triggers[0].type, "scheduled");
  assert.equal(config.observability.redactQueryString, true);
  assert.equal(config.observability.traces.enabled, true);

  // Only the local simulation receives synthetic resource IDs and a shorter test window.
  config.env.DB.id = "00000000-0000-0000-0000-000000000001";
  config.env.PUBLIC_RATE_LIMITER.simple.limit = 2;
  config.manifest = { mainModule: "index.js", modulesRoot: "/", modules: { "index.js": { type: "esm", contents: bundle } } };
  let egress = 0;
  const runtime = new Miniflare({
    cf: false,
    telemetry: { enabled: false },
    enableDevRegistry: false,
    resourcePersistencePath: directory,
    workers: [{ config, dev: { outboundService: { type: "fetcher", handler() { egress++; throw new Error("External egress is denied in runtime tests"); } } } }],
  });
  try {
    const database = await runtime.getD1Database("DB");
    const sql = ["0001_intelligence_foundation.sql", "0002_enrichment.sql", "0003_enrichment_progress.sql", "0004_ingestion_lease.sql","0005_signal_history.sql","0006_timeline_indexes.sql","0007_kev_catalog.sql","0008_epss_series.sql","0009_package_intelligence.sql","0010_osv_cve_state.sql","0011_epss_series_attempts.sql","0012_cross_source_timeline_indexes.sql","0013_osv_alias_queue.sql","0014_osv_alias_scan.sql","0015_ghsa_retry_policy.sql"].map(name => readFileSync(new URL(`../migrations/${name}`, import.meta.url), "utf8")).join("\n");
    // This migration has no semicolons in literals; apply its statements as one D1 batch.
    const statements = sql.replace(/^--.*$/gm, "").split(";").map(part => part.trim()).filter(Boolean);
    await database.batch(statements.map(statement => database.prepare(statement)));
    assert.equal((await database.prepare("SELECT version FROM schema_meta").first()).version, 1);
    assert.equal((await database.prepare("SELECT COUNT(*) AS total FROM briefings").first()).total, 0);
    await assert.rejects(() => database.prepare("INSERT INTO briefing_cves VALUES (?, ?)").bind("zw:missing", "CVE-2099-10001").run(), /FOREIGN KEY/);

    const live = await runtime.dispatchFetch("https://deployment.example/health");
    assert.equal(live.status, 200);
    assert.equal((await live.json()).status, "ok");
    // Miniflare uses fixed minute windows. If the three requests straddle a
    // window boundary, repeat with a fresh key; never accept a missing 429
    // for three requests observed within the same window.
    async function rateCheck(path, baseIp, allowed, makeInit, inspectFirst) {
      for (let attempt=0;attempt<2;attempt++) {
        const init=makeInit(`192.0.2.${baseIp+attempt}`), start=Date.now();
        const first=await runtime.dispatchFetch(`https://deployment.example${path}`,init);
        assert.equal(first.status,allowed);if(inspectFirst)await inspectFirst(first);
        assert.equal((await runtime.dispatchFetch(`https://deployment.example${path}`,init)).status,allowed);
        const third=await runtime.dispatchFetch(`https://deployment.example${path}`,init), end=Date.now();
        if(third.status===429)return;
        if(Math.floor(start/60000)===Math.floor(end/60000)||attempt===1)assert.equal(third.status,429);
      }
    }
    await rateCheck('/mcp',24,200,ip=>({method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':ip,accept:'application/json, text/event-stream'},body:'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'}),async first=>assert.ok((await first.json()).result.tools.some(tool=>tool.name==='match_briefings')));
    await rateCheck('/health',30,200,ip=>({headers:{'cf-connecting-ip':ip}}));
    await rateCheck('/missing',40,404,ip=>({headers:{'cf-connecting-ip':ip}}));
    assert.equal(egress, 0);
    assert.equal((await database.prepare("SELECT COUNT(*) AS total FROM source_state").first()).total, 0);
    assert.equal((await database.prepare("SELECT COUNT(*) AS total FROM briefings").first()).total, 0);
    const queryPlan = await database.prepare("EXPLAIN QUERY PLAN SELECT briefing_id FROM briefing_cves WHERE cve_id = ? LIMIT 25").bind("CVE-2099-10001").all();
    assert.ok(queryPlan.results.some(row => row.detail.includes("briefing_cves_by_cve")));
  } finally {
    await runtime.dispose();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("scheduled Worker creates a baseline and changes with mocked upstream only", async () => {
 const directory=mkdtempSync(join(tmpdir(),"zwc-scheduled-"));
 const output=new URL("../.cloudflare/output/v0/workers/default/",import.meta.url);
 const config=JSON.parse(readFileSync(new URL("worker.config.json",output),"utf8"));
 const bundle=readFileSync(new URL("bundle/index.js",output),"utf8");
 config.env.DB.id="00000000-0000-0000-0000-000000000002"; config.env.INGESTION_ENABLED.value="true";
 config.manifest={mainModule:"index.js",modulesRoot:"/",modules:{"index.js":{type:"esm",contents:bundle}}};
 let version="one"; let egress=0; let redirect=false;
 const runtime=new Miniflare({cf:false,telemetry:{enabled:false},enableDevRegistry:false,resourcePersistencePath:directory,workers:[{config,dev:{outboundService:{type:"fetcher",handler(request){
  egress++; const url=new URL(request.url);
  if(url.hostname==="radar.cloudflare.com" && redirect) return new Response(null,{status:302,headers:{location:"https://attacker.invalid/"}});
  if(url.hostname==="radar.cloudflare.com") return new Response(`<rss><channel><item><title>${version}</title><link>https://radar.cloudflare.com/security/zero-wire/example</link><category>CVE-2099-10001</category></item></channel></rss>`);
  if(url.hostname==="www.cisa.gov") return Response.json({catalogVersion:"1",dateReleased:"2099-01-01",count:1,vulnerabilities:[{cveID:"CVE-2099-19000",vendorProject:"Other",product:"Other",dateAdded:"2099-01-01"}]});
  if(url.hostname==="api.first.org") return Response.json({status:"OK",total:0,data:[]});
  throw new Error("unexpected egress");
 }}}}]});
 try {
  const db=await runtime.getD1Database("DB");
  const sql=["0001_intelligence_foundation.sql","0002_enrichment.sql","0003_enrichment_progress.sql","0004_ingestion_lease.sql","0005_signal_history.sql","0006_timeline_indexes.sql","0007_kev_catalog.sql","0008_epss_series.sql","0009_package_intelligence.sql","0010_osv_cve_state.sql","0011_epss_series_attempts.sql","0012_cross_source_timeline_indexes.sql","0013_osv_alias_queue.sql","0014_osv_alias_scan.sql","0015_ghsa_retry_policy.sql"].map(name=>readFileSync(new URL(`../migrations/${name}`,import.meta.url),"utf8")).join("\n");
  await db.batch(sql.replace(/^--.*$/gm,"").split(";").map(x=>x.trim()).filter(Boolean).map(x=>db.prepare(x)));
  const worker=await runtime.getWorker(); assert.equal((await worker.scheduled({cron:"0 * * * *"})).outcome,"ok");
  assert.equal((await db.prepare("SELECT count(*) n FROM briefings").first()).n,1); assert.equal((await db.prepare("SELECT count(*) n FROM change_events").first()).n,0);
  version="two"; assert.equal((await worker.scheduled({cron:"0 * * * *"})).outcome,"ok"); assert.equal((await db.prepare("SELECT count(*) n FROM change_events").first()).n,1);
  const before=egress; const res=await runtime.dispatchFetch("https://deployment.example/mcp",{method:"POST",headers:{"content-type":"application/json",accept:"application/json, text/event-stream"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"list_briefings",arguments:{}}})});
  assert.equal(res.status,200); assert.equal(egress,before); assert.equal((await db.prepare("SELECT count(*) n FROM change_events").first()).n,1);
  for (const name of ["get_triage_pack","get_signal_timeline"]) {
   const reply=await runtime.dispatchFetch("https://deployment.example/mcp",{method:"POST",headers:{"content-type":"application/json",accept:"application/json, text/event-stream"},body:JSON.stringify({jsonrpc:"2.0",id:2,method:"tools/call",params:{name,arguments:{identifier:"https://radar.cloudflare.com/security/zero-wire/example"}}})});
   const result=await reply.json();assert.equal(reply.status,200);assert.equal(result.result.isError,undefined,JSON.stringify(result));assert.equal(JSON.parse(result.result.content[0].text).data.status,"ok");
  }
  assert.equal(egress,before);assert.equal((await db.prepare("SELECT count(*) n FROM change_events").first()).n,1);
  redirect=true; const previous=egress; assert.equal((await worker.scheduled({cron:"0 * * * *"})).outcome,"exception"); assert.equal(egress,previous+3); assert.equal((await db.prepare("SELECT count(*) n FROM briefings").first()).n,1);
 } finally {await runtime.dispose();rmSync(directory,{recursive:true,force:true})}
});
