import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { createQueries } from "../src/public/queries.ts";

test("read adapter performs indexed exact matching and never mutates state", async () => {
 const db=new DatabaseSync(":memory:"); db.exec("PRAGMA foreign_keys=ON");
 for(const name of ["0001_intelligence_foundation.sql","0002_enrichment.sql","0003_enrichment_progress.sql","0004_ingestion_lease.sql","0005_signal_history.sql","0006_timeline_indexes.sql","0007_kev_catalog.sql","0008_epss_series.sql","0009_package_intelligence.sql","0010_osv_cve_state.sql","0011_epss_series_attempts.sql","0012_cross_source_timeline_indexes.sql","0013_osv_alias_queue.sql","0014_osv_alias_scan.sql","0015_ghsa_retry_policy.sql"]) db.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),"utf8"));
 try {
  const id="https://radar.cloudflare.com/security/zero-wire/example"; const now="2026-11-04T00:00:00Z";
  db.prepare("INSERT INTO briefings VALUES (?,?,?,?)").run(id,id,now,now);
  db.prepare("INSERT INTO briefing_snapshots (briefing_id,revision,normalizer_version,semantic_hash,normalized_json,observed_at) VALUES (?,?,?,?,?,?)").run(id,1,"1","a".repeat(64),JSON.stringify({title:"Example"}),now);
  db.prepare("INSERT INTO briefing_tags VALUES (?,?,?)").run(id,"php","PHP"); db.prepare("INSERT INTO briefing_cves VALUES (?,?)").run(id,"CVE-2099-10001");
  const onlyReads={prepare(sql){assert.match(sql,/^SELECT /);if(sql.includes("briefing_cves x")||sql.includes("briefing_tags x")){const qp=db.prepare("EXPLAIN QUERY PLAN "+sql).all(sql.includes("briefing_cves x")?"CVE-2099-10001":"php","",10);assert.ok(qp.some(row=>row.detail.includes("briefing_id>?")));assert.ok(qp.every(row=>!row.detail.includes("TEMP B-TREE")));}let args=[];return {bind(...v){args=v;return this},async all(){return {results:db.prepare(sql).all(...args)}},async first(){return db.prepare(sql).get(...args)??null}}}};
  const q=createQueries(onlyReads); assert.equal((await q.match("tag","php",10))[0].id,id); assert.equal((await q.match("cve","CVE-2099-10001",10))[0].id,id); assert.equal((await q.match("tag","python",10)).length,0); assert.equal((await q.match("tag","php",10,id)).length,0); assert.equal((await q.get(id)).id,id); assert.equal((await q.list(10,"")).length,1);
  const plan=db.prepare("EXPLAIN QUERY PLAN SELECT briefing_id FROM briefing_tags WHERE normalized_tag=? LIMIT 15").all("php"); assert.ok(plan.some(x=>x.detail.includes("briefing_tags_by_tag")));
  assert.equal(db.prepare("SELECT COUNT(*) n FROM briefing_snapshots").get().n,1);
 } finally {db.close()}
});

test('timeline and historical association queries use their bounded D1 indexes',async()=>{
 const sql=new DatabaseSync(':memory:');for(const name of ['0001_intelligence_foundation.sql','0002_enrichment.sql','0003_enrichment_progress.sql','0004_ingestion_lease.sql','0005_signal_history.sql','0006_timeline_indexes.sql','0007_kev_catalog.sql','0008_epss_series.sql','0009_package_intelligence.sql','0010_osv_cve_state.sql','0011_epss_series_attempts.sql','0012_cross_source_timeline_indexes.sql','0013_osv_alias_queue.sql','0014_osv_alias_scan.sql','0015_ghsa_retry_policy.sql'])sql.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
 const plans=[];const db={prepare(query){let args=[];return {bind(...v){args=v;return this},async all(){plans.push(sql.prepare('EXPLAIN QUERY PLAN '+query).all(...args).map(x=>x.detail).join(' '));return {results:sql.prepare(query).all(...args)}},async first(){return sql.prepare(query).get(...args)??null}}}};
 try{const q=createQueries(db),since='2020-01-01T00:00:00.000Z',until='2099-01-01T00:00:00.000Z',time='2099-01-01T00:00:00.000Z';
  await q.timelineBriefing('id',since,until,time,'',100,10);await q.timelineSignals('CVE-2099-10001',since,until,time,'',100,10);await q.timelineObservations('CVE-2099-10001',since,until,time,'',100,10);await q.historyMatch('CVE-2099-10001',3);
  for(const index of ['change_events_by_briefing_time','signal_events_by_cve_time','observations_by_cve_time','briefing_cve_history_by_cve'])assert.ok(plans.some(plan=>plan.includes(index)),`${index}: ${plans.join('; ')}`);
 }finally{sql.close()}
});
