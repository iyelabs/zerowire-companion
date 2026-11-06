import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';

test('KEV catalog migration adds isolated history and indexes without altering existing data',()=>{
 const db=new DatabaseSync(':memory:');try{
  for(let n=1;n<=6;n++){const path=['0001_intelligence_foundation','0002_enrichment','0003_enrichment_progress','0004_ingestion_lease','0005_signal_history','0006_timeline_indexes'][n-1];db.exec(readFileSync(new URL(`../migrations/${path}.sql`,import.meta.url),'utf8'));}
  db.prepare('INSERT INTO briefings(id,canonical_url,first_observed_at,last_observed_at) VALUES(?,?,?,?)').run('existing','https://example.test','2026-01-01','2026-01-01');
  db.exec(readFileSync(new URL('../migrations/0007_kev_catalog.sql',import.meta.url),'utf8'));
  assert.equal(db.prepare('SELECT count(*) n FROM briefings').get().n,1);
  assert.equal(db.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,0);
  assert.throws(()=>db.prepare('INSERT INTO kev_catalog_stage VALUES (?,?,?)').run('v','CVE-2021-44228','broken'));
  assert.match(JSON.stringify(db.prepare('EXPLAIN QUERY PLAN SELECT * FROM kev_catalog ORDER BY date_added DESC,cve_id LIMIT 10').all()),/kev_catalog_by_added/);
 }finally{db.close()}
});

test('native OSV tracking migration preserves populated advisory and snapshot tables',()=>{
 const db=new DatabaseSync(':memory:');try{
  for(const name of ['0001_intelligence_foundation','0002_enrichment','0003_enrichment_progress','0004_ingestion_lease','0005_signal_history','0006_timeline_indexes','0007_kev_catalog','0008_epss_series','0009_package_intelligence'])db.exec(readFileSync(new URL(`../migrations/${name}.sql`,import.meta.url),'utf8'));
  db.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('existing','https://example.test','2026-01-01','2026-01-01');
  db.prepare('INSERT INTO package_advisories VALUES(?,?,?,?,?,?,?,?)').run('ghsa','GHSA-2222-2222-2222','CVE-2021-44228','https://example.test',null,null,'2026-01-01','{}');
  db.exec(readFileSync(new URL('../migrations/0010_osv_cve_state.sql',import.meta.url),'utf8'));
  assert.equal(db.prepare('SELECT count(*) n FROM briefings').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM package_advisories').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM osv_cve_state').get().n,0);
 }finally{db.close()}
});

test('EPSS retry migration preserves existing series and creates no synthetic errors',()=>{
 const db=new DatabaseSync(':memory:');try{
  for(const name of ['0001_intelligence_foundation','0002_enrichment','0003_enrichment_progress','0004_ingestion_lease','0005_signal_history','0006_timeline_indexes','0007_kev_catalog','0008_epss_series','0009_package_intelligence','0010_osv_cve_state'])db.exec(readFileSync(new URL(`../migrations/${name}.sql`,import.meta.url),'utf8'));
  db.prepare('INSERT INTO epss_series VALUES(?,?,?,?,?,?)').run('CVE-2021-44228','2026-11-01','2026-11-01','[]','https://api.first.org/data/v1/epss',null);
  db.exec(readFileSync(new URL('../migrations/0011_epss_series_attempts.sql',import.meta.url),'utf8'));
  assert.equal(db.prepare('SELECT count(*) n FROM epss_series').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM epss_series_attempts').get().n,0);
 }finally{db.close()}
});

test('cross-source timeline indexes preserve historical events on populated upgrade',()=>{
 const db=new DatabaseSync(':memory:');try{
  for(const name of ['0001_intelligence_foundation','0002_enrichment','0003_enrichment_progress','0004_ingestion_lease','0005_signal_history','0006_timeline_indexes','0007_kev_catalog','0008_epss_series','0009_package_intelligence','0010_osv_cve_state','0011_epss_series_attempts'])db.exec(readFileSync(new URL(`../migrations/${name}.sql`,import.meta.url),'utf8'));
  db.prepare('INSERT INTO kev_catalog_events(cve_id,event_kind,observed_at,catalog_version,source_date,previous_json,current_json) VALUES(?,?,?,?,?,?,?)').run('CVE-2021-44228','kev.first_observed','2026-01-01','v1','2026-01-01',null,'{}');
  db.exec(readFileSync(new URL('../migrations/0012_cross_source_timeline_indexes.sql',import.meta.url),'utf8'));
  assert.equal(db.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,1);assert.match(JSON.stringify(db.prepare('EXPLAIN QUERY PLAN SELECT * FROM kev_catalog_events WHERE cve_id=? AND observed_at>=? ORDER BY observed_at DESC,sequence DESC LIMIT 10').all('CVE-2021-44228','2020-01-01')),/kev_catalog_events_by_cve_time/);
 }finally{db.close()}
});

test('OSV alias queue migration leaves existing package records intact',()=>{
 const db=new DatabaseSync(':memory:');try{
  for(const name of ['0001_intelligence_foundation','0002_enrichment','0003_enrichment_progress','0004_ingestion_lease','0005_signal_history','0006_timeline_indexes','0007_kev_catalog','0008_epss_series','0009_package_intelligence','0010_osv_cve_state','0011_epss_series_attempts','0012_cross_source_timeline_indexes'])db.exec(readFileSync(new URL(`../migrations/${name}.sql`,import.meta.url),'utf8'));
  db.prepare('INSERT INTO package_advisories VALUES(?,?,?,?,?,?,?,?)').run('osv','CVE-2021-20319','CVE-2021-20319','https://osv.dev/vulnerability/CVE-2021-20319',null,null,'2026-01-01','{}');
  db.exec(readFileSync(new URL('../migrations/0013_osv_alias_queue.sql',import.meta.url),'utf8'));assert.equal(db.prepare('SELECT count(*) n FROM package_advisories').get().n,1);assert.equal(db.prepare('SELECT count(*) n FROM osv_alias_queue').get().n,0);
 }finally{db.close()}
});
test('alias scan migration preserves cached native records and makes them eligible for backfill',()=>{
 const db=new DatabaseSync(':memory:');try{
 for(const f of readdirSync(new URL('../migrations/',import.meta.url)).filter(x=>x.endsWith('.sql')&&x<'0014').sort())db.exec(readFileSync(new URL(`../migrations/${f}`,import.meta.url),'utf8'));
 db.prepare("INSERT INTO osv_cve_state(cve_id,last_attempt_at,last_success_at) VALUES(?,?,?)").run('CVE-2099-10001','2099-01-01','2099-01-01');
 db.exec(readFileSync(new URL('../migrations/0014_osv_alias_scan.sql',import.meta.url),'utf8'));const row=db.prepare('SELECT * FROM osv_cve_state').get();assert.equal(row.cve_id,'CVE-2099-10001');assert.equal(row.alias_scan_at,null);
 }finally{db.close()}
});
test('GHSA retry-policy migration preserves populated advisory and source history',()=>{
 const db=new DatabaseSync(':memory:');try{for(const name of readdirSync(new URL('../migrations/',import.meta.url)).filter(x=>x.endsWith('.sql')&&x<'0015').sort())db.exec(readFileSync(new URL(`../migrations/${name}`,import.meta.url),'utf8'));
 db.prepare('INSERT INTO package_feed_state(singleton,baseline_at,last_attempt_at,last_success_at,last_error_code) VALUES(1,?,?,?,?)').run('2026-11-05T00:00:00Z','2026-11-05T01:00:00Z','2026-11-05T00:00:00Z','source_http_403');
 db.exec(readFileSync(new URL('../migrations/0015_ghsa_retry_policy.sql',import.meta.url),'utf8'));assert.equal(db.prepare('SELECT last_error_code FROM package_feed_state').get().last_error_code,'source_http_403');assert.equal(db.prepare('SELECT count(*) n FROM ghsa_retry_policy').get().n,0);
 }finally{db.close()}
});
