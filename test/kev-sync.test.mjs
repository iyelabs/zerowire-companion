import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import {validateKevCatalog} from '../src/intelligence/kev.ts';
import {syncKevCatalog} from '../src/ingestion/kev-catalog.ts';
function setup(){
 const sql=new DatabaseSync(':memory:');for(const file of readdirSync(new URL('../migrations/',import.meta.url)).filter(x=>x.endsWith('.sql')).sort())sql.exec(readFileSync(new URL(`../migrations/${file}`,import.meta.url),'utf8'));
 const db={prepare(query){let params=[];return {bind(...args){params=args;return this},async first(){return sql.prepare(query).get(...params)??null},async all(){return {results:sql.prepare(query).all(...params)}},async run(){return sql.prepare(query).run(...params)}}},async batch(stmts){sql.exec('BEGIN');try{for(const s of stmts)await s.run();sql.exec('COMMIT')}catch(e){sql.exec('ROLLBACK');throw e}}};
 sql.prepare('INSERT INTO ingestion_lease VALUES(?,?,?)').run('scheduled','owner','9999-01-01T00:00:00.000Z');return {sql,db};
}
const record=(i,desc='A')=>({cveID:`CVE-2026-${10000+i}`,vendorProject:'Vendor',product:'Product',dateAdded:'2026-01-01',shortDescription:desc});
const catalog=(rows,version='1')=>validateKevCatalog({catalogVersion:version,dateReleased:'2026-11-04T20:00:00Z',count:rows.length,vulnerabilities:rows});
const time='2026-11-05T01:00:00.000Z';
test('partial baseline remains invisible, publishes once, changes and reversions are observed',async()=>{
 const {sql,db}=setup();try{
  const original=catalog([record(1),record(2),record(3)]);
  assert.deepEqual(await syncKevCatalog(db,'owner',original,time,2),{complete:false,staged:2});
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog').get().n,0);
  assert.equal((await syncKevCatalog(db,'owner',original,time,2)).complete,true);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog').get().n,3);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,0);
  await syncKevCatalog(db,'owner',original,time,2);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,0);
  const changed=catalog([record(1,'B'),record(2),record(3),record(4)],'2');
  await syncKevCatalog(db,'owner',changed,time,2);
  assert.equal(sql.prepare("SELECT json_extract(record_json,'$.shortDescription') v FROM kev_catalog WHERE cve_id='CVE-2026-10001'").get().v,'A');
  await syncKevCatalog(db,'owner',changed,time,2);
  assert.deepEqual(sql.prepare('SELECT event_kind FROM kev_catalog_events ORDER BY sequence').all().map(x=>x.event_kind),['kev.record_changed','kev.first_observed']);
  await syncKevCatalog(db,'owner',original,time,2);await syncKevCatalog(db,'owner',original,time,2);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,4);
 }finally{sql.close()}
});
test('changed generation restarts staging and stale lease cannot publish',async()=>{
 const {sql,db}=setup();try{
  await syncKevCatalog(db,'owner',catalog([record(1),record(2),record(3)]),time,1);
  const next=catalog([record(1,'B'),record(2)],'2');
  assert.deepEqual(await syncKevCatalog(db,'owner',next,time,1),{complete:false,staged:1});
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog_stage').get().n,1);
  sql.prepare('UPDATE ingestion_lease SET owner=?').run('other');
  await assert.rejects(syncKevCatalog(db,'owner',next,time,1));
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog').get().n,0);
 }finally{sql.close()}
});
test('an implausibly shrunken catalog leaves the previous published generation intact',async()=>{
 const {sql,db}=setup();try{
  const full=catalog(Array.from({length:20},(_,i)=>record(i)));
  await syncKevCatalog(db,'owner',full,time,50);
  await assert.rejects(syncKevCatalog(db,'owner',catalog([record(1)],'2'),time,50),/unexpected_shrink/);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog').get().n,20);
  assert.equal(sql.prepare('SELECT count(*) n FROM kev_catalog_events').get().n,0);
 }finally{sql.close()}
});
