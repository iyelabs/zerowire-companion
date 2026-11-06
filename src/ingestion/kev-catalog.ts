import type { WorkerEnv } from '../../cloudflare.config.ts';
import { fencedBatch } from './lease.ts';
import { canonicalKevJson, type KevCatalog } from '../intelligence/kev.ts';

type Db=WorkerEnv['DB'];
type State={baseline_at:string|null;content_hash:string|null;generation:string|null;cursor:string|null;record_count:number|null};
const encoder=new TextEncoder();
async function digest(value:string):Promise<string>{
 const bytes=await crypto.subtle.digest('SHA-256',encoder.encode(value));
 return Array.from(new Uint8Array(bytes),x=>x.toString(16).padStart(2,'0')).join('');
}
/** Stage bounded slices and atomically publish only a complete validated generation. */
export async function syncKevCatalog(db:Db,owner:string,catalog:KevCatalog,now:string,batchSize=250):Promise<{complete:boolean;staged:number}> {
 if(!Number.isInteger(batchSize)||batchSize<1||batchSize>500)throw new Error('invalid_kev_batch');
 const rows=catalog.records.map(r=>({id:r.cveID,data:canonicalKevJson(r)}));
 // The generation includes all source content, not only a potentially reused version number.
 const generation=await digest(canonicalKevJson({version:catalog.catalogVersion,date:catalog.dateReleased,rows}));
 let state=await db.prepare('SELECT baseline_at,content_hash,generation,cursor,record_count FROM kev_catalog_state WHERE singleton=1').first<State>();
 if(state?.baseline_at && (catalog.records.length===0 || (state.record_count!==null && state.record_count>=10 && catalog.records.length < state.record_count*0.9))) throw new Error('kev_catalog_unexpected_shrink');
 if(state?.content_hash===generation && !state.generation) {
  await fencedBatch(db,owner,[db.prepare('UPDATE kev_catalog_state SET retrieved_at=?,last_error_code=NULL WHERE singleton=1').bind(now)]);
  return {complete:true,staged:0};
 }
 if(state?.generation!==generation) {
  await fencedBatch(db,owner,[db.prepare('DELETE FROM kev_catalog_stage'),db.prepare('INSERT INTO kev_catalog_state(singleton,generation,cursor,last_error_code) VALUES(1,?,\'\',NULL) ON CONFLICT(singleton) DO UPDATE SET generation=excluded.generation,cursor=excluded.cursor,last_error_code=NULL').bind(generation)]);
  state={baseline_at:state?.baseline_at??null,content_hash:state?.content_hash??null,record_count:state?.record_count??null,generation,cursor:''};
 }
 const slice=rows.filter(r=>r.id>(state?.cursor??'')).slice(0,batchSize);
 if(slice.length){
  const json=JSON.stringify(slice);
  const insert=db.prepare("INSERT INTO kev_catalog_stage(generation,cve_id,record_json) SELECT ?,json_extract(j.value,'$.id'),json_extract(j.value,'$.data') FROM json_each(?) j").bind(generation,json);
  await fencedBatch(db,owner,[insert,db.prepare('UPDATE kev_catalog_state SET cursor=? WHERE singleton=1 AND generation=?').bind(slice.at(-1)!.id,generation)]);
 }
 const staged=await db.prepare('SELECT count(*) AS n FROM kev_catalog_stage WHERE generation=?').bind(generation).first<{n:number}>();
 if(staged?.n!==rows.length)return {complete:false,staged:staged?.n??0};
 // Compare and swap in one D1 transaction. A new installation creates no historical events.
 const eventSql="INSERT INTO kev_catalog_events(cve_id,event_kind,observed_at,catalog_version,source_date,previous_json,current_json) SELECT s.cve_id,CASE WHEN c.cve_id IS NULL THEN 'kev.first_observed' ELSE 'kev.record_changed' END,?,?,?,c.record_json,s.record_json FROM kev_catalog_stage s LEFT JOIN kev_catalog c ON c.cve_id=s.cve_id WHERE s.generation=? AND EXISTS(SELECT 1 FROM kev_catalog_state WHERE singleton=1 AND baseline_at IS NOT NULL) AND (c.cve_id IS NULL OR c.record_json<>s.record_json)";
 const removedSql="INSERT INTO kev_catalog_events(cve_id,event_kind,observed_at,catalog_version,source_date,previous_json,current_json) SELECT c.cve_id,'kev.record_removed',?,?,?,c.record_json,'{}' FROM kev_catalog c WHERE NOT EXISTS(SELECT 1 FROM kev_catalog_stage s WHERE s.generation=? AND s.cve_id=c.cve_id) AND EXISTS(SELECT 1 FROM kev_catalog_state WHERE singleton=1 AND baseline_at IS NOT NULL)";
 const upsertSql="INSERT INTO kev_catalog(cve_id,vendor,product,date_added,record_json,catalog_version,source_date,first_observed_at,last_observed_at) SELECT s.cve_id,json_extract(s.record_json,'$.vendorProject'),json_extract(s.record_json,'$.product'),json_extract(s.record_json,'$.dateAdded'),s.record_json,?,?,?,? FROM kev_catalog_stage s WHERE s.generation=? ON CONFLICT(cve_id) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,date_added=excluded.date_added,record_json=excluded.record_json,catalog_version=excluded.catalog_version,source_date=excluded.source_date,last_observed_at=excluded.last_observed_at";
 await fencedBatch(db,owner,[
  db.prepare(eventSql).bind(now,catalog.catalogVersion,catalog.dateReleased,generation),
  db.prepare(removedSql).bind(now,catalog.catalogVersion,catalog.dateReleased,generation),
  db.prepare(upsertSql).bind(catalog.catalogVersion,catalog.dateReleased,now,now,generation),
  db.prepare('DELETE FROM kev_catalog WHERE NOT EXISTS(SELECT 1 FROM kev_catalog_stage s WHERE s.generation=? AND s.cve_id=kev_catalog.cve_id)').bind(generation),
  db.prepare('UPDATE kev_catalog_state SET baseline_at=COALESCE(baseline_at,?),catalog_version=?,content_hash=?,source_date=?,retrieved_at=?,record_count=?,generation=NULL,cursor=NULL,last_error_code=NULL WHERE singleton=1 AND generation=?').bind(now,catalog.catalogVersion,generation,catalog.dateReleased,now,rows.length,generation),
  db.prepare('DELETE FROM kev_catalog_stage WHERE generation=?').bind(generation)
 ]);
 return {complete:true,staged:rows.length};
}
