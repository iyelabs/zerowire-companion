import { SourceHttpError, githubFailure } from './source-http-error.ts';
import { SOURCE_USER_AGENT } from '../shared/version.ts';
import type { WorkerEnv } from "../../cloudflare.config.ts";
import { fencedBatch } from "./lease.ts";
import { validateKevCatalog } from "../intelligence/kev.ts";
import { syncKevCatalog } from "./kev-catalog.ts";
import { refreshEpssSeries } from "./epss-series.ts";
import { refreshPackages } from "./packages.ts";
const KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS = "https://api.first.org/data/v1/epss";
const LIMIT = 8 * 1024 * 1024;
type Source = "cisa_kev" | "first_epss";
type Obj = Record<string, unknown>;
const obj = (x: unknown): Obj => x && typeof x === "object" && !Array.isArray(x) ? x as Obj : {};
export async function readJsonSource(url: string, githubToken?:string): Promise<unknown> {
 const parsed=new URL(url);
 const ghsa=parsed.protocol==='https:' && parsed.hostname==='api.github.com' && !parsed.port && !parsed.username && !parsed.password && parsed.pathname==='/advisories';
 const headers:Record<string,string>={accept:"application/json","user-agent":SOURCE_USER_AGENT};
 if(ghsa && githubToken) headers.authorization=`Bearer ${githubToken}`;
 const response = await fetch(url,{redirect:"manual",signal:AbortSignal.timeout(20000),headers});
 if (!response.ok) { const ghsa=url.startsWith('https://api.github.com/advisories?') && (response.status===403 || response.status===429) ? await githubFailure(response) : null; throw new SourceHttpError(response.status,ghsa); }
 if (!response.body) throw new Error("source_empty_body");
 const reader=response.body.getReader(); const decoder=new TextDecoder(); let size=0; let content="";
 try { while(true) { const part=await reader.read(); if(part.done) break; size+=part.value.byteLength; if(size>LIMIT) throw new Error("source_too_large"); content+=decoder.decode(part.value,{stream:true}); } return JSON.parse(content+decoder.decode()); }
 finally { await reader.cancel().catch(()=>undefined); reader.releaseLock(); }
}
async function failure(db: WorkerEnv["DB"], source: Source, url: string, now: string, owner: string): Promise<void> {
 await fencedBatch(db, owner, [db.prepare("INSERT INTO source_state(source_id,source_url,last_attempt_at,last_error_code) VALUES(?,?,?,'enrichment_failed') ON CONFLICT(source_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(source,url,now)]);
}
// A 10 percentage-point absolute probability change is a signal, not a severity score.
export const EPSS_SIGNIFICANT_DELTA = 0.10;
async function store(db: WorkerEnv["DB"], source: Source, url: string, now: string, date: string | null, rows: {cve:string; data:unknown}[], owner: string): Promise<void> {
 const payload=JSON.stringify(rows);
 // All comparisons, history, current context and cursor advance share one fenced transaction.
 // json_each bounds this to a handful of D1 statements for the existing 500-CVE batch.
 const rowDate = "CASE WHEN ?='first_epss' THEN json_extract(j.value,'$.data.record.date') ELSE ? END";
 const observations=db.prepare(`INSERT INTO enrichment_observations(cve_id,source_id,source_url,observed_at,retrieved_at,source_date,data_json)
 SELECT json_extract(j.value,'$.cve'),?,?,?,?,${rowDate},json_extract(j.value,'$.data') FROM json_each(?) j
 LEFT JOIN vulnerability_context old ON old.cve_id=json_extract(j.value,'$.cve') AND old.source_id=?
 WHERE old.cve_id IS NULL OR old.data_json <> json_extract(j.value,'$.data')`).bind(source,url,now,now,source,date,payload,source);
 const membership=db.prepare(`INSERT INTO signal_events(cve_id,source_id,event_kind,source_url,observed_at,source_date,previous_json,current_json,threshold)
 SELECT json_extract(j.value,'$.cve'),?,'kev_membership_changed',?,?,?,old.data_json,json_extract(j.value,'$.data'),NULL
 FROM json_each(?) j JOIN vulnerability_context old ON old.cve_id=json_extract(j.value,'$.cve') AND old.source_id=?
 WHERE ?='cisa_kev' AND json_type(old.data_json,'$.listed') IN ('true','false')
 AND json_type(j.value,'$.data.listed') IN ('true','false')
 AND json_extract(old.data_json,'$.listed') <> json_extract(j.value,'$.data.listed')`).bind(source,url,now,date,payload,source,source);
 const epss=db.prepare(`INSERT INTO signal_events(cve_id,source_id,event_kind,source_url,observed_at,source_date,previous_json,current_json,threshold)
 SELECT json_extract(j.value,'$.cve'),?,'epss_significant_change',?,?,json_extract(j.value,'$.data.record.date'),old.data_json,json_extract(j.value,'$.data'),?
 FROM json_each(?) j JOIN enrichment_observations old ON old.sequence=(SELECT o.sequence FROM enrichment_observations o WHERE o.cve_id=json_extract(j.value,'$.cve') AND o.source_id=? AND json_extract(o.data_json,'$.available')=1 ORDER BY o.sequence DESC LIMIT 1)
 WHERE ?='first_epss' AND json_extract(j.value,'$.data.available')=1
 AND ROUND(ABS(CAST(json_extract(old.data_json,'$.record.epss') AS REAL)-CAST(json_extract(j.value,'$.data.record.epss') AS REAL)),9) >= ?
 AND (COALESCE(json_extract(old.data_json,'$.record.model_version'),json_extract(old.data_json,'$.record.modelVersion')) IS NULL OR COALESCE(json_extract(j.value,'$.data.record.model_version'),json_extract(j.value,'$.data.record.modelVersion')) IS NULL OR COALESCE(json_extract(old.data_json,'$.record.model_version'),json_extract(old.data_json,'$.record.modelVersion'))=COALESCE(json_extract(j.value,'$.data.record.model_version'),json_extract(j.value,'$.data.record.modelVersion')))`).bind(source,url,now,EPSS_SIGNIFICANT_DELTA,payload,source,source,EPSS_SIGNIFICANT_DELTA);
 const current=db.prepare(`INSERT INTO vulnerability_context(cve_id,source_id,retrieved_at,source_date,data_json)
 SELECT json_extract(j.value,'$.cve'),?,?,${rowDate},json_extract(j.value,'$.data') FROM json_each(?) j WHERE 1
 ON CONFLICT(cve_id,source_id) DO UPDATE SET retrieved_at=excluded.retrieved_at,source_date=excluded.source_date,data_json=excluded.data_json`).bind(source,now,source,date,payload);
 const progress=db.prepare("INSERT INTO enrichment_progress(source_id,last_cve) VALUES(?,?) ON CONFLICT(source_id) DO UPDATE SET last_cve=excluded.last_cve").bind(source,rows.at(-1)?.cve ?? "");
 const state=db.prepare("INSERT INTO source_state(source_id,source_url,last_attempt_at,last_success_at,source_content_date,last_error_code) VALUES(?,?,?,?,?,NULL) ON CONFLICT(source_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,source_content_date=excluded.source_content_date,last_error_code=NULL").bind(source,url,now,now,date);
 await fencedBatch(db, owner, [membership,epss,observations,current,progress,state]);
}
async function nextBatch(db: WorkerEnv["DB"], source: Source): Promise<string[]> {
 const progress = await db.prepare("SELECT last_cve FROM enrichment_progress WHERE source_id=?").bind(source).first<{last_cve:string}>();
 const fetchBatch = async (cursor: string) => (await db.prepare("SELECT DISTINCT cve_id FROM briefing_cves WHERE cve_id > ? ORDER BY cve_id LIMIT 500").bind(cursor).all<{cve_id:string}>()).results.map(row=>row.cve_id);
 const next=await fetchBatch(progress?.last_cve ?? "");
 return next.length ? next : (progress?.last_cve ? fetchBatch("") : []);
}
export async function enrich(db: WorkerEnv["DB"], owner: string, githubToken?:string): Promise<void> {
 const now = new Date().toISOString();
 const json=(url:string)=>readJsonSource(url,githubToken);
 try {
  // One bounded official download is shared by briefing enrichment and the full catalog.
  const data=obj(await json(KEV));
  // Validate the entire catalog before drawing any membership conclusion.
  // An empty or malformed feed cannot imply that tracked CVEs are not listed.
  const verified=validateKevCatalog(data);
  const byCve=new Map<string,Obj>(verified.records.map(row=>[row.cveID,row]));
  const cves=await nextBatch(db,"cisa_kev");
  if(cves.length) await store(db,"cisa_kev",KEV,now,typeof data.dateReleased === "string" ? data.dateReleased : null,cves.map(cve=>({cve,data:byCve.has(cve) ? {listed:true,record:byCve.get(cve),catalog_version:data.catalogVersion} : {listed:false,catalog_version:data.catalogVersion}})),owner);
  // Catalog health is independent: invalid detailed source records cannot replace
  // the last complete catalog or mark an incomplete staging generation current.
  try { await syncKevCatalog(db,owner,verified,now); }
  catch { await fencedBatch(db,owner,[db.prepare("INSERT INTO kev_catalog_state(singleton,last_error_code) VALUES(1,'catalog_refresh_failed') ON CONFLICT(singleton) DO UPDATE SET last_error_code='catalog_refresh_failed'")]); }
 } catch {
  await failure(db,"cisa_kev",KEV,now,owner);
  await fencedBatch(db,owner,[db.prepare("INSERT INTO kev_catalog_state(singleton,last_error_code) VALUES(1,'catalog_refresh_failed') ON CONFLICT(singleton) DO UPDATE SET last_error_code='catalog_refresh_failed'")]);
 }

 try {
  const cves=await nextBatch(db,"first_epss"); if(cves.length) {
  const rows: {cve:string;data:unknown}[]=[]; let sourceDate:string|null=null;
  for(let i=0;i<cves.length;i+=100) {
   const group=cves.slice(i,i+100); const url=`${EPSS}?cve=${encodeURIComponent(group.join(","))}`; const data=obj(await json(url));
   if(data.status !== "OK" || !Array.isArray(data.data) || !Number.isInteger(data.total) || data.total !== data.data.length) throw new Error("invalid_epss");
   const found=new Map<string,Obj>(); for(const value of data.data) { const row=obj(value); if(typeof row.cve !== "string" || !group.includes(row.cve) || found.has(row.cve) || typeof row.epss !== "string" || typeof row.percentile !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(String(row.date)) || !Number.isFinite(Number(row.epss)) || Number(row.epss) < 0 || Number(row.epss) > 1 || !Number.isFinite(Number(row.percentile)) || Number(row.percentile) < 0 || Number(row.percentile) > 1) throw new Error("invalid_epss_record"); found.set(row.cve,row); sourceDate=String(row.date); }
   for(const cve of group) rows.push({cve,data:found.has(cve) ? {available:true,record:found.get(cve)} : {available:false}});
  }
  await store(db,"first_epss",EPSS,now,sourceDate,rows,owner);
  }
 } catch { await failure(db,"first_epss",EPSS,now,owner); }
 await refreshEpssSeries(db,owner,now,json);
 await refreshPackages(db,owner,now,json);
}
