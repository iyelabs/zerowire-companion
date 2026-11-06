import { SourceHttpError } from './source-http-error.ts';
import type {WorkerEnv} from '../../cloudflare.config.ts';
import {fencedBatch} from './lease.ts';
import {normalizeGhsa,normalizeOsv,normalizeOsvCve,normalizeOsvRustsec,ghsaSemantic,type PackageAdvisory} from '../intelligence/package-advisories.ts';
type Db=WorkerEnv['DB'];
type Read=(url:string)=>Promise<unknown>;
const PER_PAGE=10;
const CACHE_HOURS=24;
const RETRY_HOURS=1;
const sourceError=(error:unknown)=>error instanceof SourceHttpError&&Number.isInteger(error.status)&&error.status>=400&&error.status<=599?`source_http_${error.status}`:'source_refresh_failed';
type RetryPolicy={failures:number;retry_not_before:string|null;suspended:number;reason:string|null};
async function retryPolicy(db:Db):Promise<RetryPolicy|null>{return db.prepare('SELECT failures,retry_not_before,suspended,reason FROM ghsa_retry_policy WHERE singleton=1').first<RetryPolicy>();}
function blocked(policy:RetryPolicy|null,now:string):boolean{return !!policy&&(policy.suspended===1 || !!policy.retry_not_before&&Date.parse(policy.retry_not_before)>Date.parse(now));}
async function recordGhsaFailure(db:Db,owner:string,now:string,error:unknown,statements:D1PreparedStatement[]):Promise<void>{
 if(!(error instanceof SourceHttpError)||![403,429].includes(error.status)){await fencedBatch(db,owner,statements);return;}
 const old=await retryPolicy(db),failures=(old?.failures??0)+1,meta=error.ghsa,reason=meta?.reason??'unknown';
 const base=Date.parse(now), delay=reason==='secondary_rate_limit'?Math.min(24,2**(failures-1))*3600000:reason==='primary_rate_limit'&&meta?.resetAt?60000:3600000;
 const retry=Math.max(base+delay,meta?.resetAt?Date.parse(meta.resetAt)+1000:0,meta?.retryAfterSeconds!==null&&meta?.retryAfterSeconds!==undefined?base+meta.retryAfterSeconds*1000:0);
 const suspended=reason==='forbidden'||failures>=5||!!meta?.invalidRetryAfter||(meta?.remaining===0&&!meta.resetAt);
 statements.push(db.prepare('INSERT INTO ghsa_retry_policy(singleton,failures,retry_not_before,suspended,reason,last_status,remaining,reset_at,retry_after_seconds) VALUES(1,?,?,?,?,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET failures=excluded.failures,retry_not_before=excluded.retry_not_before,suspended=excluded.suspended,reason=excluded.reason,last_status=excluded.last_status,remaining=excluded.remaining,reset_at=excluded.reset_at,retry_after_seconds=excluded.retry_after_seconds').bind(failures,new Date(retry).toISOString(),suspended?1:0,reason,error.status,meta?.remaining??null,meta?.resetAt??null,meta?.retryAfterSeconds??null));
 await fencedBatch(db,owner,statements);
}
function clearGhsaFailures(db:Db):D1PreparedStatement{return db.prepare('DELETE FROM ghsa_retry_policy WHERE singleton=1');}
function put(db:Db,record:PackageAdvisory,now:string){return db.prepare('INSERT INTO package_advisories(source,advisory_id,cve_id,source_url,published_at,modified_at,retrieved_at,normalized_json) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source,advisory_id,cve_id) DO UPDATE SET source_url=excluded.source_url,published_at=excluded.published_at,modified_at=excluded.modified_at,retrieved_at=excluded.retrieved_at,normalized_json=excluded.normalized_json').bind(record.source,record.id,record.cve,record.url,record.published,record.modified,now,JSON.stringify(record));}
function status(db:Db,source:string,cve:string,now:string,success:boolean,cursor:string|null,complete:boolean,scanStarted:string|null=null){return db.prepare('INSERT INTO package_source_state(source,cve_id,last_attempt_at,last_success_at,last_error_code,cursor,scan_started_at,coverage_complete) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source,cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=COALESCE(excluded.last_success_at,package_source_state.last_success_at),last_error_code=excluded.last_error_code,cursor=excluded.cursor,scan_started_at=excluded.scan_started_at,coverage_complete=excluded.coverage_complete').bind(source,cve,now,success?now:null,success?null:'source_refresh_failed',cursor,scanStarted,complete?1:0);}
/** Discover a bounded page of recently updated public GitHub advisories. */
async function refreshGhsaDiscovery(db:Db,owner:string,now:string,read:Read):Promise<void>{
 const policy=await retryPolicy(db);if(blocked(policy,now))return;
 const state=await db.prepare('SELECT baseline_at,last_attempt_at,last_error_code FROM package_feed_state WHERE singleton=1').first<{baseline_at:string|null;last_attempt_at:string|null;last_error_code:string|null}>();
 const interval=(state?.last_error_code?RETRY_HOURS:6)*3600000;
 if(!policy&&state?.last_attempt_at && Date.parse(now)-Date.parse(state.last_attempt_at)<interval)return;
 try {
  const raw=await read('https://api.github.com/advisories?type=reviewed&sort=updated&direction=desc&per_page=10');
  if(!Array.isArray(raw)||raw.length>10)throw new Error('invalid_ghsa_feed');
  const records:PackageAdvisory[]=[];
  for(const entry of raw){if(!entry || typeof entry!=='object')throw new Error('invalid_ghsa_feed');const cve=(entry as Record<string,unknown>).cve_id;if(cve===null)continue;if(typeof cve!=='string'||!/^CVE-\d{4}-\d{4,}$/.test(cve))throw new Error('invalid_ghsa_feed');records.push(...normalizeGhsa([entry],cve));}
  const statements:D1PreparedStatement[]=[];
  for(const record of records){
   const previous=await db.prepare("SELECT normalized_json FROM package_advisories WHERE source='ghsa' AND advisory_id=? AND cve_id=?").bind(record.id,record.cve).first<{normalized_json:string}>();
   if(state?.baseline_at && (!previous||ghsaSemantic(JSON.parse(previous.normalized_json))!==ghsaSemantic(record))) statements.push(db.prepare("INSERT INTO package_advisory_events(source,advisory_id,cve_id,event_kind,observed_at,source_date,source_url) VALUES('ghsa',?,?,?,?,?,?)").bind(record.id,record.cve,previous?'advisory.changed':'advisory.first_observed',now,record.modified,record.url));
   statements.push(put(db,record,now));
  }
  statements.push(db.prepare("INSERT INTO package_feed_state(singleton,baseline_at,last_attempt_at,last_success_at,last_error_code) VALUES(1,?,?,?,NULL) ON CONFLICT(singleton) DO UPDATE SET baseline_at=COALESCE(package_feed_state.baseline_at,excluded.baseline_at),last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,last_error_code=NULL").bind(now,now,now));
  await fencedBatch(db,owner,statements);
 } catch(error) {const code=sourceError(error);await recordGhsaFailure(db,owner,now,error,[db.prepare("INSERT INTO package_feed_state(singleton,last_attempt_at,last_error_code) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(now,code)]);}
}
/** Independent, bounded scheduled refresh. The public MCP path never calls it. */
export async function refreshPackages(db:Db,owner:string,now:string,read:Read):Promise<void>{
 await refreshGhsaDiscovery(db,owner,now,read);
 const feed=await db.prepare('SELECT last_attempt_at,last_success_at,last_error_code FROM package_feed_state WHERE singleton=1').first<{last_attempt_at:string|null;last_success_at:string|null;last_error_code:string|null}>();
 const policy=await retryPolicy(db);const throttled=blocked(policy,now)||!policy&&!!feed?.last_attempt_at&&['source_http_403','source_http_429'].includes(feed.last_error_code??'')&&Date.parse(now)-Date.parse(feed.last_attempt_at)<RETRY_HOURS*3600000;
 const stale=new Date(Date.parse(now)-CACHE_HOURS*3600000).toISOString();const retry=new Date(Date.parse(now)-(policy?0:RETRY_HOURS*3600000)).toISOString();
 const recent=new Date(Date.parse(now)-30*86400000).toISOString();const fairness=Math.floor(Date.parse(now)/3600000)%4===0?1:0;
 const candidate=throttled?null:await db.prepare(`WITH candidates AS (SELECT DISTINCT cve_id,0 AS priority FROM briefing_cves UNION ALL SELECT cve_id,1 AS priority FROM kev_catalog WHERE date_added>=? UNION ALL SELECT cve_id,2 AS priority FROM package_advisories WHERE source='ghsa' AND modified_at>=? UNION ALL SELECT cve_id,3 AS priority FROM package_source_state WHERE source='ghsa' UNION ALL SELECT cve_id,4 AS priority FROM kev_catalog), ranked AS (SELECT cve_id,MIN(priority) AS priority FROM candidates GROUP BY cve_id) SELECT r.cve_id,s.cursor,s.scan_started_at FROM ranked r LEFT JOIN package_source_state s ON s.source='ghsa' AND s.cve_id=r.cve_id WHERE (s.last_success_at IS NULL OR s.last_success_at<? OR s.coverage_complete=0) AND (s.last_attempt_at IS NULL OR s.last_attempt_at<? OR (s.last_error_code IN ('source_http_403','source_http_429') AND s.last_attempt_at<?)) ORDER BY CASE WHEN s.last_error_code IN ('source_http_403','source_http_429') THEN 0 ELSE 1 END,CASE WHEN ?=1 THEN COALESCE(s.last_attempt_at,'') ELSE '' END,CASE WHEN ?=1 THEN COALESCE((SELECT date_added FROM kev_catalog WHERE cve_id=r.cve_id),'9999-12-31') ELSE '' END,r.priority,COALESCE(s.last_attempt_at,''),r.cve_id LIMIT 1`).bind(recent.slice(0,10),recent,stale,retry,feed?.last_success_at??'',fairness,fairness).first<{cve_id:string;cursor:string|null;scan_started_at:string|null}>();
 if(candidate){const cve=candidate.cve_id;const page=candidate.cursor?Number(candidate.cursor):1;if(!Number.isInteger(page)||page<1||page>1000)throw new Error("invalid_ghsa_cursor");const scanStarted=candidate.scan_started_at??now;try{
  const items=normalizeGhsa(await read(`https://api.github.com/advisories?cve_id=${encodeURIComponent(cve)}&per_page=${PER_PAGE}&page=${page}`),cve);
  // Retain the previous cache until a full paginated scan completes.
  const complete=items.length<PER_PAGE;
  const statements:D1PreparedStatement[]=[];
  for(const item of items){
   const previous=await db.prepare("SELECT normalized_json FROM package_advisories WHERE source='ghsa' AND advisory_id=? AND cve_id=?").bind(item.id,item.cve).first<{normalized_json:string}>();
   const feedState=await db.prepare('SELECT baseline_at FROM package_feed_state WHERE singleton=1').first<{baseline_at:string|null}>();
   if(feedState?.baseline_at && feedState.baseline_at<now && (!previous||ghsaSemantic(JSON.parse(previous.normalized_json))!==ghsaSemantic(item))) statements.push(db.prepare("INSERT INTO package_advisory_events(source,advisory_id,cve_id,event_kind,observed_at,source_date,source_url) VALUES('ghsa',?,?,?,?,?,?)").bind(item.id,item.cve,previous?'advisory.changed':'advisory.first_observed',now,item.modified,item.url));
   statements.push(put(db,item,now));
  }
  if(complete)statements.push(db.prepare("DELETE FROM package_advisories WHERE source='ghsa' AND cve_id=? AND retrieved_at<?").bind(cve,scanStarted));
  statements.push(status(db,'ghsa',cve,now,true,complete?null:String(page+1),complete,complete?null:scanStarted),clearGhsaFailures(db));await fencedBatch(db,owner,statements);
 }catch(error){const code=sourceError(error);const statements=[db.prepare("INSERT INTO package_source_state(source,cve_id,last_attempt_at,last_error_code) VALUES('ghsa',?,?,?) ON CONFLICT(source,cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(cve,now,code)];if(code==='source_http_403'||code==='source_http_429')statements.push(db.prepare("INSERT INTO package_feed_state(singleton,last_attempt_at,last_error_code) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(now,code));await recordGhsaFailure(db,owner,now,error,statements);}}
 // Native CVE identifiers are looked up independently of GHSA aliases. A failed
 // lookup records unknown coverage and never replaces an earlier valid record.
 const native=await db.prepare(`WITH candidates AS (SELECT cve_id,0 AS priority FROM briefing_cves UNION ALL SELECT cve_id,1 AS priority FROM kev_catalog WHERE date_added>=? UNION ALL SELECT cve_id,2 AS priority FROM package_advisories WHERE source='ghsa' AND modified_at>=? UNION ALL SELECT cve_id,3 AS priority FROM osv_cve_state WHERE last_success_at IS NOT NULL UNION ALL SELECT cve_id,4 AS priority FROM kev_catalog), ranked AS (SELECT cve_id,MIN(priority) AS priority FROM candidates GROUP BY cve_id) SELECT r.cve_id FROM ranked r LEFT JOIN osv_cve_state s ON s.cve_id=r.cve_id WHERE (s.last_success_at IS NULL OR s.last_success_at<?) AND (s.last_attempt_at IS NULL OR s.last_attempt_at<?) ORDER BY CASE WHEN ?=1 THEN COALESCE(s.last_attempt_at,'') ELSE '' END,CASE WHEN ?=1 THEN COALESCE((SELECT date_added FROM kev_catalog WHERE cve_id=r.cve_id),'9999-12-31') ELSE '' END,r.priority,COALESCE(s.last_attempt_at,''),r.cve_id LIMIT 1`).bind(recent.slice(0,10),recent,stale,retry,fairness,fairness).first<{cve_id:string}>();
 if(native){
  try{
   const raw=await read(`https://api.osv.dev/v1/vulns/${encodeURIComponent(native.cve_id)}`);
   const item=raw&&typeof raw==='object'&&!Array.isArray(raw)?raw as Record<string,unknown>:{};
   if(item.id===native.cve_id&&typeof item.withdrawn==='string'&&Number.isFinite(Date.parse(item.withdrawn))){
    await fencedBatch(db,owner,[db.prepare("DELETE FROM package_advisories WHERE source='osv' AND advisory_id=? AND cve_id=?").bind(native.cve_id,native.cve_id),db.prepare("INSERT INTO osv_cve_state(cve_id,last_attempt_at,last_success_at,last_error_code) VALUES(?,?,?,'record_withdrawn') ON CONFLICT(cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,last_error_code=excluded.last_error_code").bind(native.cve_id,now,now)]);
   }else{
    const record=normalizeOsvCve(raw,native.cve_id);
    await fencedBatch(db,owner,[put(db,record,now),...(record.aliases??[]).filter(id=>id.length<=40&&(/^RUSTSEC-\d{4}-\d{4,}$/.test(id)||/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(id))).map(id=>db.prepare('INSERT INTO osv_alias_queue(cve_id,advisory_id) VALUES(?,?) ON CONFLICT(cve_id,advisory_id) DO NOTHING').bind(native.cve_id,id)),db.prepare('INSERT INTO osv_cve_state(cve_id,last_attempt_at,last_success_at,last_error_code) VALUES(?,?,?,NULL) ON CONFLICT(cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,last_error_code=NULL').bind(native.cve_id,now,now)]);
   }
  }catch(error){
   if(error instanceof SourceHttpError && error.status===404){
    // A verified 404 is a dated absence of this exact native identifier, not an
    // outage or proof that other OSV records and aliases do not exist. Keep any
    // previously retrieved advisory with its original retrieval timestamp.
    await fencedBatch(db,owner,[db.prepare("INSERT INTO osv_cve_state(cve_id,last_attempt_at,last_success_at,last_error_code) VALUES(?,?,?,'record_not_found') ON CONFLICT(cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,last_error_code=excluded.last_error_code").bind(native.cve_id,now,now)]);
   }else await fencedBatch(db,owner,[db.prepare("INSERT INTO osv_cve_state(cve_id,last_attempt_at,last_error_code) VALUES(?,?,'source_refresh_failed') ON CONFLICT(cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(native.cve_id,now)]);
  }
 }
 // Backfill one native CVE already cached before alias discovery was enabled.
 // An indexed scan cursor ensures every old row is considered once.
 const unscanned=await db.prepare("SELECT s.cve_id,a.normalized_json FROM osv_cve_state s JOIN package_advisories a ON a.source='osv' AND a.cve_id=s.cve_id AND a.advisory_id=s.cve_id WHERE s.alias_scan_at IS NULL ORDER BY s.cve_id LIMIT 1").first<{cve_id:string;normalized_json:string}>();
 if(unscanned){const data=JSON.parse(unscanned.normalized_json) as {aliases?:unknown};const ids=Array.isArray(data.aliases)?data.aliases.filter((id):id is string=>typeof id==='string'&&id.length<=40&&(/^RUSTSEC-\d{4}-\d{4,}$/.test(id)||/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/.test(id))):[];await fencedBatch(db,owner,[...ids.slice(0,20).map(id=>db.prepare('INSERT INTO osv_alias_queue(cve_id,advisory_id) VALUES(?,?) ON CONFLICT(cve_id,advisory_id) DO NOTHING').bind(unscanned.cve_id,id)),db.prepare('UPDATE osv_cve_state SET alias_scan_at=? WHERE cve_id=?').bind(now,unscanned.cve_id)]);}
 // Fetch one queued verified source alias independently of the GitHub API.
 const alias=await db.prepare("SELECT cve_id,advisory_id FROM osv_alias_queue WHERE (last_success_at IS NULL OR last_success_at<?) AND (last_attempt_at IS NULL OR last_attempt_at<?) ORDER BY COALESCE(last_attempt_at,''),cve_id,advisory_id LIMIT 1").bind(stale,retry).first<{cve_id:string;advisory_id:string}>();
 if(alias){try{
  const raw=await read(`https://api.osv.dev/v1/vulns/${encodeURIComponent(alias.advisory_id)}`);
  const record=alias.advisory_id.startsWith('GHSA-')?normalizeOsv(raw,alias.cve_id,alias.advisory_id):normalizeOsvRustsec(raw,alias.cve_id,alias.advisory_id);
  await fencedBatch(db,owner,[put(db,record,now),db.prepare("UPDATE osv_alias_queue SET last_attempt_at=?,last_success_at=?,last_error_code=NULL WHERE cve_id=? AND advisory_id=?").bind(now,now,alias.cve_id,alias.advisory_id)]);
 }catch{await fencedBatch(db,owner,[db.prepare("UPDATE osv_alias_queue SET last_attempt_at=?,last_error_code='source_refresh_failed' WHERE cve_id=? AND advisory_id=?").bind(now,alias.cve_id,alias.advisory_id)]);}}
 // OSV runs even if GHSA is temporarily unavailable, using known cached aliases.
 const osvcandidate=await db.prepare(`SELECT a.cve_id,s.cursor FROM package_advisories a LEFT JOIN package_source_state s ON s.source='osv' AND s.cve_id=a.cve_id WHERE a.source='ghsa' AND (s.last_success_at IS NULL OR s.last_success_at<? OR s.coverage_complete=0) AND (s.last_attempt_at IS NULL OR s.last_attempt_at<?) GROUP BY a.cve_id ORDER BY COALESCE(s.last_attempt_at,''),a.cve_id LIMIT 1`).bind(stale,retry).first<{cve_id:string;cursor:string|null}>();
 if(!osvcandidate)return;
 const cve=osvcandidate.cve_id,cursor=osvcandidate.cursor??'';
 const ids=(await db.prepare("SELECT advisory_id FROM package_advisories WHERE source='ghsa' AND cve_id=? AND advisory_id>? ORDER BY advisory_id LIMIT 3").bind(cve,cursor).all<{advisory_id:string}>()).results;
 if(!ids.length){await fencedBatch(db,owner,[status(db,'osv',cve,now,true,null,true)]);return;}
 try{
  const rows:PackageAdvisory[]=[];for(const {advisory_id:id} of ids)rows.push(normalizeOsv(await read(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`),cve,id));
  const last=ids.at(-1)!.advisory_id;const more=await db.prepare("SELECT advisory_id FROM package_advisories WHERE source='ghsa' AND cve_id=? AND advisory_id>? ORDER BY advisory_id LIMIT 1").bind(cve,last).first();
  await fencedBatch(db,owner,[...rows.map(x=>put(db,x,now)),status(db,'osv',cve,now,true,more?last:null,!more)]);
 }catch{await fencedBatch(db,owner,[db.prepare("INSERT INTO package_source_state(source,cve_id,last_attempt_at,last_error_code,cursor) VALUES('osv',?,?,'source_refresh_failed',?) ON CONFLICT(source,cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(cve,now,cursor)]);}
}
