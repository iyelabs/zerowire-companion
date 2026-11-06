import type {WorkerEnv} from '../../cloudflare.config.ts';
import {fencedBatch} from './lease.ts';
import {parseEpssSeries} from '../intelligence/epss-series.ts';
const ENDPOINT='https://api.first.org/data/v1/epss';
const MAX_PER_RUN=10;
const MAX_CONCURRENT=5;
const REFRESH_MS=24*60*60*1000;
const RETRY_MS=60*60*1000;
type Db=WorkerEnv['DB'];
/** Refresh at most ten tracked series per run; briefing CVEs get priority. */
export async function refreshEpssSeries(db:Db,owner:string,now:string,read:(url:string)=>Promise<unknown>):Promise<void>{
 const before=new Date(Date.parse(now)-REFRESH_MS).toISOString();
 const retryBefore=new Date(Date.parse(now)-RETRY_MS).toISOString();
 // The pool is bounded to known CVEs; successful and unavailable responses both
 // receive a retrieval timestamp so missing source data cannot starve the queue.
 const recent=new Date(Date.parse(now)-30*86400000).toISOString().slice(0,10);
 const candidates=await db.prepare(`WITH candidates AS (
   SELECT DISTINCT cve_id,0 AS priority FROM briefing_cves
   UNION ALL SELECT cve_id,1 AS priority FROM kev_catalog WHERE date_added>=?
   UNION ALL SELECT cve_id,2 AS priority FROM package_advisories WHERE source='ghsa' AND modified_at>=?
   UNION ALL SELECT cve_id,3 AS priority FROM epss_series
   UNION ALL SELECT cve_id,4 AS priority FROM kev_catalog
  ), ranked AS (SELECT cve_id,MIN(priority) AS priority FROM candidates GROUP BY cve_id), eligible AS (
   SELECT r.cve_id,r.priority,COALESCE(a.last_attempt_at,'') AS attempted,COALESCE(s.retrieved_at,'') AS retrieved,COALESCE(k.date_added,'9999-12-31') AS catalog_date
   FROM ranked r LEFT JOIN kev_catalog k ON k.cve_id=r.cve_id LEFT JOIN epss_series s ON s.cve_id=r.cve_id LEFT JOIN epss_series_attempts a ON a.cve_id=r.cve_id
   WHERE (s.retrieved_at IS NULL OR s.retrieved_at<?) AND (a.last_attempt_at IS NULL OR a.last_attempt_at<=?)
  ), ordered AS (SELECT *,ROW_NUMBER() OVER (ORDER BY priority,attempted,retrieved,cve_id) AS preferred,
   ROW_NUMBER() OVER (ORDER BY attempted,retrieved,catalog_date,priority,cve_id) AS fairness FROM eligible)
  SELECT cve_id FROM ordered ORDER BY CASE WHEN preferred<=9 THEN 0 ELSE 1 END,
   CASE WHEN preferred<=9 THEN preferred ELSE fairness END LIMIT ?`).bind(recent,new Date(Date.parse(now)-30*86400000).toISOString(),before,retryBefore,MAX_PER_RUN).all<{cve_id:string}>();
 if(!candidates.results.length)return;
 const results:{cve:string;series:ReturnType<typeof parseEpssSeries>;failed:boolean}[]=[];
 for(let i=0;i<candidates.results.length;i+=MAX_CONCURRENT){
  const group=await Promise.all(candidates.results.slice(i,i+MAX_CONCURRENT).map(async ({cve_id:cve})=>{
   try{return {cve,series:parseEpssSeries(await read(`${ENDPOINT}?cve=${encodeURIComponent(cve)}&scope=time-series`),cve),failed:false}}
   catch{return {cve,series:null,failed:true}}
  }));
  results.push(...group);
 }
 const statements:D1PreparedStatement[]=[];
 for(const result of results){
  statements.push(db.prepare("INSERT INTO epss_series_attempts(cve_id,last_attempt_at,last_error_code) VALUES(?,?,?) ON CONFLICT(cve_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(result.cve,now,result.failed?'series_refresh_failed':null));
  if(result.failed)continue;
  const series=result.series;
  const latest=series?.points[0];
  if(latest){
   // Briefing CVEs already produce signals in the main enrichment batch.
   // For catalog-only CVEs compare two actual local observations, never the
   // source's older historical points. A known model change suppresses comparison.
   const current=JSON.stringify({available:true,record:{epss:String(latest.probability),percentile:String(latest.percentile),date:latest.date,model_version:series?.modelVersion??null}});
   statements.push(db.prepare(`INSERT INTO signal_events(cve_id,source_id,event_kind,source_url,observed_at,source_date,previous_json,current_json,threshold)
    SELECT s.cve_id,'first_epss','epss_significant_change',?, ?, ?,
     json_object('available',json('true'),'record',json_object('epss',CAST(json_extract(s.observations_json,'$[0].probability') AS TEXT),'percentile',CAST(json_extract(s.observations_json,'$[0].percentile') AS TEXT),'date',s.latest_date,'model_version',s.model_version)), ?, 0.1
    FROM epss_series s WHERE s.cve_id=? AND s.latest_date<?
     AND json_type(s.observations_json,'$[0].probability') IN ('real','integer')
     AND ROUND(ABS(json_extract(s.observations_json,'$[0].probability')-?),9)>=0.1
     AND (s.model_version IS NULL OR ? IS NULL OR s.model_version=?)
     AND NOT EXISTS(SELECT 1 FROM briefing_cves b WHERE b.cve_id=s.cve_id)`).bind(ENDPOINT,now,latest.date,current,result.cve,latest.date,latest.probability,series?.modelVersion??null,series?.modelVersion??null));
  }
  statements.push(db.prepare('INSERT INTO epss_series(cve_id,retrieved_at,latest_date,observations_json,source_url,model_version) VALUES(?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET retrieved_at=excluded.retrieved_at,latest_date=excluded.latest_date,observations_json=excluded.observations_json,source_url=excluded.source_url,model_version=excluded.model_version').bind(result.cve,now,series?.points[0]?.date??null,JSON.stringify(series?.points??[]),ENDPOINT,series?.modelVersion??null));
 }
 const failed=results.some(x=>x.failed),succeeded=results.some(x=>!x.failed);
 statements.push(db.prepare("INSERT INTO epss_series_progress(singleton,last_cve,last_attempt_at,last_success_at,last_error_code) VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET last_cve=excluded.last_cve,last_attempt_at=excluded.last_attempt_at,last_success_at=COALESCE(excluded.last_success_at,epss_series_progress.last_success_at),last_error_code=excluded.last_error_code").bind(results.at(-1)!.cve,now,succeeded?now:null,failed?'series_refresh_failed':null));
 // Persistence errors are not source failures: do not mask a lost lease or a
 // transaction failure as a healthy sync.
 await fencedBatch(db,owner,statements);
}
