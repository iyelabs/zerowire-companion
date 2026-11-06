/** Normalize FIRST-published 30-day history. Never infer local historical events. */
export interface EpssPoint { date:string; probability:number; percentile:number }
export interface EpssSeries { cve:string; points:EpssPoint[]; modelVersion:string|null }
const obj=(x:unknown):Record<string,unknown>|null=>x && typeof x==='object' && !Array.isArray(x)?x as Record<string,unknown>:null;
function point(value:unknown):EpssPoint {
 const row=obj(value);const date=row?.date;const e=row?.epss;const p=row?.percentile;
 if(typeof date!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(Date.parse(date+'T00:00:00Z'))||new Date(date+'T00:00:00Z').toISOString().slice(0,10)!==date||typeof e!=='string'||!e.trim()||typeof p!=='string'||!p.trim())throw new Error('invalid_epss_point');
 const probability=Number(e),percentile=Number(p);if(!Number.isFinite(probability)||probability<0||probability>1||!Number.isFinite(percentile)||percentile<0||percentile>1)throw new Error('invalid_epss_point');
 return {date,probability,percentile};
}
export function parseEpssSeries(input:unknown,cve:string):EpssSeries|null {
 const data=obj(input);if(data?.status!=='OK'||!Array.isArray(data.data)||!Number.isInteger(data.total)||data.total!==data.data.length||data.data.length>1)throw new Error('invalid_epss_response');
 if(!data.data.length)return null;
 const row=obj(data.data[0]);if(!row||row.cve!==cve)throw new Error('invalid_epss_series');
 // FIRST omits time-series entirely when it has no earlier score for a CVE.
 // A missing field is different from a malformed present value.
 const history=row['time-series'];if(history!==undefined&&(!Array.isArray(history)||history.length>30))throw new Error('invalid_epss_series');
 const all=[point(row),...(history??[] as unknown[]).map(point)];const byDate=new Map<string,EpssPoint>();
 for(const entry of all){const old=byDate.get(entry.date);if(old&&(old.probability!==entry.probability||old.percentile!==entry.percentile))throw new Error('conflicting_epss_date');byDate.set(entry.date,entry);}
 const points=[...byDate.values()].sort((a,b)=>b.date.localeCompare(a.date)).slice(0,30);
 return {cve,points,modelVersion:typeof row.modelVersion==='string'?row.modelVersion:typeof row.model_version==='string'?row.model_version:null};
}
