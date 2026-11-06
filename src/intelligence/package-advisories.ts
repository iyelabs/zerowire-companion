type Obj=Record<string,unknown>;
const obj=(v:unknown):Obj=>v&&typeof v==='object'&&!Array.isArray(v)?v as Obj:{};
const str=(v:unknown,max=500):string|null=>typeof v==='string'&&v.length<=max?v:null;
const rustsecPattern=/^RUSTSEC-\d{4}-\d{4,}$/;
const ghsaPattern=/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/;
export interface PackageAdvisory {source:'ghsa'|'osv';id:string;cve:string;url:string;published:string|null;modified:string|null;packages:unknown[];truncated:boolean;aliases?:string[];upstream_source?:string;withdrawn_at?:string|null}
export function normalizeGhsa(value:unknown,cve:string):PackageAdvisory[] {
 if(!Array.isArray(value)||value.length>30)throw new Error('invalid_ghsa_response');
 return value.map(raw=>{const row=obj(raw);const id=str(row.ghsa_id,40);if(!id||!ghsaPattern.test(id)||row.cve_id!==cve||!Array.isArray(row.vulnerabilities))throw new Error('invalid_ghsa_advisory');
  const withdrawn=str(row.withdrawn_at,60);if(row.withdrawn_at && (!withdrawn||!Number.isFinite(Date.parse(withdrawn))))throw new Error('invalid_ghsa_withdrawal');
  const packages=row.vulnerabilities.slice(0,20).map(v=>{const r=obj(v),p=obj(r.package);return {ecosystem:str(p.ecosystem,100),name:str(p.name,300),affected_range:str(r.vulnerable_version_range,500),first_patched_version:str(r.first_patched_version,100)};});
  return {source:'ghsa' as const,id,cve,url:`https://github.com/advisories/${id}`,published:str(row.published_at,60),modified:str(row.updated_at,60),withdrawn_at:withdrawn,packages:withdrawn?[]:packages,truncated:row.vulnerabilities.length>20};
 });
}
export function normalizeOsv(value:unknown,cve:string,expectedId:string):PackageAdvisory {
 const row=obj(value);if(!ghsaPattern.test(expectedId)||row.id!==expectedId||!Array.isArray(row.aliases)||!row.aliases.includes(cve)||!Array.isArray(row.affected))throw new Error('invalid_osv_advisory');
 // Initial scope accepts only OSV records tracing back to GitHub's advisory database.
 // OSV aggregates records under different upstream terms; do not assume one license.
 const withdrawn=str(row.withdrawn,60);if(row.withdrawn && (!withdrawn || !Number.isFinite(Date.parse(withdrawn))))throw new Error('invalid_osv_withdrawal');
 const sources=row.affected.map(a=>str(obj(obj(a).database_specific).source,1024));
 if(sources.some(source=>{try{const u=new URL(source??'');return u.protocol!=='https:'||u.hostname!=='github.com'||!u.pathname.startsWith('/github/advisory-database/blob/')||!u.pathname.endsWith('/'+expectedId+'.json')}catch{return true}}))throw new Error('osv_source_rights_unverified');
 const packages=row.affected.slice(0,20).map(a=>{const r=obj(a),p=obj(r.package);const ranges=Array.isArray(r.ranges)?r.ranges.slice(0,10).map(raw=>{const range=obj(raw);const events=Array.isArray(range.events)?range.events.slice(0,30).map(e=>{const value=obj(e);return {introduced:str(value.introduced,100),fixed:str(value.fixed,100),last_affected:str(value.last_affected,100),limit:str(value.limit,100)}}):[];return {type:str(range.type,30),events,truncated:Array.isArray(range.events)&&range.events.length>30}}):[];return {ecosystem:str(p.ecosystem,100),name:str(p.name,300),ranges,truncated:Array.isArray(r.ranges)&&r.ranges.length>10};});
 return {source:'osv',id:expectedId,cve,url:`https://osv.dev/vulnerability/${expectedId}`,published:str(row.published,60),modified:str(row.modified,60),withdrawn_at:withdrawn,packages:withdrawn?[]:packages,truncated:row.affected.length>20,aliases:[cve],...(sources[0]?{upstream_source:sources[0]}:{})};
}

/** Accept only the OSV native CVE conversion with an attributable source. */
export function normalizeOsvCve(value:unknown,cve:string):PackageAdvisory {
 const row=obj(value);
 if(!/^CVE-\d{4}-\d{4,}$/.test(cve)||row.id!==cve||!Array.isArray(row.affected))throw new Error('invalid_osv_cve');
 if(row.withdrawn)throw new Error('osv_cve_withdrawn');
 const expected=`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`;
 if(!row.affected.length||row.affected.some(a=>obj(obj(a).database_specific).source!==expected))throw new Error('osv_source_rights_unverified');
 const packages=row.affected.slice(0,20).map(a=>{
  const item=obj(a),pkg=obj(item.package);
  const ranges=Array.isArray(item.ranges)?item.ranges.slice(0,10).map(raw=>{const range=obj(raw);const events=Array.isArray(range.events)?range.events.slice(0,30).map(event=>{const e=obj(event);return {introduced:str(e.introduced,100),fixed:str(e.fixed,100),last_affected:str(e.last_affected,100),limit:str(e.limit,100)}}):[];return {type:str(range.type,30),events,truncated:Array.isArray(range.events)&&range.events.length>30};}):[];
  return {ecosystem:str(pkg.ecosystem,100),name:str(pkg.name,300),ranges,truncated:Array.isArray(item.ranges)&&item.ranges.length>10};
 });
 return {source:'osv',id:cve,cve,url:`https://osv.dev/vulnerability/${cve}`,published:str(row.published,60),modified:str(row.modified,60),packages,truncated:row.affected.length>20,aliases:Array.isArray(row.aliases)?row.aliases.filter((x):x is string=>typeof x==='string'&&x.length<=40&&(ghsaPattern.test(x)||rustsecPattern.test(x))).slice(0,20):[],upstream_source:expected};
}

/** Compare security-bearing GHSA fields; source dates and presentation order are metadata. */
export function ghsaSemantic(value:unknown):string {
 const item=obj(value);if(!Array.isArray(item.packages))throw new Error('ghsa_comparison_unavailable');
 const packages=item.packages.map(value=>{const p=obj(value);return JSON.stringify({ecosystem:str(p.ecosystem,100),name:str(p.name,300),affected_range:str(p.affected_range,500),first_patched_version:str(p.first_patched_version,100)});}).sort();
 return JSON.stringify({withdrawn_at:str(item.withdrawn_at,60),packages,truncated:item.truncated===true,source_modified_if_truncated:item.truncated===true?str(item.modified,60):null});
}

/** Selected OSV RustSec aliases: only records traceable to RustSec's own export. */
export function normalizeOsvRustsec(value:unknown,cve:string,id:string):PackageAdvisory {
 const row=obj(value);if(id.length>40||!rustsecPattern.test(id)||row.id!==id||!/^CVE-\d{4}-\d{4,}$/.test(cve)||!Array.isArray(row.aliases)||!row.aliases.includes(cve)||!Array.isArray(row.affected))throw new Error('invalid_rustsec_advisory');
 const withdrawn=str(row.withdrawn,60);if(row.withdrawn&&(!withdrawn||!Number.isFinite(Date.parse(withdrawn))))throw new Error('invalid_osv_withdrawal');
 const expected=`https://github.com/rustsec/advisory-db/blob/osv/crates/${id}.json`;
 if(!withdrawn&&(!row.affected.length||row.affected.some(a=>obj(obj(a).database_specific).source!==expected)))throw new Error('osv_source_rights_unverified');
 const packages=row.affected.slice(0,20).map(a=>{const r=obj(a),p=obj(r.package);const ranges=Array.isArray(r.ranges)?r.ranges.slice(0,10).map(raw=>{const range=obj(raw);const events=Array.isArray(range.events)?range.events.slice(0,30).map(e=>{const v=obj(e);return {introduced:str(v.introduced,100),fixed:str(v.fixed,100),last_affected:str(v.last_affected,100),limit:str(v.limit,100)}}):[];return {type:str(range.type,30),events,truncated:Array.isArray(range.events)&&range.events.length>30};}):[];return {ecosystem:str(p.ecosystem,100),name:str(p.name,300),ranges,truncated:Array.isArray(r.ranges)&&r.ranges.length>10};});
 return {source:'osv',id,cve,url:`https://osv.dev/vulnerability/${id}`,published:str(row.published,60),modified:str(row.modified,60),withdrawn_at:withdrawn,packages:withdrawn?[]:packages,truncated:row.affected.length>20,aliases:row.aliases.filter((x):x is string=>typeof x==='string'&&(x===cve||ghsaPattern.test(x))).slice(0,20),upstream_source:expected};
}
