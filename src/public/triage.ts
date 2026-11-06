import { assessmentPrompt } from '../shared/assessment-prompt.ts';
import { semanticSections } from "../shared/sections.ts";
import type { ReadQueries } from "./queries.ts";

type Row = Record<string,unknown>;
type SectionName = "overview" | "what_happened" | "why_it_matters" | "affected_scope" | "recommended_actions" | "source_chronology" | "other_sections" | "assessment_prompt";
const allSections:SectionName[]=["overview","what_happened","why_it_matters","affected_scope","recommended_actions","source_chronology","assessment_prompt"];
function clip(value:unknown, bytes:number): {text:string|null;truncated:boolean} {
 if(typeof value!=="string")return {text:null,truncated:false};
 const encoded=new TextEncoder().encode(value);
 return {text:encoded.length<=bytes?value:new TextDecoder().decode(encoded.subarray(0,bytes),{stream:true}),truncated:encoded.length>bytes};
}
const object=(value:unknown):Row=>value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const parse=(value:unknown):Row=>typeof value === "string" ? object(JSON.parse(value)) : {};
export function compactContext(source:string, raw:unknown): Row {
 const data=parse(raw);const record=object(data.record);const truncated:string[]=[];
 const value=(name:string,x:unknown,max:number):string|null=>{const result=clip(x,max);if(result.truncated)truncated.push(name);return result.truncated?null:result.text;};
 if(source==="cisa_kev")return {listed:typeof data.listed==="boolean"?data.listed:null,catalog_version:value("catalog_version",data.catalog_version,100),date_added:value("date_added",record.dateAdded,50),truncated_fields:truncated};
 return {available:typeof data.available==="boolean"?data.available:null,probability:value("probability",record.epss,32),percentile:value("percentile",record.percentile,32),score_date:value("score_date",record.date,50),model_version:value("model_version",record.model_version ?? record.modelVersion,100),truncated_fields:truncated};
}
function recentEpss(row:Row|null):Row {
 if(!row)return {availability:"not_cached",points:[],source_url:"https://api.first.org/data/v1/epss",note:"No locally cached 30-day series; this does not mean the score is zero."};
 const points=typeof row.observations_json==="string"?JSON.parse(row.observations_json) as {date:string;probability:number;percentile:number}[]:[];
 const latest=points[0]??null,earliest=points.at(-1)??null;
 const movement=points.length>=2&&latest&&earliest?Math.round((latest.probability-earliest.probability)*10000)/100:null;
 return {availability:points.length?"available":row.last_error_code?"refresh_failed_no_cache":"unavailable_from_source",last_attempt_at:row.last_attempt_at??null,last_error_code:row.last_error_code??null,latest,earliest,points,absolute_percentage_point_change:movement,source_date:row.latest_date,retrieved_at:row.retrieved_at,source_url:row.source_url??"https://api.first.org/data/v1/epss",model_version:row.model_version,source_history_kind:"FIRST reported dates; not local observations",note:points.length===1?"A single score does not establish a trend. EPSS is not severity, confirmed exploitation or the probability this environment is compromised.":"EPSS is not severity, confirmed exploitation or the probability this environment is compromised."};
}
// PyPI project names follow the Python packaging normalization specification;
// keep other ecosystems case-sensitive and only equate explicit pip/PyPI labels.
function samePackage(left:{name:string|null;ecosystem:string|null},right:{name:string|null;ecosystem:string|null}):boolean {
 if(!left.name||!right.name||!left.ecosystem||!right.ecosystem)return false;
 const eco=(value:string)=>['pip','pypi'].includes(value.toLowerCase())?'pypi':value.toLowerCase();
 const a=eco(left.ecosystem),b=eco(right.ecosystem);if(a!==b)return false;
 return a==='pypi'?left.name.toLowerCase().replace(/[-_.]+/g,'-')===right.name.toLowerCase().replace(/[-_.]+/g,'-'):left.name===right.name;
}
function packageEvidence(rows:Row[],states:Row[]):Row {
 const items=rows.slice(0,4).map(row=>{const data=parse(row.normalized_json);const original=Array.isArray(data.packages)?data.packages:[];
  const packages=original.slice(0,3).map(raw=>{const p=object(raw);const ranges=Array.isArray(p.ranges)?p.ranges:[];return {ecosystem:clip(p.ecosystem,80).text,name:clip(p.name,200).text,affected_range:clip(p.affected_range,300).text,first_patched_version:clip(p.first_patched_version,100).text,ranges:ranges.slice(0,2).map(rawRange=>{const range=object(rawRange);const events=Array.isArray(range.events)?range.events:[];return {type:clip(range.type,30).text,events:events.slice(0,6).map(event=>{const e=object(event);return Object.fromEntries(Object.entries(e).slice(0,4).map(([key,value])=>[clip(key,40).text,clip(value,100).text]));}),truncated:events.length>6||range.truncated===true};}),truncated:ranges.length>2||p.truncated===true};});
  return {source:row.source,id:row.advisory_id,url:row.source_url,published_at:row.published_at,modified_at:row.modified_at,retrieved_at:row.retrieved_at,withdrawn_at:clip(data.withdrawn_at,60).text,aliases:Array.isArray(data.aliases)?data.aliases.filter((x):x is string=>typeof x==="string"&&x.length<=40).slice(0,20):[],upstream_source:clip(data.upstream_source,1024).text,packages,truncated:data.truncated===true||original.length>3};});
 // Compare only the same advisory alias and package; keep both source records.
 // Fixed-version agreement does not establish affected-range equivalence.
 const comparisons:Row[]=[];
 for(const ghsa of items.filter(x=>x.source==="ghsa"&&!x.withdrawn_at))for(const osv of items.filter(x=>x.source==="osv"&&!x.withdrawn_at&&(x.id===ghsa.id||x.aliases.includes(String(ghsa.id)))))for(const left of ghsa.packages)for(const right of osv.packages){
  if(!samePackage(left,right))continue;
  const fixes=[...new Set(right.ranges.filter(r=>r.type==='ECOSYSTEM'||r.type==='SEMVER').flatMap(r=>r.events.map(event=>event.fixed).filter((v):v is string=>typeof v==="string"&&v.length>0)))];
  const interval=typeof left.affected_range==='string'?left.affected_range.match(/^>= ([^, ]+), < ([^, ]+)$/):null;
  const range=right.ranges.length===1?right.ranges[0]:undefined;
  const [start,end]=range?.events??[];
  const comparable=!ghsa.truncated&&!osv.truncated&&!left.truncated&&!right.truncated&&!!interval&&!!range&&!range.truncated&&['ECOSYSTEM','SEMVER'].includes(String(range.type))&&range.events.length===2&&start?.introduced===interval[1]&&!!end?.fixed&&interval[2]===left.first_patched_version&&Object.entries(start??{}).every(([k,v])=>k==='introduced'||v===null)&&Object.entries(end??{}).every(([k,v])=>k==='fixed'||v===null);
  comparisons.push({advisory_id:ghsa.id,package:left.name,ecosystem:left.ecosystem,ghsa_fixed_version:left.first_patched_version,osv_fixed_versions:fixes,
   fixed_version_comparison:!comparable?"inconclusive":end?.fixed===left.first_patched_version?"agrees":"differs",
   comparison_scope:"Only single untruncated intervals with the same explicit lower bound are comparable.",affected_range_comparison:"not_evaluated",sources:[ghsa.url,osv.url]});
 }
 // Collapse only a provably identical simple interval. Complex/disjoint ranges,
 // missing fixes, Git commit ranges and truncated records remain separate.
 const equivalent:Row[]=[];
 for(const ghsa of items.filter(x=>x.source==="ghsa"&&!x.truncated&&!x.withdrawn_at))for(const osv of items.filter(x=>x.source==="osv"&&!x.truncated&&!x.withdrawn_at&&(x.id===ghsa.id||x.aliases.includes(String(ghsa.id))))){
  osv.packages=osv.packages.filter(right=>{
   if(right.truncated||right.ranges.length!==1||!['SEMVER','ECOSYSTEM'].includes(String(right.ranges[0]?.type)))return true;
   const range=right.ranges[0]!;if(range.truncated||range.events.length!==2)return true;
   const [start,end]=range.events;const introduced=start?.introduced,fixed=end?.fixed;
   if(!introduced||!fixed||Object.entries(start??{}).some(([k,v])=>k!=='introduced'&&v!==null)||Object.entries(end??{}).some(([k,v])=>k!=='fixed'&&v!==null))return true;
   const match=ghsa.packages.find(left=>!left.truncated&&samePackage(left,right)&&left.first_patched_version===fixed&&left.affected_range===`>= ${introduced}, < ${fixed}`);
   if(!match)return true;
   equivalent.push({advisory_id:ghsa.id,package:match.name,ecosystem:match.ecosystem,affected_range:match.affected_range,first_patched_version:fixed,sources:[ghsa.url,osv.url]});return false;
  });
 }
 return {availability:items.length?"available":states.length?"no_cached_advisory":"not_checked",advisories:items,equivalent_package_evidence:equivalent.slice(0,12),equivalent_evidence_truncated:equivalent.length>12,cross_source_comparisons:comparisons.slice(0,12),comparisons_truncated:comparisons.length>12,source_state:states,truncated:rows.length>4,limitations:["Package matches do not prove that the package or affected version is installed.","Withdrawn advisories are historical and must not be treated as active guidance.","GHSA and OSV are retained separately; compare source evidence when ranges disagree.","OSV coverage is limited to verified GitHub Advisory Database, RustSec and native CVE conversion records; other sources are not queried.","An OSV native record_not_found applies only to that CVE identifier at the last lookup; cached records may predate it and other aliases may exist.","RustSec records are attributed to RustSec; some imported advisories use CC BY 4.0.","CVE-derived material is subject to the CVE Program terms: https://www.cve.org/Legal/TermsOfUse."]};
}
function sectionSelection(name:SectionName, item:Row, sections:ReturnType<typeof semanticSections>, url:string,includePrompt=false):Row {
 if(name==="assessment_prompt")return assessmentPrompt(item.content_html,url,includePrompt);
 const lookup:Record<Exclude<SectionName,"overview"|"other_sections"|"assessment_prompt">,string[]>={
  what_happened:["what happened"],why_it_matters:["why this needs attention","why it remains relevant","why it matters"],
  affected_scope:["who should investigate","who is affected","affected scope"],recommended_actions:["what to do now"],source_chronology:["update chronology"]
 };
 if(name==="overview")return {availability:typeof item.description==="string"?"available":"unavailable",...clip(item.description,1100),source_url:url};
 if(name==="other_sections") {
  const known=new Set(Object.values(lookup).flat());const entries=Object.entries(sections ?? {}).filter(([key])=>!known.has(key));
  return {availability:sections===null?"unavailable":entries.length?"available":"not_present",items:entries.slice(0,4).map(([title,value])=>({title:clip(title,100).text,title_truncated:clip(title,100).truncated,...clip(value.text,400),source_url:url})),truncated:entries.length>4};
 }
 const heading=lookup[name].find(key=>sections?.[key]);const section=heading ? sections?.[heading] : undefined;
 if(!section)return {availability:sections===null?"unavailable":"not_present_or_unparsed",text:null,source_url:url};
 return {availability:section.text?"available":"empty_or_unparsed",heading,...clip(section.text,name==="recommended_actions"?2000:1200),source_url:url};
}
function kevChange(x:Row):Row{return {sequence:x.sequence,event_kind:x.event_kind,observed_at:x.observed_at,source_date:x.source_date,catalog_version:x.catalog_version,source_url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"};}
function packageChange(x:Row):Row{return {sequence:x.sequence,event_kind:x.event_kind,observed_at:x.observed_at,source_date:x.source_date,source:x.source,advisory_id:x.advisory_id,source_url:x.source_url};}
function signalChange(x:Row):Row{return {sequence:x.sequence,source_id:x.source_id,event_kind:x.event_kind,source_url:x.source_url,observed_at:x.observed_at,source_date:x.source_date,previous:compactContext(String(x.source_id),x.previous_json),current:compactContext(String(x.source_id),x.current_json),threshold:x.threshold};}
/** Deterministic composition of stored source evidence. No network or database writes. */
export async function triage(queries:ReadQueries, identifier:string, requested?:SectionName[]): Promise<Row> {
 const cve=/^CVE-\d{4}-\d{4,}$/i.test(identifier) ? identifier.toUpperCase() : null;
 let row:Row|null;
 if(cve) {
  const matches=await queries.match("cve",cve,4);
  if(matches.length!==1) {
   const historical=matches.length===0?await queries.historyMatch(cve,4):[];
   const associations=matches.slice(0,3).map(x=>{const data=parse(x.normalized_json);const url=String(x.canonical_url??x.id);return {id:x.id,canonical_url:url,title:clip(data.title,200).text,recommended_actions:{...clip(data.recommended_actions,500),source_url:url},assessment_prompt:assessmentPrompt(data.content_html,url)};});
   const [kev,context,freshness,catalogState,series,packages,packageState,kevEvents,packageEvents,signals]=await Promise.all([queries.kev(cve),queries.context(cve),queries.sources(),queries.kevState(),queries.epssSeries(cve),queries.packageAdvisories(cve,5),queries.packageState(cve),queries.kevChanges(cve,6),queries.packageChanges(cve,6),queries.signalEvents(cve,6)]);
   if(matches.length || historical.length || kev || packages.length || kevEvents.length || packageEvents.length || signals.length || context.length || series){
    const record=parse(kev?.record_json);
    return {status:"ok",identification:{cve,briefing:null,briefings:associations,briefings_truncated:matches.length>3,historical_briefings:historical.slice(0,3).map(x=>({id:x.id,canonical_url:x.canonical_url})),historical_briefings_truncated:historical.length>3,source_coverage:[...new Set([...(matches.length||historical.length?["zero_wire"]:[]),...(kev||kevEvents.length?["cisa_kev"]:[]),...packages.map(x=>String(x.source)),...packageEvents.map(x=>String(x.source)),...(series||signals.some(x=>x.source_id==="first_epss")?["first_epss"]:[]),...context.map(x=>String(x.source_id))])]},
     verified_intelligence:{kev_membership:{status:kev?"listed":catalogState?.baseline_at?"not_listed_in_cached_catalog":"unknown",catalog_version:catalogState?.catalog_version??null,source_date:catalogState?.source_date??null,retrieved_at:catalogState?.retrieved_at??null,source_url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},kev:kev?{listed:true,vendor:kev.vendor,product:kev.product,date_added:kev.date_added,
      vulnerability_name:clip(record.vulnerabilityName,300).text,description:clip(record.shortDescription,1200).text,
      required_action:clip(record.requiredAction,1200).text,due_date:clip(record.dueDate,30).text,
      known_ransomware_campaign_use:clip(record.knownRansomwareCampaignUse,100).text,
      catalog_version:kev.catalog_version,source_date:kev.source_date,first_observed_at:kev.first_observed_at,
      source_url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}:null,source_freshness:freshness,catalog_state:catalogState},
     affected_software:packageEvidence(packages,packageState),
     exploitation_intelligence:{cve,epss_series:recentEpss(series),context:context.map(x=>({source_id:x.source_id,retrieved_at:x.retrieved_at,source_date:x.source_date,...compactContext(String(x.source_id),x.data_json)}))},
     observed_changes:{kev:kevEvents.slice(0,5).map(kevChange),package:packageEvents.slice(0,5).map(packageChange),signals:signals.slice(0,5).map(signalChange),truncated:kevEvents.length>5||packageEvents.length>5||signals.length>5,note:"Only changes observed by this instance after its baseline."},
     investigation:{source_actions:{...clip(record.requiredAction,1200),availability:kev&&typeof record.requiredAction==="string"?"available":"unavailable",source_url:kev?"https://www.cisa.gov/known-exploited-vulnerabilities-catalog":null},environment_questions:["Is the affected product and version deployed?","Is the component exposed?","Have vendor fixes been applied?"]},
     limitations:[matches.length?"Each briefing is distinct; its guidance is scoped to that briefing. Open an individual briefing for detail.":historical.length?"Prior briefing associations are historical; removal does not establish resolution or safety.":"No Zero Wire briefing is associated with this CVE.","KEV catalog presence does not establish that your environment is affected or compromised.","Missing EPSS context is unknown; EPSS is not severity or organization-specific compromise probability."]};
   }
   return {status:"not_tracked",identifier:cve,explanation:"No stored briefing or KEV record is associated with this CVE; this does not establish safety or source status.",catalog_state:catalogState,package_source_state:packageState};
  }
  row=matches[0] ?? null;
 } else row=await queries.get(identifier);
 if(!row)return {status:"not_tracked",identifier,explanation:"No stored briefing matches this ID."};
 const item=parse(row.normalized_json);const sourceUrl=typeof row.canonical_url==="string"?row.canonical_url:String(row.id);
 const sections=semanticSections(typeof item.content_html==="string"?item.content_html:null);
 const selected=requested ?? allSections;const structured=Object.fromEntries(selected.map(name=>[name,sectionSelection(name,item,sections,sourceUrl,requested?.includes("assessment_prompt")??false)]));
 const cves=Array.isArray(item.cves)?item.cves.filter((x):x is string=>typeof x==="string"):[];
 const tags=Array.isArray(item.tags)?item.tags.filter((x):x is string=>typeof x==="string"):[];
 const signals=[];
 for(const id of cves.slice(0,8)) {
  const [context,events,kevHistory,epssHistory,series,packages,packageState,kevEvents,packageEvents]=await Promise.all([queries.context(id),queries.signalEvents(id,6),queries.observations(id,"cisa_kev",4),queries.observations(id,"first_epss",4),queries.epssSeries(id),queries.packageAdvisories(id,5),queries.packageState(id),queries.kevChanges(id,6),queries.packageChanges(id,6)]);
  signals.push({cve:id,epss_series:recentEpss(series),affected_software:packageEvidence(packages,packageState),context:context.map(x=>({source_id:x.source_id,retrieved_at:x.retrieved_at,source_date:x.source_date,...compactContext(String(x.source_id),x.data_json)})),
   history:[...kevHistory.slice(0,3),...epssHistory.slice(0,3)].map(x=>({sequence:x.sequence,source_id:x.source_id,source_url:x.source_url,observed_at:x.observed_at,retrieved_at:x.retrieved_at,source_date:x.source_date,...compactContext(String(x.source_id),x.data_json)})),
   changes:events.slice(0,5).map(signalChange),kev_changes:kevEvents.slice(0,5).map(kevChange),package_changes:packageEvents.slice(0,5).map(packageChange),
   history_limit_per_source:3,history_truncated:kevHistory.length>3 || epssHistory.length>3,change_limit:5,changes_truncated:events.length>5||kevEvents.length>5||packageEvents.length>5,model_version_note:"EPSS model version is unknown unless supplied by the source."});
 }
 // The MCP transport JSON-encodes the JSON text a second time. Bound the
 // aggregate signals before serialization, retaining every selected CVE and
 // explicit omission notices even for unusually large upstream records.
 let signalBytes=0; let signalDetailsTruncated=false;
 const boundedSignals=signals.map(signal=>{
  const size=new TextEncoder().encode(JSON.stringify(signal)).length;
  if(signalBytes+size<=11000){signalBytes+=size;return signal;}
  signalDetailsTruncated=true;
  return {cve:signal.cve,details_truncated:true,
   explanation:"Additional cached details exceed this response budget; query vulnerability context or the source for this CVE.",
   epss_series:{availability:signal.epss_series.availability,last_attempt_at:signal.epss_series.last_attempt_at,last_error_code:signal.epss_series.last_error_code,latest:signal.epss_series.latest,source_url:signal.epss_series.source_url},
   context:signal.context.map(x=>{const v=object(x);return {source_id:v.source_id,retrieved_at:v.retrieved_at,source_date:v.source_date,listed:v.listed,available:v.available,probability:v.probability,score_date:v.score_date};})};
 });
 const [changes,freshness]=await Promise.all([queries.briefingChanges(String(row.id),6),queries.sources()]);
 const rawEvidence=Array.isArray(item.evidence_urls)?item.evidence_urls.filter((x):x is string=>typeof x==="string"):null;
 const evidence=rawEvidence?.filter(x=>{try{const u=new URL(x);return x.length<=1024 && u.protocol==="https:"&&!u.username&&!u.password;}catch{return false;}}).slice(0,10) ?? null;
 return {status:"ok",identification:{id:row.id,canonical_url:sourceUrl,title:clip(item.title,300).text,cves:cves.slice(0,50).filter(x=>x.length<=32),technologies:tags.slice(0,40).map(x=>clip(x,100).text),source_status:clip(item.status,100).text,source_feed_publication:clip(item.source_feed_pub_date,100).text,identification_truncated:cves.length>50 || cves.some(x=>x.length>32) || tags.length>40 || tags.some(x=>clip(x,100).truncated),first_observed_at:row.first_observed_at,last_observed_at:row.last_observed_at},
  source_sections:structured,evidence:{urls:evidence,availability:evidence===null?"unavailable":"available",truncated:rawEvidence!==null && evidence!==null && rawEvidence.length!==evidence.length},
  exploitation_intelligence:{cves:boundedSignals,truncated:cves.length>8||signalDetailsTruncated,source_freshness:freshness},
  observed_advisory_changes:changes.slice(0,5).map(x=>{const diff=parse(x.diff_json);const guidance=object(diff.guidance);return {sequence:x.sequence,event_kind:x.event_kind,observed_at:x.observed_at,changed_fields:Array.isArray(diff.changed_fields)?diff.changed_fields.slice(0,20):[],classifications:Array.isArray(diff.classifications)?diff.classifications.slice(0,12):null,guidance:diff.guidance?{previous:clip(guidance.previous,500),current:clip(guidance.current,500),source_url:sourceUrl}:null};}),observed_change_limit:5,observed_changes_truncated:changes.length>5,
  investigation:{source_actions:structured.recommended_actions ?? sectionSelection("recommended_actions",item,sections,sourceUrl),environment_questions:["Which product and version are actually deployed?","Is the affected component reachable or internet-facing?","Are vendor fixes applied to all running instances?","Which compensating controls are active and effective?"]},
  limitations:["Technology or CVE relevance does not establish exposure or safety.","Installed software, affected versions, internet exposure, patch status and compensating controls are not verified.","Source chronology is the publisher's narrative; observed changes begin only after this instance's baseline.","KEV absence does not rule out exploitation. EPSS is an estimate of exploitation activity, not severity or an environment-specific compromise probability.","Missing context is unknown. Check source freshness and the original advisory."]};
}
export const TRIAGE_SECTION_NAMES = ["overview","what_happened","why_it_matters","affected_scope","recommended_actions","source_chronology","other_sections","assessment_prompt"] as const;
