import type { ReadQueries } from "./queries.ts";
import { semanticSections } from "../shared/sections.ts";
import { compactContext } from "./triage.ts";
type Row=Record<string,unknown>;
export type TimelineCursor={observed_at:string;kind:string;sequence:number};
const parse=(x:unknown):Row=>typeof x==="string" ? JSON.parse(x) as Row : {};
function afterCursor(e:TimelineCursor,c:TimelineCursor):boolean {
 return e.observed_at<c.observed_at || (e.observed_at===c.observed_at && (e.kind>c.kind || (e.kind===c.kind && e.sequence<c.sequence)));
}
function description(diff:Row):Row {
 return {changed_fields:Array.isArray(diff.changed_fields)?diff.changed_fields.slice(0,20):[],classifications:Array.isArray(diff.classifications)?diff.classifications.slice(0,12):[],classification_availability:Array.isArray(diff.classifications)?"available":"legacy_unclassified"};
}
function signalItem(x:Row):Row {return {kind:"signal_change",sequence:x.sequence,identifier:x.cve_id,event_type:x.event_kind,source:x.source_id,source_url:x.source_url,source_date:x.source_date,observed_at:x.observed_at,previous:compactContext(String(x.source_id),x.previous_json),current:compactContext(String(x.source_id),x.current_json),threshold:x.threshold};}
function observationItem(x:Row):Row {return {kind:"source_observation",sequence:x.sequence,identifier:x.cve_id,event_type:"enrichment_observed",source:x.source_id,source_url:x.source_url,source_date:x.source_date,observed_at:x.observed_at,retrieved_at:x.retrieved_at,context:compactContext(String(x.source_id),x.data_json)};}
function kevItem(x:Row):Row {return {kind:"kev_change",sequence:x.sequence,identifier:x.cve_id,event_type:x.event_kind,source:"cisa_kev",source_url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",source_date:x.source_date,observed_at:x.observed_at,catalog_version:x.catalog_version};}
function packageItem(x:Row):Row {return {kind:"package_change",sequence:x.sequence,identifier:x.cve_id,event_type:x.event_kind,source:x.source,source_url:x.source_url,source_date:x.source_date,observed_at:x.observed_at,advisory_id:x.advisory_id};}
const order=(a:Row,b:Row)=>String(b.observed_at).localeCompare(String(a.observed_at)) || String(a.kind).localeCompare(String(b.kind)) || Number(b.sequence)-Number(a.sequence);
async function cveOnlyTimeline(q:ReadQueries,cve:string,since:string,until:string,limit:number,cursor?:TimelineCursor):Promise<Row>{
 const current=cursor??{observed_at:"9999-12-31T23:59:59.999Z",kind:"",sequence:Number.MAX_SAFE_INTEGER},start=since||"0000-01-01T00:00:00.000Z",end=until||"9999-12-31T23:59:59.999Z";
 const [kev,packages,series,knownSignals,knownKev,knownPackages,context,signals,observations,kevEvents,packageEvents,freshness]=await Promise.all([q.kev(cve),q.packageAdvisories(cve,1),q.epssSeries(cve),q.signalEvents(cve,1),q.kevChanges(cve,1),q.packageChanges(cve,1),q.context(cve),q.timelineSignals(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelineObservations(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelineKev(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelinePackages(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.sources()]);
 if(!kev&&!packages.length&&!series&&!knownSignals.length&&!knownKev.length&&!knownPackages.length&&!context.length&&!signals.length&&!observations.length&&!kevEvents.length&&!packageEvents.length)return {status:"not_tracked",identifier:cve,events:[],freshness,limitations:["Not tracked does not mean safe."]};
 const events=[...signals.map(signalItem),...observations.map(observationItem),...kevEvents.map(kevItem),...packageEvents.map(packageItem)].sort(order);const page=events.slice(0,limit),last=page.at(-1);
 return {status:"ok",identifier:cve,requested_cve:cve,events:page,next_cursor:events.length>limit&&last?{observed_at:last.observed_at,kind:last.kind,sequence:last.sequence}:null,source_chronology:{kind:"unavailable",text:null,note:"No associated briefing narrative."},freshness,limitations:["Dates are local observations unless labelled source_date; a catalog baseline does not invent prior events.","No event does not establish safety or absence of exploitation.","EPSS is not severity; model version is unknown unless supplied by FIRST."]};
}
export async function timeline(q:ReadQueries,identifier:string,since:string,until:string,limit:number,cursor?:TimelineCursor):Promise<Row> {
 const requestedCve=/^CVE-\d{4}-\d{4,}$/i.test(identifier)?identifier.toUpperCase():null;
 let row:Row|null;
 if(requestedCve) {
  const matches=await q.historyMatch(requestedCve,3);
  if(!matches.length)return cveOnlyTimeline(q,requestedCve,since,until,limit,cursor);
  if(matches.length>1)return {status:"ambiguous",identifier:requestedCve,briefings:matches.map(x=>({id:x.id,canonical_url:x.canonical_url})),truncated:matches.length===3};
  row=matches[0] ?? null;
 } else row=await q.get(identifier);
 if(!row)return {status:"not_tracked",identifier,events:[]};
 const source=String(row.canonical_url ?? row.id),data=parse(row.normalized_json);
 const allCves=Array.isArray(data.cves)?data.cves.filter((x):x is string=>typeof x==="string"):[];
 const cves=requestedCve?[requestedCve]:allCves.slice(0,8);
 const current=cursor ?? {observed_at:"9999-12-31T23:59:59.999Z",kind:"",sequence:Number.MAX_SAFE_INTEGER};
 const start=since||"0000-01-01T00:00:00.000Z",end=until||"9999-12-31T23:59:59.999Z";
 const [changes,...groups]=await Promise.all([q.timelineBriefing(String(row.id),start,end,current.observed_at,current.kind,current.sequence,limit+1),...cves.flatMap(cve=>[q.timelineSignals(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelineObservations(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelineKev(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1),q.timelinePackages(cve,start,end,current.observed_at,current.kind,current.sequence,limit+1)])]);
 const events:Row[]=changes.map(x=>({kind:"briefing_change",sequence:x.sequence,identifier:x.briefing_id,event_type:x.event_kind,source:"Cloudflare Radar Zero Wire",source_url:source,source_date:null,observed_at:x.observed_at,details:description(parse(x.diff_json))}));
 for(let i=0;i<groups.length;i++)for(const x of groups[i] ?? []) {
  if(i%4===0)events.push(signalItem(x));
  else if(i%4===1)events.push(observationItem(x));
  else if(i%4===2)events.push(kevItem(x));
  else events.push(packageItem(x));
 }
 const first=String(row.first_observed_at ?? "");const baseline={kind:"first_observed",sequence:0,identifier:row.id,event_type:"briefing.first_observed",source:"Cloudflare Radar Zero Wire",source_url:source,source_date:typeof data.source_feed_pub_date==="string" && data.source_feed_pub_date.length<=100?data.source_feed_pub_date:null,observed_at:first,note:"The briefing was first observed here; an associated CVE may have been added later."};
 if(first && first>=start && first<=end && afterCursor(baseline,current))events.push(baseline);
 events.sort(order);
 const page=events.slice(0,limit);const last=page.at(-1);const next=events.length>limit && last ? {observed_at:last.observed_at,kind:last.kind,sequence:last.sequence} : null;
 const chronology=semanticSections(typeof data.content_html==="string"?data.content_html:null)?.["update chronology"];
 const text=chronology?.text ?? null;const bytes=text?new TextEncoder().encode(text):null;
 return {status:"ok",identifier:row.id,requested_cve:requestedCve,events:page,next_cursor:next,
  source_chronology:{kind:"source_narrative",text:bytes && bytes.length>1200?new TextDecoder().decode(bytes.subarray(0,1200),{stream:true}):text,truncated:!!bytes && bytes.length>1200,source_url:source,source_date:null,date_availability:"not parsed",note:"Publisher narrative, not locally observed events."},
  freshness:await q.sources(),limitations:["Dates in this timeline are local observation times unless labelled source_date.","A missing event does not establish safety or absence of exploitation.","EPSS is not severity; model version is unknown unless supplied by FIRST.",...(allCves.length>8 && !requestedCve?["Only the first eight currently associated CVEs are included."]:[])]};
}
