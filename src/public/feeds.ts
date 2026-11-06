import type {ReadQueries} from './queries.ts';
import {intelligenceDigest,type DigestCursor} from './digest.ts';
const SOURCES=new Set(['zero_wire','cisa_kev','first_epss','ghsa']);
const STREAMS=new Set(['briefing','kev','signal','package']);
const ALLOWED=new Set(['since','until','source','cve','tag','category','vendor','product','limit','cursor_time','cursor_stream','cursor_sequence']);
function escapeXml(value:unknown):string{return String(value??'').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/g,'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');}
function httpsLink(value:unknown):string{try{const url=new URL(String(value));return url.protocol==='https:'&&!url.username&&!url.password?url.href:''}catch{return ''}}
function timestamp(value:string):string|null{if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value))return null;const date=new Date(value);return Number.isFinite(date.valueOf())?date.toISOString():null;}
function bad():Response{return Response.json({error:'invalid_feed_parameters'},{status:400});}
export async function handleFeed(request:Request,queries:ReadQueries):Promise<Response>{
 if(request.method!=='GET')return Response.json({error:'method_not_allowed'},{status:405,headers:{allow:'GET'}});
 const url=new URL(request.url);const p=url.searchParams;
 for(const key of p.keys())if(!ALLOWED.has(key)||p.getAll(key).length!==1)return bad();
 const end=p.has('until')?timestamp(p.get('until')!):new Date().toISOString();if(!end)return bad();
 const since=p.has('since')?timestamp(p.get('since')!):new Date(Date.parse(end)-7*86400000).toISOString();if(!since || since>end || Date.parse(end)-Date.parse(since)>31*86400000)return bad();
 const source=p.get('source')??'',cve=p.get('cve')??'',tag=p.get('tag')??'',category=p.get('category')??'',vendor=p.get('vendor')??'',product=p.get('product')??'',rawLimit=p.get('limit')??'10';
 if((source&&!SOURCES.has(source))||(cve&&!/^CVE-\d{4}-\d{4,}$/i.test(cve))||tag.length>100||category.length>80||vendor.length>150||product.length>150||((vendor||product)&&source!==''&&source!=='cisa_kev')||!/^\d{1,2}$/.test(rawLimit))return bad();const limit=Number(rawLimit);if(limit<1||limit>15)return bad();
 const cursorParts=['cursor_time','cursor_stream','cursor_sequence'].map(k=>p.get(k));let cursor:DigestCursor|undefined;
 if(cursorParts.some(x=>x!==null)) {const [time,stream,seq]=cursorParts;if(!time||!stream||!seq||!timestamp(time)||!STREAMS.has(stream)||!/^\d{1,15}$/.test(seq)||!Number.isSafeInteger(Number(seq)))return bad();cursor={observed_at:timestamp(time)!,stream,sequence:Number(seq)};}
 const data=await intelligenceDigest(queries,{since,until:end,source,cve,tag,category,vendor,product,limit,cursor,includeSourcePublications:false});
 if(url.pathname==='/events.json')return Response.json({...data,source_publications:undefined},{headers:{'content-type':'application/json; charset=utf-8'}});
 const items=data.items.map(item=>`<item><guid isPermaLink="false">${escapeXml(item.id)}</guid><title>${escapeXml(item.event_type)}: ${escapeXml(item.cve??item.briefing_id??item.source)}</title><link>${escapeXml(httpsLink(item.source_url))}</link><pubDate>${escapeXml(new Date(String(item.observed_at)).toUTCString())}</pubDate><description>${escapeXml(`Observed ${item.observed_at}; source date ${item.source_date??'unknown'}. ${item.follow_up}`)}</description></item>`).join('');
 const xml=`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0" xmlns:zw="urn:iyelabs:zerowire-companion:events:1"><channel><title>ZeroWire Companion — observed intelligence</title><link>${escapeXml(httpsLink(url.origin+url.pathname))}</link><description>Locally observed events; source coverage is partial.</description><zw:freshness>${escapeXml(JSON.stringify(data.freshness))}</zw:freshness><zw:nextCursor>${escapeXml(JSON.stringify(data.next_cursor))}</zw:nextCursor>${items}</channel></rss>`;
 return new Response(xml,{headers:{'content-type':'application/rss+xml; charset=utf-8'}});
}
