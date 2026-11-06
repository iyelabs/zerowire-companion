import { stripMarkup, stripUnsafeBlocks } from './sections.ts';

const TITLES=new Set(['assess your exposure with an agent','assess your exposure with an ai agent','ai agent assessment']);
const MAX_BYTES=6000;
function entities(text:string):string {
 return text.replace(/&(?:amp|lt|gt|quot|apos|nbsp);|&#(?:x[0-9a-f]+|[0-9]+);/gi,value=>{
  const named:Record<string,string>={'&amp;':'&','&lt;':'<','&gt;':'>','&quot;':'"','&apos;':"'",'&nbsp;':' '};
  if(!value.startsWith('&#'))return named[value.toLowerCase()]??value;
  const hex=value[2]?.toLowerCase()==='x';const n=parseInt(value.slice(hex?3:2,-1),hex?16:10);
  return n>0&&n<=0x10ffff&&!(n>=0xd800&&n<=0xdfff)?String.fromCodePoint(n):'\ufffd';
 });
}
/** Extract a publisher's explicit prompt block; never infer or execute a prompt. */
export function assessmentPrompt(html:unknown,sourceUrl:string,includeText=false) {
 const base={source:'Cloudflare Radar Zero Wire',source_url:sourceUrl,format:'plain_text_extracted_from_html',trust:'untrusted_source_content',execution:'not_executed',requires_user_authorization:true};
 const empty=(availability:string)=>({...base,availability,text:null,text_included:false,truncated:false});
 if(typeof html!=='string'||!html)return empty('unavailable');
 const clean=stripUnsafeBlocks(html),lower=clean.toLowerCase();
 const headings=[...clean.matchAll(/<h[23](?=[\s>])[^>]*>/gi)];
 for(let i=0;i<headings.length;i++) {
  const h=headings[i];if(!h)continue;const start=(h.index??0)+h[0].length;const tag=h[0].slice(1,3).toLowerCase();
  const boundary=headings[i+1]?.index??clean.length,close=lower.indexOf(`</${tag}`,start);
  if(close<start||close>=boundary)continue;const end=lower.indexOf('>',close);if(end<0||end>=boundary)continue;
  const title=entities(stripMarkup(clean.slice(start,close))).replace(/\s+/g,' ').trim().toLowerCase();
  if(!TITLES.has(title))continue;
  const section=clean.slice(end+1,boundary),opens=[...section.matchAll(/<pre(?=[\s>])[^>]*>/gi)];
  if(opens.length!==1)return empty(opens.length?'multiple_prompt_blocks':'not_present_or_unparsed');
  const open=opens[0];if(!open)return empty('not_present_or_unparsed');const bodyStart=(open.index??0)+open[0].length;
  const closing=section.slice(bodyStart).match(/<\/pre\s*>/i);if(!closing)return empty('not_present_or_unparsed');
  const raw=section.slice(bodyStart,bodyStart+(closing.index??0));
  // Keep literal angle-bracket text inside the prompt; strip only presentation tags.
  const text=entities(raw.replace(/<br\s*\/?>/gi,'\n').replace(/<\/?(?:code|span)(?=[\s>])[^>]*>/gi,'')).replace(/\r\n?/g,'\n').trim();
  if(!text)return empty('empty_or_unparsed');
  if(new TextEncoder().encode(text).length>MAX_BYTES)return {...empty('too_large'),omitted:true,maximum_bytes:MAX_BYTES};
  return {...base,availability:'available',text:includeText?text:null,text_included:includeText,truncated:false,...(!includeText?{retrieval_hint:'Call get_triage_pack with this briefing ID and sections: ["assessment_prompt"].'}:{})};
 }
 return empty('not_present_or_unparsed');
}
