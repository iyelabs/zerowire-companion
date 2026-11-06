/** Conservative comparison: retain text and HTTPS references from every section. */
export function canonicalText(value: string | null | undefined): string | null {
 if (!value) return null;
 const normalized = value.replace(/\bLast checked\s*:?\s*(?:on\s+)?(?:\d{4}-\d{2}-\d{2}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})(?:\s+(?:at\s+)?\d{1,2}:\d{2}(?::\d{2})?\s*(?:UTC|GMT|Z)?)?/gi, " ")
  .replace(/\s+/g," ").replace(/\s+([.,;:!?])/g,"$1").trim();
 return normalized || null;
}
const asciiLower=(value:string):string=>value.replace(/[A-Z]/g,c=>c.toLowerCase());
/** Strip executable blocks in linear time, including malformed/unclosed blocks. */
export function stripUnsafeBlocks(html:string):string {
 const lower=asciiLower(html);let cursor=0;let result="";
 while(cursor<html.length) {
  const script=lower.indexOf("<script",cursor),style=lower.indexOf("<style",cursor);
  const found=[script,style].filter(x=>x>=0).sort((x,y)=>x-y)[0];if(found===undefined){result+=html.slice(cursor);break;}
  const name=found===script?"script":"style";const after=lower[found+name.length+1];
  if(after!==">" && after!=="/" && !/\s/.test(after ?? "")){result+=html.slice(cursor,found+name.length+1);cursor=found+name.length+1;continue;}
  result+=html.slice(cursor,found)+" ";const openEnd=lower.indexOf(">",found+name.length+1);if(openEnd<0)break;
  const close=lower.indexOf(`</${name}`,openEnd+1);if(close<0)break;const end=lower.indexOf(">",close+name.length+2);if(end<0)break;cursor=end+1;
 }
 return result;
}
/** Render text boundaries without interpreting or executing markup. */
export function stripMarkup(html:string):string {
 let pos=0,result="";
 while(pos<html.length) {
  const start=html.indexOf("<",pos);if(start<0){result+=html.slice(pos);break;}
  result+=html.slice(pos,start);const end=html.indexOf(">",start+1);if(end<0){result+=html.slice(start);break;}
  const tag=html.slice(start+1,end);
  if(/^\/?(?:p|div|br|li|ul|ol|table|tr|td|th|section|article|h[1-6])(?:\s|\/|$)/i.test(tag))result+=" ";
  if(/^img(?:\s|\/|$)/i.test(tag)) { const match=tag.match(/\balt\s*=\s*(["'])([^"']*)\1/i);if(match)result+=` ${match[2]} `; }
  pos=end+1;
 }
 return result;
}
export function safeLinks(html:string,includeSrc:boolean):string[] {
 const links=new Set<string>();const attr=includeSrc?/\b(?:href|src)\s*=\s*(["'])/gi:/\bhref\s*=\s*(["'])/gi;
 for(const match of html.matchAll(attr)) {
  const start=(match.index ?? 0)+match[0].length;const end=html.indexOf(match[1] ?? "",start);if(end<0)break;const href=html.slice(start,end).replace(/&amp;/gi,"&");
  if(href.length>2048)continue;try{const u=new URL(href);if(u.protocol==="https:"&&!u.username&&!u.password)links.add(u.href);}catch{ /* Ignore invalid or non-HTTPS URLs. */ }
 }
 return [...links].sort();
}
function sectionValue(html: string): {text:string|null; links:string[]} {
 const cleaned=stripUnsafeBlocks(html);const links=safeLinks(cleaned,true);
 const plain=stripMarkup(cleaned).replace(/&nbsp;|&#160;/gi," ").replace(/&amp;/gi,"&").replace(/&lt;/gi,"<").replace(/&gt;/gi,">").replace(/&quot;/gi,'"').replace(/&apos;|&#39;/gi,"'");
 return {text:canonicalText(plain),links};
}
/** A linear heading scan avoids unbounded backtracking on malformed source HTML. */
export function headingSpans(html:string): {index:number;end:number;title:string}[] {
 const lower=asciiLower(html);const spans:{index:number;end:number;title:string}[]=[];let cursor=0;
 while(cursor<html.length) {
  const start=lower.indexOf("<h2",cursor);if(start<0)break;
  const after=lower[start+3];if(after!==">" && after!==" " && after!=="\n" && after!=="\t" && after!=="\r"){cursor=start+3;continue;}
  const tagEnd=lower.indexOf(">",start+3);if(tagEnd<0)break;
  let close=lower.indexOf("</h2",tagEnd+1);
  while(close>=0 && lower[close+4]!==">" && !/\s/.test(lower[close+4] ?? ""))close=lower.indexOf("</h2",close+4);
  if(close<0)break;const end=lower.indexOf(">",close+4);if(end<0)break;
  spans.push({index:start,end:end+1,title:html.slice(tagEnd+1,close)});cursor=end+1;
 }
 return spans;
}
export function semanticSections(html: string | null | undefined): Record<string,{text:string|null;links:string[]}> | null {
 if(!html)return null;
 const clean=stripUnsafeBlocks(html);
 const headings=headingSpans(clean);
 const sections:Record<string,{text:string|null;links:string[]}>=Object.create(null);const counts=new Map<string,number>();
 const prefix=clean.slice(0,headings[0]?.index ?? clean.length); const prefixValue=sectionValue(prefix);
 if(prefixValue.text || prefixValue.links.length){sections["__unsectioned"]=prefixValue;counts.set("__unsectioned",1);}
 for(let i=0;i<headings.length;i++) {
  const h=headings[i]; if(!h)continue;
  const title=canonicalText(stripMarkup(h.title))?.toLowerCase() ?? "__unnamed";
  const count=(counts.get(title) ?? 0)+1;counts.set(title,count);const key=count===1?title:`${title} #${count}`;
  sections[key]=sectionValue(clean.slice(h.end,headings[i+1]?.index ?? clean.length));
 }
 return sections;
}
