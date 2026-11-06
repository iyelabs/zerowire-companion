import type { Briefing } from "./feed.ts";

import { canonicalText, semanticSections } from "../shared/sections.ts";

export function semanticBriefing(item: Briefing): Record<string,unknown> {
 const sections=semanticSections(item.content_html);
 // Re-derive both old and new snapshots using the same parser, so parser-only
 // differences do not hide a real source change during an upgrade.
 return {title:canonicalText(item.title),description:canonicalText(item.description),cves:item.cves,tags:item.tags,status:canonicalText(item.status),recommended_actions:sections?.["what to do now"]?.text ?? canonicalText(item.recommended_actions),evidence_urls:sections?.["evidence and sources"]?.links ?? item.evidence_urls,sections};
}
export function changeClasses(previous: Record<string,unknown>, current: Record<string,unknown>, fields: string[]): string[] {
 const classes=new Set<string>();
 const prev=Array.isArray(previous.cves)?previous.cves as string[]:[];const next=Array.isArray(current.cves)?current.cves as string[]:[];
 if(next.some(x=>!prev.includes(x)))classes.add("briefing.cve_added");
 if(prev.some(x=>!next.includes(x)))classes.add("briefing.cve_removed");
 if(fields.includes("recommended_actions"))classes.add("briefing.guidance_changed");
 if(fields.includes("evidence_urls"))classes.add("briefing.evidence_changed");
 if(fields.includes("status"))classes.add("briefing.status_changed");
 if(fields.includes("tags"))classes.add("briefing.affected_scope_changed");
 if(fields.includes("sections")) {
  const before=(previous.sections ?? {}) as Record<string,unknown>;const after=(current.sections ?? {}) as Record<string,unknown>;
  for(const name of new Set([...Object.keys(before),...Object.keys(after)])) {
   if(JSON.stringify(before[name])===JSON.stringify(after[name]))continue;
   if(name==="what to do now")classes.add("briefing.guidance_changed");
   else if(name==="evidence and sources")classes.add("briefing.evidence_changed");
   else if(/^(who should investigate|who is affected|affected scope)(?:\s|$)/.test(name))classes.add("briefing.affected_scope_changed");
   else classes.add("briefing.unclassified_content_changed");
  }
 }
 if(fields.some(x=>["title","description"].includes(x)))classes.add("briefing.unclassified_content_changed");
 return [...classes].sort();
}
