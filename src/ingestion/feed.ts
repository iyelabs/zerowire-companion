import { XMLParser, XMLValidator } from "fast-xml-parser";
import { headingSpans, safeLinks, semanticSections, stripMarkup, stripUnsafeBlocks } from "../shared/sections.ts";

export const FEED_URL = "https://radar.cloudflare.com/security/zero-wire/rss";
export const NORMALIZER_VERSION = "3";
export interface Briefing {
  id: string; canonical_url: string; title: string; description: string | null;
  content_html: string | null; source_guid: string | null; source_feed_pub_date: string | null; source_last_checked_date: string | null;
  cves: string[]; tags: string[]; status: string | null;
  recommended_actions: string | null; evidence_urls: string[] | null;
}
type Node = Record<string, unknown>;
const asNode = (x: unknown): Node => x !== null && typeof x === "object" && !Array.isArray(x) ? x as Node : {};
const array = (x: unknown): unknown[] => x === undefined ? [] : Array.isArray(x) ? x : [x];
const text = (x: unknown): string | null => {
  if (typeof x === "object" && x !== null) return text(asNode(x)["#text"]);
  if (typeof x !== "string" && typeof x !== "number") return null;
  const s = String(x).trim();
  return s ? s.replace(/&(?:amp|lt|gt|quot|apos);/g, e => ({"&amp;":"&","&lt;":"<","&gt;":">","&quot;":'"',"&apos;":"'"})[e] ?? e) : null;
};

/** Extract only known RSS sections. All text and links remain untrusted data. */
function section(html: string | null, title: string): string | null {
  if (!html) return null;
  const clean=stripUnsafeBlocks(html);
  const headings=headingSpans(clean);const index=headings.findIndex(h=>stripMarkup(h.title).trim().toLowerCase()===title.toLowerCase());
  if(index<0)return null;const heading=headings[index];if(!heading)return null;
  return clean.slice(heading.end,headings[index+1]?.index ?? clean.length);
}
function extractActions(html: string | null): string | null {
  const value=semanticSections(html)?.["what to do now"]?.text;
  return value ? Array.from(value).slice(0,6000).join("") : null;
}
function extractEvidence(html: string | null): string[] | null {
  const raw = section(html, "Evidence and sources"); if (raw === null) return null;
  return safeLinks(raw,false).slice(0,25);
}

export function parseFeed(xml: string): Briefing[] {
  if (/<!\s*(?:DOCTYPE|ENTITY)\b/i.test(xml)) throw new Error("unsafe_xml_declaration");
  if (XMLValidator.validate(xml) !== true) throw new Error("invalid_xml");
  const parsed: unknown = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_", processEntities: false, parseTagValue: false, trimValues: true }).parse(xml);
  const channel = asNode(asNode(asNode(parsed).rss).channel);
  if (!channel.item) throw new Error("empty_or_invalid_feed");
  const items = array(channel.item);
  if (items.length > 500) throw new Error("feed_item_limit");
  const seen = new Set<string>();
  return items.map(raw => {
    const item = asNode(raw); const rawUrl = text(item.link); const title = text(item.title);
    if (!rawUrl || !title) throw new Error("missing_identity_or_title");
    const url = new URL(rawUrl);
    if (url.protocol !== "https:" || url.hostname !== "radar.cloudflare.com" || url.port || url.username || url.password || !/^\/security\/zero-wire\/[a-z0-9][a-z0-9-]*\/?$/.test(url.pathname)) throw new Error("invalid_briefing_url");
    url.pathname = url.pathname.replace(/\/$/, ""); url.search = ""; url.hash = "";
    const canonical_url = url.toString();
    if (seen.has(canonical_url)) throw new Error("duplicate_briefing_identity");
    seen.add(canonical_url);
    const cves = new Set<string>(); const tags = new Set<string>(); let status: string | null = null;
    for (const value of array(item.category)) {
      const category = text(value); const domain = text(asNode(value)["@_domain"]);
      if (!category) continue;
      if (/^CVE-/i.test(category)) { if(category.length>32 || !/^CVE-\d{4}-\d{4,}$/i.test(category)) throw new Error("invalid_cve_category"); cves.add(category.toUpperCase()); }
      else if (domain?.startsWith("https://radar.cloudflare.com/security/zero-wire/tag/") && ![...tags].some(tag => tag.toLowerCase() === category.toLowerCase())) tags.add(category);
      else if (!domain && status === null) status = category;
    }
    const content_html = text(item["content:encoded"]);
    const plain = content_html ? stripMarkup(stripUnsafeBlocks(content_html)).replace(/\s+/g, " ") : "";
    const source_last_checked_date = plain.match(/\bLast checked\s*:?\s*(?:on\s+)?(\d{4}-\d{2}-\d{2}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})/i)?.[1] ?? null;
    return { id: canonical_url, canonical_url, title, description: text(item.description), content_html, recommended_actions: extractActions(content_html), evidence_urls: extractEvidence(content_html), source_guid: text(item.guid), source_feed_pub_date: text(item.pubDate), source_last_checked_date, cves: [...cves].sort(), tags: [...tags].sort((a,b) => a.localeCompare(b, "en")), status };
  });
}

export async function sha256(value: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2,"0")).join("");
}
