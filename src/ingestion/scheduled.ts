import { SOURCE_USER_AGENT } from '../shared/version.ts';
import type { WorkerEnv } from "../../cloudflare.config.ts";
import { emitOperationalEvent } from "../observability.ts";
import { enrich } from "./enrichment.ts";
import { fencedBatch } from "./lease.ts";
import { FEED_URL, NORMALIZER_VERSION, parseFeed, sha256, type Briefing } from "./feed.ts";
import { semanticBriefing, changeClasses } from "./semantic.ts";

const MAX_FEED_BYTES = 1024 * 1024;
async function readFeed(response: Response): Promise<string> {
  if (!response.ok || !response.body) throw new Error("feed_http_error");
  const reader = response.body.getReader(); const decoder = new TextDecoder(); let result = ""; let size = 0;
  try { while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > MAX_FEED_BYTES) throw new Error("feed_too_large"); result += decoder.decode(part.value, { stream: true }); } return result + decoder.decode(); }
  finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
}

export async function handleScheduledIngestion(env: { INGESTION_ENABLED: string; DB: WorkerEnv["DB"]; GITHUB_ADVISORY_TOKEN?:string }): Promise<void> {
  if (env.INGESTION_ENABLED !== "true") { emitOperationalEvent({ event: "scheduled_disabled", outcome: "disabled" }); return; }
  const db = env.DB; const now = new Date().toISOString();
  const owner = crypto.randomUUID(); const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  const lease = await db.prepare("INSERT INTO ingestion_lease(name,owner,expires_at) VALUES('scheduled',?,?) ON CONFLICT(name) DO UPDATE SET owner=excluded.owner,expires_at=excluded.expires_at WHERE ingestion_lease.expires_at<=? RETURNING owner").bind(owner,expiresAt,now).first<{owner:string}>();
  if (lease?.owner !== owner) { emitOperationalEvent({ event: "scheduled_ingestion", outcome: "skipped_locked" }); return; }
  let feedError: unknown = null;
  try {
  try {
    const response = await fetch(FEED_URL, { redirect: "manual", signal: AbortSignal.timeout(15000), headers: { accept: "application/rss+xml, application/xml", "user-agent": SOURCE_USER_AGENT } });
    const feed = parseFeed(await readFeed(response));
    const state = await db.prepare("SELECT baseline_at FROM source_state WHERE source_id = 'zero_wire'").first<{ baseline_at: string | null }>();
    const baseline = !state?.baseline_at;
    const statements: D1PreparedStatement[] = [];
    for (const item of feed) {
      const normalized = JSON.stringify(item);
      const semantic = semanticBriefing(item);
      const hash = await sha256(JSON.stringify(semantic));
      const latest = await db.prepare("SELECT revision, semantic_hash, normalizer_version, normalized_json, source_guid, source_feed_pub_date, source_last_checked_date FROM briefing_snapshots WHERE briefing_id = ? ORDER BY revision DESC LIMIT 1").bind(item.id).first<{revision:number; semantic_hash:string; normalizer_version:string; normalized_json:string; source_guid:string|null; source_feed_pub_date:string|null; source_last_checked_date:string|null}>();
      statements.push(db.prepare("INSERT INTO briefings(id,canonical_url,first_observed_at,last_observed_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_observed_at=excluded.last_observed_at").bind(item.id,item.canonical_url,now,now));
      const previous = latest ? JSON.parse(latest.normalized_json) as Briefing : null;
      if (previous && (!Array.isArray(previous.cves) || !Array.isArray(previous.tags) || !(typeof previous.content_html === "string" || previous.content_html === null))) throw new Error("normalizer_comparison_unavailable");
      const previousSemantic = previous ? semanticBriefing(previous) : null;
      const semanticSame = previousSemantic !== null && JSON.stringify(previousSemantic) === JSON.stringify(semantic);
      const metadataSame = latest?.source_guid === item.source_guid && latest?.source_feed_pub_date === item.source_feed_pub_date && latest?.source_last_checked_date === item.source_last_checked_date;
      if (semanticSame && metadataSame && latest?.normalizer_version === NORMALIZER_VERSION) continue;
      const rev = (latest?.revision ?? 0) + 1;
      statements.push(db.prepare("INSERT INTO briefing_snapshots(briefing_id,revision,normalizer_version,semantic_hash,source_guid,source_feed_pub_date,source_last_checked_date,normalized_json,observed_at) VALUES(?,?,?,?,?,?,?,?,?)").bind(item.id,rev,NORMALIZER_VERSION,hash,item.source_guid,item.source_feed_pub_date,item.source_last_checked_date,normalized,now));
      statements.push(db.prepare("DELETE FROM briefing_cves WHERE briefing_id = ?").bind(item.id));
      for (const cve of item.cves) { statements.push(db.prepare("INSERT INTO briefing_cves(briefing_id,cve_id) VALUES(?,?)").bind(item.id,cve)); statements.push(db.prepare("INSERT OR IGNORE INTO briefing_cve_history(briefing_id,cve_id) VALUES(?,?)").bind(item.id,cve)); }
      statements.push(db.prepare("DELETE FROM briefing_tags WHERE briefing_id = ?").bind(item.id));
      for (const tag of item.tags) statements.push(db.prepare("INSERT INTO briefing_tags(briefing_id,normalized_tag,display_tag) VALUES(?,?,?)").bind(item.id,tag.toLowerCase(),tag));
      if (!baseline && !semanticSame) {
        const fields = previousSemantic ? Object.keys(semantic).filter(key => JSON.stringify(previousSemantic[key]) !== JSON.stringify(semantic[key])).sort() : [];
        const sets: Record<string,{added:string[];removed:string[]}> = {};
        if (previous) for (const key of ["cves", "tags", "evidence_urls"] as const) {
          if (Array.isArray(previous[key]) && Array.isArray(item[key]) && fields.includes(key)) {
            const old = previous[key] as string[]; const current = item[key] as string[];
            sets[key] = {added:current.filter(x=>!old.includes(x)),removed:old.filter(x=>!current.includes(x))};
          }
        }
        const oldGuidance = typeof previous?.recommended_actions === "string" ? Array.from(previous.recommended_actions) : null;
        const newGuidance = typeof item.recommended_actions === "string" ? Array.from(item.recommended_actions) : null;
        const guidance = previous && fields.includes("recommended_actions") ? {
          previous: oldGuidance?.slice(0,1500).join("") ?? null,
          current: newGuidance?.slice(0,1500).join("") ?? null,
          truncated: (oldGuidance?.length ?? 0)>1500 || (newGuidance?.length ?? 0)>1500,
        } : null;
        statements.push(db.prepare("INSERT INTO change_events(event_id,briefing_id,from_revision,to_revision,event_kind,observed_at,diff_json) VALUES(?,?,?,?,?,?,?)").bind(`${item.id}#${rev}`,item.id,latest?.revision ?? null,rev,latest ? "changed" : "first_observed",now,JSON.stringify({ changed_fields: fields, set_changes: sets, guidance, classifications: previousSemantic ? changeClasses(previousSemantic, semantic, fields) : ["briefing.first_observed"] })));
      }
    }
    statements.push(db.prepare("INSERT INTO source_state(source_id,source_url,last_attempt_at,last_success_at,baseline_at,last_error_code) VALUES('zero_wire',?,?,?,?,NULL) ON CONFLICT(source_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_success_at=excluded.last_success_at,baseline_at=COALESCE(source_state.baseline_at,excluded.baseline_at),last_error_code=NULL").bind(FEED_URL,now,now,now));
    await fencedBatch(db, owner, statements);
    emitOperationalEvent({ event: "scheduled_ingestion", outcome: "success", count: feed.length });
  } catch (error) {
    await fencedBatch(db, owner, [db.prepare("INSERT INTO source_state(source_id,source_url,last_attempt_at,last_error_code) VALUES('zero_wire',?,?,'ingestion_failed') ON CONFLICT(source_id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code").bind(FEED_URL,now)]);
    emitOperationalEvent({ event: "scheduled_ingestion", outcome: "failed" }); feedError = error;
  }
  // Enrichment has separate source health and must not mark a successful feed as failed.
  await enrich(db, owner, env.GITHUB_ADVISORY_TOKEN);
  if (feedError) throw feedError;
  } finally {
    await db.prepare("DELETE FROM ingestion_lease WHERE name='scheduled' AND owner=?").bind(owner).run();
  }
}
