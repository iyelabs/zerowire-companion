import type { WorkerEnv } from "../../cloudflare.config.ts";
import { RADAR_CVE_CATALOG_URL, RADAR_CVE_FEED_URL } from "../shared/radar-cve.ts";
import { SOURCE_USER_AGENT } from "../shared/version.ts";
import { fencedBatch } from "./lease.ts";

type Row = Record<string, unknown>;
function object(value: unknown): Row {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_radar_cve_feed");
  return value as Row;
}

export function parseRadarCves(raw: unknown) {
  const feed = object(raw);
  if (feed.version !== "https://jsonfeed.org/version/1.1" || !Array.isArray(feed.items) || !feed.items.length || feed.items.length > 100) {
    throw new Error("invalid_radar_cve_feed");
  }
  const ids = new Set<string>();
  return feed.items.map((item: unknown) => {
    const row = object(item);
    const meta = object(row._cve);
    const id = meta.id;
    if (typeof id !== "string" || !/^CVE-\d{4}-\d{4,}$/.test(id) || id.length > 32 || ids.has(id)) {
      throw new Error("invalid_radar_cve_id");
    }
    ids.add(id);
    const url = `${RADAR_CVE_CATALOG_URL}/${id}`;
    if (row.url !== url || row.id !== url) throw new Error("invalid_radar_cve_url");
    if (typeof row.date_published !== "string" || !/^\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(row.date_published)) {
      throw new Error("invalid_radar_cve_date");
    }
    const published = new Date(row.date_published);
    if (!Number.isFinite(published.valueOf())) throw new Error("invalid_radar_cve_date");
    const score = meta.score ?? null;
    const version = meta.cvss_version ?? null;
    const severity = meta.severity ?? null;
    if (
      (score !== null && (typeof score !== "number" || !Number.isFinite(score) || score < 0 || score > 10)) ||
      (version !== null && (typeof version !== "string" || !/^\d\.\d$/.test(version))) ||
      (severity !== null && (typeof severity !== "string" || !["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"].includes(severity))) ||
      (row.summary != null && typeof row.summary !== "string")
    ) throw new Error("invalid_radar_cve_metadata");

    return {
      cve_id: id, source_url: url, published_at: published.toISOString(),
      summary: Array.from(typeof row.summary === "string" ? row.summary : "").slice(0, 600).join(""),
      cvss_score: score, cvss_version: version, severity,
    };
  });
}

async function readCveFeed(): Promise<unknown> {
  const response = await fetch(RADAR_CVE_FEED_URL, {
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
    headers: { accept: "application/feed+json", "user-agent": SOURCE_USER_AGENT },
  });
  if (!response.ok || !response.body) throw new Error("radar_cve_feed_http_error");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let body = "";
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > 1024 * 1024) throw new Error("radar_cve_feed_too_large");
      body += decoder.decode(chunk.value, { stream: true });
    }
    return JSON.parse(body + decoder.decode());
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function refreshRadarCves(db: WorkerEnv["DB"], owner: string, now: string): Promise<void> {
  try {
    const items = parseRadarCves(await readCveFeed());
    const data = JSON.stringify(items);
    await fencedBatch(db, owner, [
      db.prepare(`INSERT INTO radar_cve_feed_items(cve_id,source_url,published_at,summary,cvss_score,cvss_version,severity)
        SELECT json_extract(value,'$.cve_id'),json_extract(value,'$.source_url'),json_extract(value,'$.published_at'),
          json_extract(value,'$.summary'),json_extract(value,'$.cvss_score'),json_extract(value,'$.cvss_version'),json_extract(value,'$.severity')
        FROM json_each(?) WHERE 1
        ON CONFLICT(cve_id) DO UPDATE SET source_url=excluded.source_url,published_at=excluded.published_at,
          summary=excluded.summary,cvss_score=excluded.cvss_score,cvss_version=excluded.cvss_version,severity=excluded.severity
        WHERE radar_cve_feed_items.published_at IS NOT excluded.published_at OR radar_cve_feed_items.summary IS NOT excluded.summary
          OR radar_cve_feed_items.cvss_score IS NOT excluded.cvss_score OR radar_cve_feed_items.cvss_version IS NOT excluded.cvss_version
          OR radar_cve_feed_items.severity IS NOT excluded.severity`).bind(data),
      db.prepare("DELETE FROM radar_cve_feed_items WHERE cve_id NOT IN (SELECT value FROM json_each(?))").bind(JSON.stringify(items.map(x => x.cve_id))),
      db.prepare(`INSERT INTO radar_cve_feed_state(singleton,last_attempt_at,last_success_at,item_count) VALUES(1,?,?,?)
        ON CONFLICT(singleton) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
          last_success_at=excluded.last_success_at,item_count=excluded.item_count,last_error_code=NULL`).bind(now, now, items.length),
    ]);
  } catch {
    await fencedBatch(db, owner, [
      db.prepare(`INSERT INTO radar_cve_feed_state(singleton,last_attempt_at,last_error_code) VALUES(1,?,'refresh_failed')
        ON CONFLICT(singleton) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code`).bind(now),
    ]);
  }
}
