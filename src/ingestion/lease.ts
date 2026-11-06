import type { WorkerEnv } from "../../cloudflare.config.ts";
/** Checked inside each write transaction so an expired owner cannot persist. */
export function fencedBatch(db: WorkerEnv["DB"], owner: string, statements: D1PreparedStatement[]): Promise<D1Result[]> {
 const guard = db.prepare("INSERT INTO ingestion_fence(valid) SELECT CASE WHEN EXISTS (SELECT 1 FROM ingestion_lease WHERE name='scheduled' AND owner=? AND expires_at>strftime('%Y-%m-%dT%H:%M:%fZ','now')) THEN 1 ELSE 0 END").bind(owner);
 return db.batch([guard,...statements,db.prepare("DELETE FROM ingestion_fence")]);
}
