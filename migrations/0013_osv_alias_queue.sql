-- Bounded, independently retried OSV aliases discovered from tracked CVEs.
CREATE TABLE osv_alias_queue (
 cve_id TEXT NOT NULL,
 advisory_id TEXT NOT NULL,
 last_attempt_at TEXT,
 last_success_at TEXT,
 last_error_code TEXT,
 PRIMARY KEY(cve_id,advisory_id)
) STRICT;
CREATE INDEX osv_alias_queue_by_attempt ON osv_alias_queue(last_attempt_at,cve_id,advisory_id);
