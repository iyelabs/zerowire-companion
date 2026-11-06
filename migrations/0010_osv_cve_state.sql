-- Independent lookup of OSV records whose native identifier is a tracked CVE.
-- Separate from GHSA-alias OSV pagination; neither source can mask the other.
CREATE TABLE osv_cve_state (
 cve_id TEXT PRIMARY KEY,
 last_attempt_at TEXT NOT NULL,
 last_success_at TEXT,
 last_error_code TEXT
) STRICT;
CREATE INDEX osv_cve_state_by_attempt ON osv_cve_state(last_attempt_at,cve_id);
