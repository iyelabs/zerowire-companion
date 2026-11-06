-- Preserve per-CVE retry state without replacing the last valid EPSS series.
CREATE TABLE epss_series_attempts (
 cve_id TEXT PRIMARY KEY,
 last_attempt_at TEXT NOT NULL,
 last_error_code TEXT
) STRICT;
CREATE INDEX epss_series_attempts_by_time ON epss_series_attempts(last_attempt_at,cve_id);
