-- Backfill aliases from previously cached native CVE records without resetting data.
ALTER TABLE osv_cve_state ADD COLUMN alias_scan_at TEXT;
CREATE INDEX osv_cve_state_alias_scan ON osv_cve_state(alias_scan_at,cve_id);
