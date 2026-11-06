-- Bound timeline reads by briefing/CVE and observation time without rewriting data.
CREATE INDEX change_events_by_briefing_time ON change_events(briefing_id, observed_at, sequence);
CREATE INDEX signal_events_by_cve_time ON signal_events(cve_id, observed_at, sequence);
CREATE INDEX observations_by_cve_time ON enrichment_observations(cve_id, observed_at, sequence);
-- Retain associations actually present in any stored snapshot, including removed CVEs.
CREATE TABLE briefing_cve_history (
  briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE RESTRICT,
  cve_id TEXT NOT NULL,
  PRIMARY KEY(briefing_id,cve_id)
) STRICT;
CREATE INDEX briefing_cve_history_by_cve ON briefing_cve_history(cve_id,briefing_id);
INSERT OR IGNORE INTO briefing_cve_history(briefing_id,cve_id)
SELECT s.briefing_id,j.value FROM briefing_snapshots s,json_each(s.normalized_json,'$.cves') j
WHERE j.type='text';
