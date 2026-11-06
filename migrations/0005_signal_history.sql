-- Preserve the latest previously retrieved context as the first known observation.
-- No earlier history or transition is inferred during migration.
CREATE TABLE enrichment_observations (
  sequence INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source_id TEXT NOT NULL CHECK (source_id IN ('cisa_kev', 'first_epss')),
  source_url TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  retrieved_at TEXT NOT NULL,
  source_date TEXT,
  data_json TEXT NOT NULL CHECK (json_valid(data_json))
) STRICT;
CREATE INDEX enrichment_observations_by_cve_source ON enrichment_observations(cve_id, source_id, sequence);
CREATE INDEX enrichment_observations_by_time ON enrichment_observations(observed_at, sequence);
INSERT INTO enrichment_observations(cve_id,source_id,source_url,observed_at,retrieved_at,source_date,data_json)
SELECT cve_id,source_id,CASE source_id WHEN 'cisa_kev' THEN 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' ELSE 'https://api.first.org/data/v1/epss' END,
       retrieved_at,retrieved_at,CASE WHEN source_id='first_epss' THEN COALESCE(json_extract(data_json,'$.record.date'),source_date) ELSE source_date END,data_json
FROM vulnerability_context;

CREATE TABLE signal_events (
  sequence INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  source_id TEXT NOT NULL CHECK (source_id IN ('cisa_kev','first_epss')),
  event_kind TEXT NOT NULL CHECK (event_kind IN ('kev_membership_changed','epss_significant_change')),
  source_url TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  source_date TEXT,
  previous_json TEXT NOT NULL CHECK (json_valid(previous_json)),
  current_json TEXT NOT NULL CHECK (json_valid(current_json)),
  threshold REAL
) STRICT;
CREATE INDEX signal_events_by_cve ON signal_events(cve_id, sequence);
CREATE INDEX signal_events_by_time ON signal_events(observed_at, sequence);
