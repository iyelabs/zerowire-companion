CREATE TABLE vulnerability_context (
  cve_id TEXT NOT NULL,
  source_id TEXT NOT NULL CHECK (source_id IN ('cisa_kev', 'first_epss')),
  retrieved_at TEXT NOT NULL,
  source_date TEXT,
  data_json TEXT NOT NULL CHECK (json_valid(data_json)),
  PRIMARY KEY (cve_id, source_id)
) STRICT;
CREATE INDEX vulnerability_context_by_source ON vulnerability_context(source_id, retrieved_at);
