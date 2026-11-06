-- Each source advances independently; failures retain the previous cursor.
CREATE TABLE enrichment_progress (
  source_id TEXT PRIMARY KEY CHECK (source_id IN ('cisa_kev', 'first_epss')),
  last_cve TEXT NOT NULL
) STRICT;
