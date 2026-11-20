CREATE TABLE radar_cve_feed_items (
  cve_id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  published_at TEXT NOT NULL,
  summary TEXT NOT NULL,
  cvss_score REAL CHECK (cvss_score BETWEEN 0 AND 10),
  cvss_version TEXT,
  severity TEXT
) STRICT;

CREATE INDEX radar_cve_feed_recent_idx ON radar_cve_feed_items(published_at DESC, cve_id DESC);

CREATE TABLE radar_cve_feed_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  last_attempt_at TEXT NOT NULL,
  last_success_at TEXT,
  last_error_code TEXT,
  item_count INTEGER CHECK (item_count BETWEEN 1 AND 100)
) STRICT;
