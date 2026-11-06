-- Original schema only. No source content, user profiles or deployment identifiers.
CREATE TABLE schema_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  version INTEGER NOT NULL CHECK (version >= 1)
) STRICT;
INSERT INTO schema_meta (singleton, version) VALUES (1, 1);

CREATE TABLE source_state (
  source_id TEXT PRIMARY KEY CHECK (source_id IN ('zero_wire', 'cisa_kev', 'first_epss')),
  source_url TEXT NOT NULL,
  last_attempt_at TEXT,
  last_success_at TEXT,
  baseline_at TEXT,
  source_content_date TEXT,
  etag TEXT,
  last_modified TEXT,
  body_sha256 TEXT,
  last_error_code TEXT
) STRICT;

CREATE TABLE briefings (
  id TEXT PRIMARY KEY,
  canonical_url TEXT NOT NULL UNIQUE,
  first_observed_at TEXT NOT NULL,
  last_observed_at TEXT NOT NULL
) STRICT;

CREATE TABLE briefing_snapshots (
  briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE RESTRICT,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  normalizer_version TEXT NOT NULL,
  semantic_hash TEXT NOT NULL CHECK (length(semantic_hash) = 64),
  source_guid TEXT,
  source_feed_pub_date TEXT,
  source_last_checked_date TEXT,
  normalized_json TEXT NOT NULL CHECK (json_valid(normalized_json)),
  observed_at TEXT NOT NULL,
  PRIMARY KEY (briefing_id, revision)
) STRICT;

CREATE TABLE briefing_cves (
  briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE RESTRICT,
  cve_id TEXT NOT NULL,
  PRIMARY KEY (briefing_id, cve_id)
) STRICT;
CREATE INDEX briefing_cves_by_cve ON briefing_cves(cve_id, briefing_id);

CREATE TABLE briefing_tags (
  briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE RESTRICT,
  normalized_tag TEXT NOT NULL,
  display_tag TEXT NOT NULL,
  PRIMARY KEY (briefing_id, normalized_tag)
) STRICT;
CREATE INDEX briefing_tags_by_tag ON briefing_tags(normalized_tag, briefing_id);

CREATE TABLE change_events (
  sequence INTEGER PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  briefing_id TEXT NOT NULL,
  from_revision INTEGER,
  to_revision INTEGER NOT NULL,
  event_kind TEXT NOT NULL CHECK (event_kind IN ('first_observed', 'changed')),
  observed_at TEXT NOT NULL,
  diff_json TEXT NOT NULL CHECK (json_valid(diff_json)),
  FOREIGN KEY (briefing_id, to_revision) REFERENCES briefing_snapshots(briefing_id, revision),
  FOREIGN KEY (briefing_id, from_revision) REFERENCES briefing_snapshots(briefing_id, revision),
  UNIQUE (briefing_id, to_revision, event_kind),
  CHECK (from_revision IS NULL OR to_revision > from_revision),
  CHECK ((event_kind = 'first_observed' AND from_revision IS NULL) OR
         (event_kind = 'changed' AND from_revision IS NOT NULL))
) STRICT;
CREATE INDEX change_events_by_time ON change_events(observed_at, sequence);
CREATE INDEX change_events_by_briefing ON change_events(briefing_id, sequence);
CREATE INDEX briefings_by_observation ON briefings(first_observed_at, id);
