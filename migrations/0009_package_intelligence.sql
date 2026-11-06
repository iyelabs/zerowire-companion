-- Derived package metadata remains attributable to each independent source.
CREATE TABLE package_advisories (
 source TEXT NOT NULL CHECK(source IN ('ghsa','osv')),
 advisory_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 source_url TEXT NOT NULL,
 published_at TEXT,
 modified_at TEXT,
 retrieved_at TEXT NOT NULL,
 normalized_json TEXT NOT NULL CHECK(json_valid(normalized_json)),
 PRIMARY KEY(source,advisory_id,cve_id)
) STRICT;
CREATE INDEX package_advisories_by_cve ON package_advisories(cve_id,source,advisory_id);
CREATE TABLE package_source_state (
 source TEXT NOT NULL CHECK(source IN ('ghsa','osv')),
 cve_id TEXT NOT NULL,
 last_attempt_at TEXT NOT NULL,
 last_success_at TEXT,
 last_error_code TEXT,
 cursor TEXT,
 scan_started_at TEXT,
 coverage_complete INTEGER NOT NULL DEFAULT 0 CHECK(coverage_complete IN (0,1)),
 PRIMARY KEY(source,cve_id)
) STRICT;
CREATE INDEX package_source_state_by_attempt ON package_source_state(source,last_attempt_at,cve_id);
CREATE TABLE package_feed_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 baseline_at TEXT,
 last_attempt_at TEXT,
 last_success_at TEXT,
 last_error_code TEXT
) STRICT;
CREATE TABLE package_advisory_events (
 sequence INTEGER PRIMARY KEY,
 source TEXT NOT NULL CHECK(source='ghsa'),
 advisory_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 event_kind TEXT NOT NULL CHECK(event_kind IN ('advisory.first_observed','advisory.changed')),
 observed_at TEXT NOT NULL,
 source_date TEXT,
 source_url TEXT NOT NULL
) STRICT;
CREATE INDEX package_advisory_events_by_time ON package_advisory_events(observed_at,sequence);
