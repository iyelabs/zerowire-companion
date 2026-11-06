-- A staged catalog is not queryable until validation and the full sync finish.
CREATE TABLE kev_catalog (
 cve_id TEXT PRIMARY KEY,
 vendor TEXT NOT NULL,
 product TEXT NOT NULL,
 date_added TEXT NOT NULL,
 record_json TEXT NOT NULL CHECK(json_valid(record_json)),
 catalog_version TEXT NOT NULL,
 source_date TEXT NOT NULL,
 first_observed_at TEXT NOT NULL,
 last_observed_at TEXT NOT NULL
) STRICT;
CREATE INDEX kev_catalog_by_added ON kev_catalog(date_added DESC,cve_id);
CREATE INDEX kev_catalog_by_vendor ON kev_catalog(vendor COLLATE NOCASE,product COLLATE NOCASE,cve_id);
CREATE TABLE kev_catalog_events (
 sequence INTEGER PRIMARY KEY,
 cve_id TEXT NOT NULL,
 event_kind TEXT NOT NULL CHECK(event_kind IN ('kev.first_observed','kev.record_changed','kev.record_removed')),
 observed_at TEXT NOT NULL,
 catalog_version TEXT NOT NULL,
 source_date TEXT NOT NULL,
 previous_json TEXT CHECK(previous_json IS NULL OR json_valid(previous_json)),
 current_json TEXT NOT NULL CHECK(json_valid(current_json))
) STRICT;
CREATE INDEX kev_catalog_events_by_time ON kev_catalog_events(observed_at,sequence);
CREATE INDEX kev_catalog_events_by_cve ON kev_catalog_events(cve_id,sequence);
CREATE TABLE kev_catalog_state (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 baseline_at TEXT,
 catalog_version TEXT,
 content_hash TEXT,
 source_date TEXT,
 retrieved_at TEXT,
 record_count INTEGER,
 generation TEXT,
 cursor TEXT,
 last_error_code TEXT
) STRICT;
CREATE TABLE kev_catalog_stage (
 generation TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 record_json TEXT NOT NULL CHECK(json_valid(record_json)),
 PRIMARY KEY(generation,cve_id)
) STRICT;
