-- FIRST-published scores; local retrieval time is not an event date.
CREATE TABLE epss_series (
 cve_id TEXT PRIMARY KEY,
 retrieved_at TEXT NOT NULL,
 latest_date TEXT,
 observations_json TEXT NOT NULL CHECK(json_valid(observations_json)),
 source_url TEXT NOT NULL,
 model_version TEXT
) STRICT;
CREATE INDEX epss_series_by_retrieved ON epss_series(retrieved_at,cve_id);
CREATE TABLE epss_series_progress (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 last_cve TEXT NOT NULL,
 last_attempt_at TEXT NOT NULL,
 last_success_at TEXT,
 last_error_code TEXT
) STRICT;
