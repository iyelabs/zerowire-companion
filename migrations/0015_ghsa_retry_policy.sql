-- Preserve bounded GitHub rate-limit backoff independently of advisory data.
CREATE TABLE ghsa_retry_policy (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  failures INTEGER NOT NULL DEFAULT 0,
  retry_not_before TEXT,
  suspended INTEGER NOT NULL DEFAULT 0 CHECK(suspended IN (0,1)),
  reason TEXT,
  last_status INTEGER,
  remaining INTEGER,
  reset_at TEXT,
  retry_after_seconds INTEGER
);
