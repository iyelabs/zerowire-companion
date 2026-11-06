-- One scheduled writer at a time; a crashed invocation leaves an expiring lease.
CREATE TABLE ingestion_lease (
  name TEXT PRIMARY KEY CHECK (name = 'scheduled'),
  owner TEXT NOT NULL,
  expires_at TEXT NOT NULL
) STRICT;
CREATE TABLE ingestion_fence (
  valid INTEGER NOT NULL CHECK (valid = 1)
) STRICT;
