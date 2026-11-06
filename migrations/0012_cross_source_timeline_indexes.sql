-- Bound cross-source timelines by CVE and observation time.
CREATE INDEX kev_catalog_events_by_cve_time ON kev_catalog_events(cve_id,observed_at,sequence);
CREATE INDEX package_advisory_events_by_cve_time ON package_advisory_events(cve_id,observed_at,sequence);
