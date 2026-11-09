# Source coverage

ZeroWire Companion combines a complete cached CISA KEV catalog with the published
Zero Wire RSS corpus and selective EPSS, GHSA and OSV enrichment. It does not
provide complete coverage of every CVE or package advisory.

| Source | Coverage | Important boundary |
| --- | --- | --- |
| Zero Wire | Validated official RSS items and observed snapshots | Feed retention and source formatting determine available detail |
| CISA KEV | Complete validated catalog after the first baseline finishes | A staging generation is not published as a partial complete catalog; each CISA update takes several hourly runs to appear |
| FIRST EPSS | Selected CVEs, current scores and up to 30 published daily observations | Missing cache and missing history are not zero probability |
| GHSA | Selected public records and bounded discovery | Unauthenticated API limits can delay coverage |
| OSV | Selected records from supported upstreams and aliases | No full mirror or universal upstream license is assumed |

Six Zero Wire briefings were observed on November 5, 2026. This is a dated source
count, not an application limit. Briefings can contain multiple CVEs or no CVE.
The importer processes every validated RSS item within its documented resource
bounds; public pagination limits are separate from ingestion coverage.

Queries read the stored corpus. They never fetch a missing CVE on demand.
Recently relevant CVEs are prioritized; older catalog records are background
coverage. Source-level success does not mean every CVE refreshed in that cycle.
Check the returned retrieval dates, source dates and coverage indicators.

Technology matching is exact and case-insensitive. A PHP tag can match separate
runtime and application briefings; those retain separate identities, CVEs and
remediation evidence. A package match does not prove it is installed.

The first successful observation establishes a baseline. Later source dates do
not become invented local historical events. No match, no observed change,
source failure and unavailable evidence have different meanings. None establishes
that a system is safe or unaffected.
