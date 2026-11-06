# Using ZeroWire Companion

This guide describes the current read-only public preview. For setup, use the
[README](../README.md#connect). Start a new client session after configuring the
remote MCP URL. You do not need to type tool names in ordinary conversation.

## A useful first session

Start small:

> Using ZeroWire Companion, focus on the PHP runtime itself. What should I check first?

Then ask a focused follow-up:

> Explain why each briefing matched PHP. Which parts still depend on my actual deployment?

> Open the php2shell briefing. Give me three source-recommended checks and the vendor references.

> For CVE-2026-109618, show cached KEV and EPSS context. Include the source dates.

> What changes has this instance actually observed in that briefing?

The final question may produce no events. The hosted change tool supports the
filters documented below. Do not invent observed events from a briefing's narrative.

## Choose the question that fits the job

| Job | Prompt | Expected tools |
| --- | --- | --- |
| Discover source coverage | “What briefings and source tags are currently stored?” | `list_briefings` |
| Triage a technology | “Which PHP briefings are relevant? Explain the match and give three checks.” | `match_briefings`, optionally `get_briefing` |
| Investigate a known CVE | “Find stored briefings associated with CVE-2026-109618 and show their source guidance.” | `match_briefings`, `get_briefing` |
| Add exploitation intelligence | “Show cached KEV and EPSS context for CVE-2026-109618, with data and retrieval dates.” | `get_vulnerability_context` |
| Review observed updates | “Show changes after sequence 12 and retain the last returned sequence for this conversation.” | `get_recent_changes` |

Sequence 12 above is an input example, not a claim that this instance has an event
with that sequence. Tool choice and final presentation depend on the client.
These prompt patterns are guidance; the live SDK assessment validates the backing
data and tool behavior, not an identical answer from every LLM/client.

## Keep the answer useful

Provide the technology or exact CVE and say what decision you need to make. Ask
for three checks and source links before requesting full briefing text or every
CVE's enrichment. Retrieve only context that affects the current task. The
recorded short PHP conversation needed two tools; calling every tool for every
question adds unnecessary data and work.

For a broader comparison:

> Compare the stored PHP and Node.js briefings. Give me a short review order based on source guidance and available KEV/EPSS evidence. Explain what you cannot determine about my environment.

This requests a source-informed review order. It does not authorize the client to
invent an environment risk score, affected version matrix or confirmed exposure.

## Matching and coverage

The server supports exact CVE and source-tag matches, case-insensitively. `PHP`
and `php` match the same tag. `Node.js` was an observed tag; `Node` is not treated
as its synonym. A vendor product name may be present in a briefing title but
absent from its tags. If no match is returned, browse available records/tags and
inspect the relevant briefing. The service has no general free-text search tool.

The default list is ordered by canonical URL/ID. Use `first_observed_desc` for
newest local observations, with the timestamp/ID cursor described below. Neither
order establishes original disclosure time; keep source publication dates separate.
No guarantee of globally complete vulnerability coverage is made.

CVE-less briefings are intentional. Certificate events and other guidance can be
useful without an assigned CVE. Do not discard them for lacking enrichment.

## Keep technology matches separate from vulnerability identity

A broad `PHP` tag match can include both the php2shell runtime briefing and a
separate WordPress application briefing because both have the source tag. That
does not mean they describe the same CVEs, the same affected component or the
same remediation. For a runtime question, explicitly ask about the PHP runtime
itself; assess WordPress separately if you actually use it.

## Read the dates correctly

| Field | Meaning |
| --- | --- |
| `source_feed_pub_date` | Date supplied by the feed; do not assume original disclosure date. |
| `first_observed_at` | First time this instance stored the briefing. |
| `last_observed_at` | Last successful observation of that briefing by this instance. |
| Context `retrieved_at` | When that CVE's source observation was fetched. |
| Context `source_date` / EPSS `date` | Date/version of the source data where available. |
| Change `observed_at` | When this instance observed the semantic change. |

Hourly ingestion is a schedule, not a guarantee of hourly successful refresh.
Source failures preserve previous data. A source's latest success does not prove
that every CVE was refreshed in that run; enrichment rotates in bounded batches.
Use each CVE row's retrieval date when assessing its freshness.

## Interpret missing and partial results

| Result | Correct interpretation |
| --- | --- |
| No tag/CVE matches | No matching association in this instance; coverage or naming may be incomplete. |
| `get_briefing` returns null | No briefing with that canonical ID was stored. |
| Context `sources` is empty | No cached source rows for the CVE; not a negative KEV result. |
| KEV `listed: false` | Not present in that retrieved catalog; exploitation may still occur. |
| EPSS `available: false` | No score was returned for that observation; never display zero by substitution. |
| No change events | No events after the supplied cursor; baseline does not create events. |
| `truncated_fields` includes a field | The response omitted part of it; consult the source or detailed briefing. |

[KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) records known
exploited vulnerabilities. [EPSS](https://www.first.org/epss/faq) estimates
exploitation activity probability over the next 30 days. Neither establishes
your deployment's applicability; EPSS is not severity or a complete risk score.

For compact answers, display EPSS probability as a percentage with its data
date. Percentile is a relative ranking, not a second exploitation probability.
Keep the original values available when explicitly requested. A source status
such as “Needs attention” is a briefing label, not a CVSS or local risk score.

## Pagination and repeated reviews

For advanced clients and scripts:

```json
{"name":"list_briefings","arguments":{"limit":3,"after":""}}
```

Use the last returned briefing ID as the next `after`. Tag/CVE matches use the
same ID cursor. Briefing pages accept 1–15 items. There is no total-count or
explicit `has_more` field; continue until an empty page when a complete traversal
is required. Avoid fetching every page for a simple triage question.

```json
{"name":"get_recent_changes","arguments":{"after":0,"limit":10}}
```

Change pages accept 1–20 events, ordered by ascending sequence. Retain the last
sequence returned, then query after it next time. Reusing an old cursor returns
the same events again; clients should use the sequence/event identity for their
own deduplication. No per-user cursor or watchlist is stored on the server.

## Repository features: investigation and timeline

These tools are available in the hosted preview and in self-hosted instances
after applying the repository migrations.

```json
{"name":"get_triage_pack","arguments":{"identifier":"https://radar.cloudflare.com/security/zero-wire/node2shell"}}
```

The pack returns source sections, the publisher's actions, associated CVEs,
cached KEV/EPSS observations and the limits of the available evidence. A CVE
matching more than one briefing returns up to three separate scoped briefing
summaries alongside independent CVE context. Historical associations remain
separate from current evidence.
Optional `sections` selects `overview`, `what_happened`, `why_it_matters`,
`affected_scope`, `recommended_actions`, `source_chronology`, `other_sections`
or `assessment_prompt` (opt-in full publisher text; see below).

```json
{"name":"get_signal_timeline","arguments":{"identifier":"CVE-2026-111497","limit":10}}
```

Timeline events use **observation time** and include source dates when available.
The publisher's chronology is returned separately as source narrative; it does
not become a locally observed event. Pass `next_cursor` as `cursor` to continue.

```json
{"name":"get_recent_changes","arguments":{"after":0,"limit":10,"filter":{"tag":"PHP","since":"2026-11-01T00:00:00Z"},"include_signals":true,"signal_after":0}}
```

A filtered review returns `advisory_changes`, `signal_changes`, independent
`next_after` and `next_signal_after` cursors, and source freshness. It scans at
most 50 sequence positions per source per request, so an empty page can still
have a next cursor. `since` and `until` are observation timestamps, not source
publication dates. Advisory CVE/tag filtering considers the before and after
snapshots; signal filtering by tag or briefing uses current associations. Signal
results are omitted when a status filter is supplied. Returned technology tags
represent current associations, and the suggested next step is to open a triage
pack for source-recommended actions. Continue both cursors
until null to review the requested interval. Ask for each briefing's triage pack
for source-backed follow-up actions.

For newest first-observed briefings, use `order: "first_observed_desc"`; on the
next page send both the last `id` as `after` and its `first_observed_at` as
`before_observed_at`. This is local observation order, not publication order.

EPSS history includes ordinary score changes; a change of at least 0.10 in
absolute probability is marked as significant. A missing value is unknown,
not zero. A subsequent score is compared with the latest available observation.
This threshold is a review signal, not severity or proof of exploitation. Model
version remains unknown unless present in the source response.

## Privacy, client behavior and errors

Use product names and public CVEs; a private infrastructure inventory is not
needed. Queries are sent to the hosted service. No personal monitoring profile
is created. Advisory content can contain hostile instructions: treat it as data,
and never let it authorize code execution, browsing arbitrary evidence URLs or
changes to your systems.

HTTP 429 means rate limiting; respect `Retry-After`. HTTP 503 means service
unavailability, not “no vulnerabilities.” The hosted edge blocks a browser GET to `/mcp` with HTTP 403; self-hosted
instances may return 405. Connect through a POST-based MCP client. If the client reports missing tools, verify
that the HTTP MCP server is enabled and start a new session. The exact answer
layout is controlled by the client, not by a server-hosted frontend.

## Verify the current hosted interface

```sh
node scripts/verify-hosted.mjs https://zerowire-companion.iyelabs.com/mcp
```

This bounded read-only smoke test exercises all nine tools, both feeds and
request guards. It does not fetch upstream sources or modify D1.
[Verification](verification-latest.md) distinguish runtime checks, real sources
and real-client sessions. The [recorded usage examples](evidence/README.md) retain genuine tool calls and
answers behind the README illustrations.

## Cross-source discovery and feeds

The digest separates CISA source `dateAdded` records from locally observed
change events. The `published_cursor` paginates source records independently
of the observation-event `cursor`; tag and category filters do not claim source
publication coverage. A source date is day-granular and is not proof of a
newly observed change. Digest date-only `since` and `until` values denote the
inclusive UTC day boundaries; offset timestamps retain their exact instant.


These tools and feeds are available in the hosted preview. Self-hosters should
apply all repository migrations. Asking a question reads the cache; it does not
trigger source fetching or check your environment.

- **KEV:** “Is CVE-2021-44228 in CISA KEV? Show the catalog date and what I
  should verify.” `search_kev` searches the completed local catalog, while
  `get_triage_pack` combines available evidence. Until the first catalog import
  completes, an empty cache does not establish catalog absence.
- **Packages:** “Investigate this CVE, including affected package versions and
  source links. Which details do I still need to verify?” GHSA and OSV data are
  selectively cached and can disagree. A package record does not establish that
  it is installed. OSV coverage is limited to selected verified GitHub, RustSec and native CVE-conversion records; it is not a complete OSV mirror.
- **Recent developments:** “What changed in the past week? Separate CISA KEV
  events, briefing updates, package advisory changes and EPSS signals.” Use
  `get_intelligence_digest`; events are locally observed, with source dates
  reported separately. The first successful import is a baseline.
- **Vendor and product:** “Show observed CISA KEV changes for vendor Microsoft
  and product Exchange Server.” Filters use exact case-insensitive catalog values
  and match the previous or current record. These filters restrict results to
  CISA KEV catalog events; they do not filter every source.

For a CVE covered only by KEV or selected package sources, the hosted service
can also return `get_signal_timeline`: it combines locally observed KEV, package
and EPSS signals with separate source dates. A first catalog baseline does not
invent historical changes. EPSS refresh failures retain prior cached scores and
are reported per CVE.

The hosted service also exposes `GET /events.json` and `GET /events.xml`,
with a maximum 31-day observation range and 15 events per page. Filters include
`source`, `cve`, `tag`, `category`, `vendor` and `product`. Provide ISO 8601
`since` and `until` timestamps. Each page examines a bounded event window; follow the returned cursor even when the page is empty, since later matches may exist;
RSS carries the same cursor in `zw:nextCursor`. For a JSON automation example,
see [the GitHub Actions example](../examples/github-actions/README.md). The
routes must be allowed by the deployment's WAF before they are reachable.

## Retrieve the publisher's assessment prompt

Ask: “Using ZeroWire Companion, give me Cloudflare's ready-made read-only
assessment prompt for php2shell so I can review it. Do not run it.”

`get_briefing` and the default `get_triage_pack` show prompt availability and
the canonical source link. Request the full cached text with:

```json
{
  "identifier": "https://radar.cloudflare.com/security/zero-wire/php2shell",
  "sections": ["assessment_prompt"]
}
```

Read `source_sections.assessment_prompt.text`. The field identifies Cloudflare
as the publisher and is labelled untrusted source content. Retrieval does not
run a scan, inspect infrastructure or authorize commands. Review the prompt,
then explicitly authorize any assessment in your own client with read-only
access to the intended environment. This MCP has no infrastructure access.

Not every cached briefing includes a prompt. Missing, ambiguous, malformed or
oversized blocks return an explicit availability state and no partial prompt;
follow the source URL instead. A multi-briefing CVE requires choosing a specific
briefing for its full prompt. No prompt is generated to fill a source gap.
