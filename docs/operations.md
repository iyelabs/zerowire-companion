# Operations

ZeroWire Companion runs as one Worker with D1 and hourly Cron. The maintained
endpoint is `https://zerowire-companion.iyelabs.com/mcp`; it is not a website.
No frontend, hosted LLM or user-account service is required.

## Health and source freshness

`GET /health` is a liveness check, not proof that D1 or source ingestion is healthy.
Use the tools' source/per-CVE retrieval dates, errors and coverage indicators.
Ingestion is bounded and selective; one successful source refresh does not mean
every CVE refreshed in that run. An outage preserves previous valid evidence.

Run a bounded read-only smoke check with:

```sh
node scripts/verify-hosted.mjs https://zerowire-companion.iyelabs.com/mcp
```

It checks nine tools, both feeds, sample data, request guards and output bounds.
Repeated runs may reach the rate limit. This is not a load test or a source sync.
Keep TLS verification enabled. An organization CA may require
`NODE_USE_SYSTEM_CA=1`; never disable certificate validation.

## Deployment configuration

The maintained instance uses hourly `0 * * * *` UTC Cron and enabled ingestion.
Generic self-host defaults deliberately use `INGESTION_ENABLED=false` and enable
`workers.dev`. Before redeploying an existing instance, preserve its actual D1
binding, domain, Cron, ingestion flag, alternative exposure and rate limiter.
Never apply generic defaults over an operator's managed production settings.
CI has no Cloudflare credentials or automatic deployment step.

Apply migrations only through an authorized operator workflow. Record the D1
migration ledger and a recoverable backup/bookmark before database changes.
Worker code rollback does not roll back D1. Do not reset data or remove migration
history to make a rollout pass. Test a candidate locally before a controlled
runtime deployment and retain its previous Worker version for rollback.

## Guardrails and visibility

- Approximate 60 requests per minute per connecting IP and Cloudflare location;
  HTTP 429 carries `Retry-After: 60`. Shared NAT users share a bucket.
- 16 KiB request bodies, a two-second body deadline and a 64 KiB HTTP response cap.
  Public queries use fixed parameterized SELECT services, indexes and bounds.
- A 50 ms Worker CPU bound limits each invocation. It is not a throughput promise.
- The hosted edge permits POST `/mcp` and GET `/health`, `/events.json`, `/events.xml`.
  Browser GET `/mcp` is blocked with 403; self-hosted instances may return 405.
- Structured logs omit prompts, inventories, source bodies, authorization headers
  and client IPs. Query-string redaction is enabled; invocation logs are disabled.
  Cloudflare still processes connection data as the infrastructure provider.

Use Workers exceptions, logs, request metrics and D1 usage for operational review.
No automated alert delivery, independent penetration test or uptime SLA is claimed.
Use only isolated, controlled traffic for load tests, not the shared public service.

## Upstream limits and recovery

GHSA refresh honors `Retry-After` and primary `X-RateLimit-Reset` values.
Secondary rate limits use increasing backoff. Five consecutive rate-limit failures,
unclassified 403s or unsafe retry metadata suspend GHSA rather than retry forever.
Other sources remain independent. Inspect `ghsa_retry_policy`; resolve the cause
before an authorized operator resets a suspended policy for a later scheduled
retry. Public MCP calls cannot change the policy or start a refresh.

## Costs and emergency disable

Public rate limits are approximate and per-location, evaluated after Worker
invocation. They are not a global quota or bill ceiling. D1 reads, ingestion,
storage and history still consume resources. Storage can remain billable after
requests stop. Review actual [Workers](https://developers.cloudflare.com/workers/platform/pricing/)
and [D1](https://developers.cloudflare.com/d1/platform/pricing/) pricing and usage.
No strict zero-overage Worker/D1 guarantee is established.

For excess traffic, disable only this Worker's custom-domain routing and keep
`workers.dev` and preview exposure disabled. Disable scheduled work independently
by turning off `INGESTION_ENABLED` or removing its Cron trigger. Preserve D1.
Do not disable unrelated applications or grant the public Worker account-level
billing or WAF-management credentials. Record the incident and check freshness
before restoring traffic or ingestion.

## History and capacity

Source baselines do not create historical security events. Real subsequent
transitions, ordinary score observations and source narrative remain distinct.
History and storage grow with usage. Local wall-clock or fixture benchmarks do
not establish production CPU cost, capacity or Cloudflare invoice totals.
Independent endurance, destructive restore and second-account deployment tests
are not claimed. See the [verification guide](verification-latest.md).
