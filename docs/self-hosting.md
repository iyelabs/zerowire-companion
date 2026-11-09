# Self-hosting (experimental)

## Choose how to use it

Most users can connect to the maintained public preview at
`https://zerowire-companion.iyelabs.com/mcp`. They do not need a Cloudflare account,
database, domain, deployment or server API key. Their MCP client reads the
intelligence already ingested by the hosted instance.

Self-hosting is optional: it gives the operator control of refreshes, storage,
access policy and operating costs. The running IyeLabs instance proves that the
Worker/D1/Cron architecture works with real briefing data. It does not verify
every new account's permissions, resource provisioning or CLI setup. No known
IyeLabs-specific account, domain or secret dependency is required by the source.

## Deployment verification boundary

A clean deployment in a separate Cloudflare account is not independently verified.
Fresh and populated local D1 migration upgrades are covered by the regression
suite. Review the target account's permissions, source conditions and cost controls
before exposing an instance. The hosted instance does not require self-hosters
to use an IyeLabs account, domain or secret.

Prerequisites: Node.js 24.22.2, npm, and a Cloudflare account on the Workers Paid
plan with Workers and D1 permissions. The configured CPU limit requires the paid
(Standard) usage model. On Workers Free, each invocation gets 10 ms of CPU and 50 D1
queries; scheduled ingestion and triage packs for briefings with six or more CVEs
need more. Follow Cloudflare's [account selection instructions](https://developers.cloudflare.com/cf/get-started/#select-an-account).

```sh
npm ci
npx cf auth login
npx cf d1 create --name zerowire-companion-intelligence
# Copy the database UUID printed by the previous command.
npx cf d1 migrations apply <DATABASE_UUID> --dir ./migrations
npm run typecheck
npm test
npm run build
npm run test:runtime
npx cf deploy
```

These are preparatory commands; remote creation, migrations and deployment have
not been independently verified using this exact sequence. Choose the intended
account explicitly before creating any resource. The configuration binds the D1
database by name; the migration command requires the database UUID. Never commit
credentials, account identifiers, or `.cloudflare/` state to the repository.

`INGESTION_ENABLED` defaults to `false`. Keep it disabled until source usage,
rate controls and monitoring have been reviewed for the intended deployment.
A deployed empty service cannot return useful briefing intelligence. The Worker
contains scheduled and request handlers; MCP requests do not start synchronization
or write to D1. Endpoint and domain setup are deployment-specific, and the
repository does not require an IyeLabs account or domain.

For Cloudflare workers.dev or custom-domain setup, use Cloudflare's current
[Workers routing documentation](https://developers.cloudflare.com/workers/configuration/routing/).
Actual availability of a rate-limit binding, DNS configuration and cron trigger
must be checked in the target account. The rate limiter is approximate and
per-location, not a global spending cap.
