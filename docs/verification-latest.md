# Verification

CI verifies each pushed revision with the checked-in Node.js version:

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run test:runtime
```

[GitHub Actions](https://github.com/iyelabs/zerowire-companion/actions) is the
revision-specific CI record. A passing workflow is engineering evidence, not
an independent penetration test, an uptime guarantee or proof of local exposure.

The regression suite covers source normalization, initial baselines, observed
transitions, source failures, KEV/EPSS history, package aliases, query bounds,
migrations and public read-only capability boundaries. Runtime tests use local
workerd/D1 and synthetic inputs; they are separate from live source checks.

## Recorded product examples

- [CVE investigation](evidence/2026-11-05-readme-investigation.json): exact
  prompt, two real MCP calls, answer and official source comparisons.
- [Package versions](evidence/2026-11-05-final-hosted-package.json): the recorded
  Django investigation, including its additional web lookup.
- [Recent intelligence](evidence/2026-11-05-public-ready-digest.json): source-dated
  KEV additions, locally observed changes and source freshness.

README images are explicitly labelled interface recreations of those recorded
sessions. They are not native screenshots or invented conversations. Dates and
coverage describe each recorded session, not permanent source state.

## Repeat a bounded hosted check

```sh
node scripts/verify-hosted.mjs https://zerowire-companion.iyelabs.com/mcp
```

This opt-in check calls all nine MCP tools and both feeds. It does not synchronize
sources, modify intelligence or perform a load test. Repeated checks may hit the
public rate limiter. Check returned per-source and per-CVE dates before acting.

A clean second-account deployment, independent human usability study, independent
penetration test, destructive restore and exhaustive capacity validation are not
claimed. See [operations](operations.md), [coverage](source-coverage.md) and
[the security policy](../SECURITY.md).
