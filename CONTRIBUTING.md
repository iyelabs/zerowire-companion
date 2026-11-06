# Contributing

Issues and small, focused pull requests are welcome. Describe the user-visible
problem and include a reproducible example using synthetic data. Do not attach
credentials, private infrastructure information, or complete upstream briefings.

Use Node.js 24.22.2 and run:

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run test:runtime
```

Keep the scheduled ingestion and read-only public request paths separate. Do not
add upstream fetching, D1 writes, migrations, or background sync to MCP calls.
Preserve source attribution, observation times, baseline semantics, untrusted
content boundaries, and unknown applicability. Document any limitation and add
focused tests for behavior changes. CI runs these checks without a deployment.

Report security vulnerabilities using [SECURITY.md](SECURITY.md), not a public
issue. New contributions to the project code are provided under the MIT license.
