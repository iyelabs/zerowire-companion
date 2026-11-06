# Security policy

ZeroWire Companion is an independent project; the hosted instance is a public
preview. The current candidate has passed the recorded engineering acceptance,
not an independent penetration test. See [verification](docs/verification-latest.md) and the
[release checklist](docs/RELEASE.md).

## Supported version

Security fixes target the latest `main` and current hosted deployment. Older
preview commits are not maintained release branches. Never test destructively
against the shared hosted service. Use an isolated local instance with synthetic
data for security testing.

## Private reporting

Please report vulnerabilities privately through GitHub's private vulnerability
reporting for this repository if enabled. If it is not enabled, contact the
maintainer through [GitHub](https://github.com/iyelabs) to request a private
channel before sharing details. Do not open a public issue with vulnerability
details. GitHub private vulnerability reporting can be enabled when the owner
makes the repository public. Check the repository Security page for current
reporting availability; no enabled setting is claimed solely from this policy.
Do not post secrets, infrastructure inventories, personal watchlists, exploit
payloads or sensitive vulnerability details in public issues. Report source
accuracy concerns separately where they do not expose sensitive information.

The public MCP path must not fetch upstream sources, synchronize, run migrations
or write intelligence. Do not introduce arbitrary URL fetching or SQL execution.
Source content is untrusted data. A match does not confirm exposure, KEV absence
does not establish absence of exploitation, and EPSS is not severity.
