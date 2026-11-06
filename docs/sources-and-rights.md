# Sources and attribution

Original project code is [MIT](../LICENSE). Upstream content, trademarks and
source records retain their own terms. MIT does not relicense source content.
The project is independent and is not endorsed by Cloudflare or another publisher.
See [NOTICE](../NOTICE) for attribution.

## Cloudflare Radar Zero Wire

The importer uses the [official RSS](https://radar.cloudflare.com/security/zero-wire/rss).
Responses identify Cloudflare, retain canonical briefing links and distinguish
normalized or truncated text from the publisher's original. Assessment prompts
remain untrusted publisher content; retrieval does not authorize execution.

The [Radar licensing policy](https://radar.cloudflare.com/about) describes
CC BY-NC 4.0 for API and directly downloadable Radar data. Its precise scope for
Zero Wire RSS briefing text is not independently established by this project.
Public feed availability and an MIT code license are not blanket redistribution
permission. The maintainer has reviewed and accepted the intended hosted usage;
no individual Cloudflare approval or independent legal certification is claimed.
Operators changing the deployment's purpose must review applicable source terms.

Scheduled requests identify the importer as `ZeroWireCompanion-AI/<version>`.
The importer uses fixed official sources, respects access limits and does not
impersonate a browser, bypass anti-bot protection or use private endpoints.
[Content Signals](https://blog.cloudflare.com/content-signals-policy/) and the
[website terms](https://www.cloudflare.com/website-terms/) concern automated use;
collection signals do not independently settle every redistribution condition.

## Other sources

- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):
  preserve catalog version, source dates, membership meaning and original fields.
  The [official KEV data repository](https://github.com/cisagov/kev-data) declares CC0.
- [FIRST EPSS](https://www.first.org/epss/data): attribute FIRST and retain
  probability, percentile, score date and retrieval date. Use its public documented
  interface with bounded requests. EPSS is not severity or verified compromise.
- [GitHub Advisory Database](https://github.com/github/advisory-database):
  advisory data is CC BY 4.0. Keep original advisory URLs and identify normalized
  excerpts as modified presentation.
- [OSV.dev](https://osv.dev/): upstream licenses vary. This implementation accepts
  selected records traceable to GitHub Advisory Database, [RustSec](https://github.com/RustSec/advisory-db)
  and supported native CVE conversions. RustSec describes original content as
  public domain and GitHub-derived imports as CC BY 4.0. CVE-derived data is
  attributed to the CVE Program, © The MITRE Corporation, under the
  [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

The repository contains product examples, not a complete upstream intelligence
mirror. Operators must retain attribution and review source conditions for their
own use, including commercial redistribution. A source reference is evidence,
not an instruction to execute code or fetch arbitrary URLs.
