# GitHub Actions example

Copy `workflow.yml` into `.github/workflows/zerowire.yml` and copy
`zerowire-summary.py` to `examples/github-actions/zerowire-summary.py` in your
repository. Run **ZeroWire intelligence review** from the Actions tab. Set
`ZEROWIRE_CVE` or `ZEROWIRE_TAG` in the workflow to filter results; uncomment
the schedule if desired. The job writes the first page of the last seven days
of observed events to its workflow summary. It does not create issues or send
notifications. A match does not establish exposure, and an empty page does not
establish safety; a continuation cursor can indicate unscanned events even when a page has no matches. Source coverage and freshness can be inspected via the JSON
endpoint. No credentials are needed for the hosted preview.
