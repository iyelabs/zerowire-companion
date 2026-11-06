#!/usr/bin/env python3
"""Write a bounded ZeroWire Companion intelligence summary using only stdlib."""
import json
import os
import re
import sys
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

ENDPOINT = 'https://zerowire-companion.iyelabs.com/events.json'
MAX_BYTES = 65536

def text(value):
    return str(value or '').replace('\\', '\\\\').replace('|', '\\|').replace('\n', ' ').replace('\r', ' ')[:400]

def run():
    params = {'limit': '15'}
    cve = os.environ.get('ZEROWIRE_CVE', '').strip()
    tag = os.environ.get('ZEROWIRE_TAG', '').strip()
    if cve:
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve, re.IGNORECASE):
            raise ValueError('ZEROWIRE_CVE must be a CVE ID')
        params['cve'] = cve.upper()
    if tag:
        if len(tag) > 100:
            raise ValueError('ZEROWIRE_TAG is too long')
        params['tag'] = tag
    req = Request(ENDPOINT + '?' + urlencode(params), headers={'Accept': 'application/json', 'User-Agent': 'ZeroWire-Companion-Example/1'})
    with urlopen(req, timeout=15) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError('Response exceeded size limit')
    result = json.loads(data)
    lines = ['## ZeroWire Companion intelligence', '', 'Events are locally observed; a match does not establish exposure.', '', '| Observed (UTC) | Event | CVE | Source |', '| --- | --- | --- | --- |']
    for item in result.get('items', []):
        url = str(item.get('source_url') or '')
        parsed = urlparse(url)
        source = f'[{text(item.get("source"))}]({url})' if parsed.scheme == 'https' and parsed.hostname in {'github.com', 'www.cisa.gov', 'radar.cloudflare.com', 'api.first.org'} and not any(c in url for c in '()<> \r\n') else text(item.get('source'))
        lines.append(f'| {text(item.get("observed_at"))} | {text(item.get("event_type"))} | {text(item.get("cve"))} | {source} |')
    if not result.get('items'):
        lines.extend(['', 'No matching events on this page. This does not establish safety.'])
    if result.get('next_cursor'):
        lines.extend(['', 'More events remain to be scanned; matches may appear on a later page. This example displays only the first page.'])
    lines.extend(['', 'Review source freshness and coverage before acting.'])
    summary = '\n'.join(lines) + '\n'
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as f:
            f.write(summary)
    else:
        print(summary, end='')

if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        print(f'ZeroWire summary unavailable: {type(error).__name__}', file=sys.stderr)
        sys.exit(1)
