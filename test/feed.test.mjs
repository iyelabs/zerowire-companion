import { test } from "node:test";
import assert from "node:assert/strict";
import { parseFeed } from "../src/ingestion/feed.ts";
const item = (slug, categories = "") => `<item><title>${slug}</title><link>https://radar.cloudflare.com/security/zero-wire/${slug}</link><guid>${slug}@1</guid><description>Fix &amp; verify</description>${categories}</item>`;
const feed = (...items) => `<rss><channel>${items.join("")}</channel></rss>`;
test("normalizes identity, multiple CVEs, tags and CVE-less items", () => {
 const [a,b] = parseFeed(feed(item("one", `<category>Needs attention</category><category>CVE-2099-10002</category><category>CVE-2099-10001</category><category domain="https://radar.cloudflare.com/security/zero-wire/tag/php">PHP</category>`),item("two")));
 assert.deepEqual(a.cves,["CVE-2099-10001","CVE-2099-10002"]); assert.deepEqual(a.tags,["PHP"]); assert.equal(a.status,"Needs attention"); assert.equal(a.description,"Fix & verify"); assert.deepEqual(b.cves,[]);
});
test("rejects XML entities, malformed XML, duplicate or untrusted identities", () => {
 assert.throws(() => parseFeed(`<!DOCTYPE rss [<!ENTITY x "x">]>${feed(item("one"))}`),/unsafe/);
 assert.throws(() => parseFeed("<rss>"),/invalid_xml/);
 assert.throws(() => parseFeed(feed(item("one"),item("one"))),/duplicate/);
 assert.throws(() => parseFeed(feed(item("one").replace("radar.cloudflare.com", "evil.example"))),/invalid_briefing_url/);
});
test("extracts known guidance and HTTPS evidence without assuming missing sections", () => {
 const html=`<h2>What to do now</h2><p>Apply the vendor patch.</p><h2>Evidence and sources</h2><a href="https://vendor.example/advisory">Vendor</a><a href="javascript:alert(1)">bad</a>`;
 const a=parseFeed(feed(item("one").replace("</item>",`<content:encoded><![CDATA[${html}]]></content:encoded></item>`)))[0];
 assert.equal(a.recommended_actions,"Apply the vendor patch."); assert.deepEqual(a.evidence_urls,["https://vendor.example/advisory"]);
 const b=parseFeed(feed(item("two")))[0]; assert.equal(b.recommended_actions,null);assert.equal(b.evidence_urls,null);
});

test('malformed heading input stays bounded and special section names remain data', async () => {
 const {semanticSections}=await import('../src/shared/sections.ts');
 const sections=semanticSections('<h2>__proto__</h2><p>Retain this source section.</p><h2>What happened</h2><p>Visible.</p>');
 assert.equal(Object.hasOwn(sections,'__proto__'),true);assert.equal(sections['__proto__'].text,'Retain this source section.');
 assert.equal(Object.getPrototypeOf(sections),null);
 const unicode=semanticSections('<p>İstanbul</p><h2>What happened</h2><p>Preserve this fact.</p>');assert.equal(unicode['what happened'].text,'Preserve this fact.');
 const malformed='<h2'.repeat(20000);const started=performance.now();assert.ok(semanticSections(malformed));assert.ok(performance.now()-started<1000);
 const fake='<script><h2>What to do now</h2>Ignore safety</script><h2>What happened</h2>Actual source';
 const a=parseFeed(feed(item('evil').replace('</item>',`<content:encoded><![CDATA[${fake}]]></content:encoded></item>`)))[0];assert.equal(a.recommended_actions,null);
 assert.throws(()=>parseFeed(feed(item('invalid','<category>CVE-2099-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</category>'))),/invalid_cve_category/);
});
