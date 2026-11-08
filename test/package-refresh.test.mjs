import {SourceHttpError} from '../src/ingestion/source-http-error.ts';
import {test} from 'node:test';import assert from 'node:assert/strict';import {readFileSync,readdirSync} from 'node:fs';import {DatabaseSync} from 'node:sqlite';import {refreshPackages} from '../src/ingestion/packages.ts';
function setup(){const sql=new DatabaseSync(':memory:');for(const f of readdirSync(new URL('../migrations/',import.meta.url)).filter(x=>x.endsWith('.sql')).sort())sql.exec(readFileSync(new URL(`../migrations/${f}`,import.meta.url),'utf8'));const db={prepare(query){let p=[];return{bind(...v){p=v;return this},async first(){return sql.prepare(query).get(...p)??null},async all(){return {results:sql.prepare(query).all(...p)}},async run(){return sql.prepare(query).run(...p)}}},async batch(stmts){sql.exec('BEGIN');try{for(const s of stmts)await s.run();sql.exec('COMMIT')}catch(e){sql.exec('ROLLBACK');throw e}}};sql.prepare('INSERT INTO ingestion_lease VALUES(?,?,?)').run('scheduled','owner','9999-01-01T00:00:00.000Z');return {sql,db}}
const cve='CVE-2021-44228',id='GHSA-jfh8-c2jp-5v3q',at='2026-11-05T00:00:00.000Z';
const ghsa=[{ghsa_id:id,cve_id:cve,vulnerabilities:[{package:{ecosystem:'maven',name:'log4j-core'},vulnerable_version_range:'< 2.15',first_patched_version:'2.15'}]}];
const osv={id,aliases:[cve],affected:[{package:{ecosystem:'Maven',name:'log4j-core'},database_specific:{source:`https://github.com/github/advisory-database/blob/main/advisories/${id}/${id}.json`},ranges:[]}]};
test('bounded refresh preserves cached data across GHSA outage while independently refreshing OSV',async()=>{const {sql,db}=setup();try{sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);const seen=[];await refreshPackages(db,'owner',at,async url=>{seen.push(url);return url.includes('api.github.com')?ghsa:osv});assert.equal(seen.length,4);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisories').get().n,2);
 const later='2026-11-07T00:00:00.000Z',seen2=[];await refreshPackages(db,'owner',later,async url=>{seen2.push(url);if(url.includes('api.github.com'))throw Error('429');return osv});assert.equal(seen2.length,4);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisories').get().n,2);assert.equal(sql.prepare("SELECT last_error_code FROM package_source_state WHERE source='ghsa'").get().last_error_code,'source_refresh_failed');assert.equal(sql.prepare("SELECT last_success_at FROM package_source_state WHERE source='osv'").get().last_success_at,later);
}finally{sql.close()}});
test('rejects lost ingestion lease rather than accepting an uncommitted refresh',async()=>{const {sql,db}=setup();try{sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);sql.prepare('UPDATE ingestion_lease SET owner=?').run('other');await assert.rejects(refreshPackages(db,'owner',at,async()=>ghsa));assert.equal(sql.prepare('SELECT count(*) n FROM package_advisories').get().n,0)}finally{sql.close()}});
test('recent advisory discovery builds a baseline and records only later changes',async()=>{const {sql,db}=setup();try{const read=async url=>url.includes('api.github.com')?ghsa:osv;await refreshPackages(db,'owner',at,read);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,0);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisories').get().n,2);const modified=[{...ghsa[0],vulnerabilities:[{...ghsa[0].vulnerabilities[0],first_patched_version:'2.16'}]}];await refreshPackages(db,'owner','2026-11-05T07:00:00.000Z',async url=>url.includes('api.github.com')?modified:osv);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,1);assert.equal(sql.prepare('SELECT event_kind FROM package_advisory_events').get().event_kind,'advisory.changed');}finally{sql.close()}});
test('targeted GHSA refresh records a changed advisory even outside the discovery page',async()=>{const {sql,db}=setup();try{sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);await refreshPackages(db,'owner',at,async url=>url.includes('api.github.com')?ghsa:osv);const later='2026-11-07T00:00:00.000Z';const modified=[{...ghsa[0],vulnerabilities:[{...ghsa[0].vulnerabilities[0],first_patched_version:'2.17'}]}];await refreshPackages(db,'owner',later,async url=>url.includes('api.github.com')?(url.includes('cve_id=')?modified:[]):osv);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,1);assert.equal(sql.prepare('SELECT event_kind FROM package_advisory_events').get().event_kind,'advisory.changed');}finally{sql.close()}});
test('GHSA pagination resumes on the next bounded refresh and completes coverage',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const alphabet='23456789cf';const many=[...alphabet].map(ch=>({...ghsa[0],ghsa_id:`GHSA-${ch}222-2222-2222`}));
 const read=async url=>{if(url.includes('sort=updated'))return [];if(url.includes('api.github.com'))return new URL(url).searchParams.get('page')==='1'?many:[];throw Error('OSV unavailable')};
 await refreshPackages(db,'owner',at,read);let state=sql.prepare("SELECT cursor,coverage_complete FROM package_source_state WHERE source='ghsa'").get();assert.equal(state.cursor,'2');assert.equal(state.coverage_complete,0);assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='ghsa'").get().n,10);
 await refreshPackages(db,'owner','2026-11-05T02:00:00.000Z',read);state=sql.prepare("SELECT cursor,coverage_complete FROM package_source_state WHERE source='ghsa'").get();assert.equal(state.cursor,null);assert.equal(state.coverage_complete,1);assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='ghsa'").get().n,10);
}finally{sql.close()}});
test('native OSV CVE refresh is independent of GHSA and preserves old data on failure',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const native={id:cve,aliases:[id],affected:[{package:{ecosystem:'npm',name:'example'},database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[{type:'SEMVER',events:[{introduced:'0'},{fixed:'2.0'}]}]}]};
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))throw Error('unavailable');if(url.endsWith(cve))return native;throw Error('unexpected')});
 const row=sql.prepare("SELECT * FROM package_advisories WHERE source='osv' AND advisory_id=?").get(cve);assert.ok(row);assert.equal(JSON.parse(row.normalized_json).packages[0].name,'example');assert.equal(sql.prepare('SELECT last_success_at FROM osv_cve_state WHERE cve_id=?').get(cve).last_success_at,at);
 const later='2026-11-07T00:00:00.000Z';await refreshPackages(db,'owner',later,async()=>{throw Error('outage')});assert.equal(sql.prepare('SELECT last_error_code FROM osv_cve_state WHERE cve_id=?').get(cve).last_error_code,'source_refresh_failed');assert.equal(sql.prepare("SELECT retrieved_at FROM package_advisories WHERE source='osv' AND advisory_id=?").get(cve).retrieved_at,at);
}finally{sql.close()}});
test('verified OSV withdrawal removes only the native cached record and is not treated as a source outage',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const native={id:cve,affected:[{database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[]}]};
 await refreshPackages(db,'owner',at,async url=>url.endsWith(cve)?native:[]);
 await refreshPackages(db,'owner','2026-11-07T00:00:00.000Z',async url=>url.endsWith(cve)?{id:cve,withdrawn:'2026-11-06T00:00:00Z'}:[]);
 assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='osv' AND advisory_id=?").get(cve).n,0);assert.equal(sql.prepare('SELECT last_error_code FROM osv_cve_state WHERE cve_id=?').get(cve).last_error_code,'record_withdrawn');
}finally{sql.close()}});
test('initial targeted GHSA enrichment does not create false events immediately after discovery baseline',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 await refreshPackages(db,'owner',at,async url=>url.includes('sort=updated')?[]:url.includes('api.github.com')?ghsa:osv);
 assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='ghsa'").get().n,1);assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,0);
}finally{sql.close()}});
test('GHSA metadata and package order do not produce false material changes',async()=>{const {sql,db}=setup();try{
 const second={package:{ecosystem:'npm',name:'example'},vulnerable_version_range:'< 2.0',first_patched_version:'2.0'};const base=[{...ghsa[0],updated_at:'2026-11-01T00:00:00Z',vulnerabilities:[ghsa[0].vulnerabilities[0],second]}];
 await refreshPackages(db,'owner',at,async url=>url.includes('api.github.com')?base:osv);
 const reordered=[{...base[0],updated_at:'2026-11-02T00:00:00Z',vulnerabilities:[second,ghsa[0].vulnerabilities[0]]}];await refreshPackages(db,'owner','2026-11-05T07:00:00.000Z',async url=>url.includes('api.github.com')?reordered:osv);
 assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,0);
 const withdrawn=[{...reordered[0],withdrawn_at:'2026-11-05T08:00:00Z'}];await refreshPackages(db,'owner','2026-11-05T14:00:00.000Z',async url=>url.includes('api.github.com')?withdrawn:osv);
 assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,1);
}finally{sql.close()}});
test('truncated GHSA advisory retains source modification as a review signal',async()=>{const {sql,db}=setup();try{
 const many=Array.from({length:21},(_,i)=>({package:{ecosystem:'npm',name:`pkg-${i}`},vulnerable_version_range:'< 1.0',first_patched_version:'1.0'}));
 const first=[{...ghsa[0],updated_at:'2026-11-01T00:00:00Z',vulnerabilities:many}];await refreshPackages(db,'owner',at,async url=>url.includes('api.github.com')?first:osv);
 const changed=[{...first[0],updated_at:'2026-11-02T00:00:00Z',vulnerabilities:many.map((v,i)=>i===20?{...v,first_patched_version:'1.1'}:v)}];await refreshPackages(db,'owner','2026-11-05T07:00:00.000Z',async url=>url.includes('api.github.com')?changed:osv);
 assert.equal(sql.prepare('SELECT count(*) n FROM package_advisory_events').get().n,1);assert.equal(JSON.parse(sql.prepare("SELECT normalized_json FROM package_advisories WHERE source='ghsa'").get().normalized_json).truncated,true);
}finally{sql.close()}});
test('native CVE discovers RustSec independently and preserves its cache on outage',async()=>{const {sql,db}=setup();try{
 const cve='CVE-2021-20319',id='RUSTSEC-2022-0103';sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const native={id:cve,aliases:[id],affected:[{database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[]}]};
 const rust={id,aliases:[cve],affected:[{package:{ecosystem:'crates.io',name:'coreos-installer'},database_specific:{source:`https://github.com/rustsec/advisory-db/blob/osv/crates/${id}.json`},ranges:[]}]};
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))throw Error('GHSA outage');if(url.endsWith(cve))return native;if(url.endsWith(id))return rust;throw Error('unexpected')});
 assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='osv'").get().n,2);assert.equal(sql.prepare('SELECT last_error_code FROM osv_alias_queue WHERE advisory_id=?').get(id).last_error_code,null);
 await refreshPackages(db,'owner','2026-11-07T00:00:00.000Z',async()=>{throw Error('outage')});assert.equal(sql.prepare('SELECT last_error_code FROM osv_alias_queue WHERE advisory_id=?').get(id).last_error_code,'source_refresh_failed');assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='osv'").get().n,2);
}finally{sql.close()}});

test('native OSV 404 is a bounded negative lookup and retains previously cached evidence',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const native={id:cve,affected:[{database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[]}]};
 await refreshPackages(db,'owner',at,async url=>url.endsWith(cve)?native:[]);
 const later='2026-11-07T00:00:00.000Z';await refreshPackages(db,'owner',later,async url=>{if(url.endsWith(cve))throw new SourceHttpError(404);return []});
 const state=sql.prepare('SELECT * FROM osv_cve_state WHERE cve_id=?').get(cve);assert.equal(state.last_error_code,'record_not_found');assert.equal(state.last_success_at,later);assert.equal(sql.prepare("SELECT retrieved_at FROM package_advisories WHERE source='osv' AND advisory_id=?").get(cve).retrieved_at,at);
 let nativeCalls=0;await refreshPackages(db,'owner','2026-11-07T02:00:00.000Z',async url=>{if(url.endsWith(cve))nativeCalls++;return []});assert.equal(nativeCalls,0);
}finally{sql.close()}});
test('package refresh prioritizes new KEV and periodically advances older KEV',async()=>{const {sql,db}=setup();try{
 const base='2026-11-05T00:00:00.000Z',old='CVE-2099-90001',recent='CVE-2099-10001';const insert=sql.prepare('INSERT INTO kev_catalog VALUES(?,?,?,?,?,?,?,?,?)');
 insert.run(old,'Old','Product','2020-01-01','{}','v',base,base,base);insert.run(recent,'New','Product','2026-11-04','{}','v',base,base,base);
 const normal=new Date(Date.parse(base)+[1,2,3,4].find(n=>Math.floor((Date.parse(base)+n*3600000)/3600000)%4!==0)*3600000).toISOString();
 const seen=[];await refreshPackages(db,'owner',normal,async url=>{if(url.includes('cve_id='))seen.push(new URL(url).searchParams.get('cve_id'));return url.includes('api.github.com')?[]:{id:'none'}});assert.equal(seen[0],recent);
 sql.prepare('DELETE FROM package_source_state').run();sql.prepare('DELETE FROM osv_cve_state').run();
 const fair=new Date(Date.parse(normal)+(4-Math.floor(Date.parse(normal)/3600000)%4)*3600000).toISOString();const seenFair=[];await refreshPackages(db,'owner',fair,async url=>{if(url.includes('cve_id='))seenFair.push(new URL(url).searchParams.get('cve_id'));return url.includes('api.github.com')?[]:{id:'none'}});assert.equal(seenFair[0],old);
}finally{sql.close()}});
test('failed GHSA discovery retries after one hour and preserves source status',async()=>{const {sql,db}=setup();try{
 let calls=0;await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com')){calls++;throw new SourceHttpError(429)}throw Error('unexpected')});
 assert.equal(sql.prepare('SELECT last_error_code FROM package_feed_state').get().last_error_code,'source_http_429');
 await refreshPackages(db,'owner','2026-11-05T00:30:00.000Z',async()=>{calls++;return ghsa});assert.equal(calls,1);
 await refreshPackages(db,'owner','2026-11-05T01:00:00.000Z',async url=>{if(url.includes('api.github.com')){calls++;return ghsa}return osv});assert.equal(calls,2);const state=sql.prepare('SELECT * FROM package_feed_state').get();assert.equal(state.last_error_code,null);assert.ok(state.baseline_at);
}finally{sql.close()}});
test('GHSA targeted throttling records HTTP status and preserves previously cached advisory',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 await refreshPackages(db,'owner',at,async url=>url.includes('api.github.com')?ghsa:osv);
 const later='2026-11-07T00:00:00.000Z';await refreshPackages(db,'owner',later,async url=>{if(url.includes('api.github.com')&&url.includes('cve_id='))throw new SourceHttpError(403);return url.includes('api.github.com')?[]:osv});
 const state=sql.prepare("SELECT last_error_code FROM package_source_state WHERE source='ghsa' AND cve_id=?").get(cve);assert.equal(state.last_error_code,'source_http_403');assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM package_advisories WHERE source='ghsa' AND cve_id=?").get(cve).n,1);
}finally{sql.close()}});
test('GHSA 403 applies source-wide backoff while independent OSV refresh continues',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 let ghsaRequests=0,osvRequests=0;const read=async url=>{if(url.includes('api.github.com')){ghsaRequests++;throw new SourceHttpError(403)}osvRequests++;return {id:cve,affected:[{database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[]}]}};
 await refreshPackages(db,'owner',at,read);assert.equal(ghsaRequests,1);assert.equal(osvRequests,1);assert.equal(sql.prepare('SELECT last_error_code FROM package_feed_state').get().last_error_code,'source_http_403');
 await refreshPackages(db,'owner','2026-11-05T00:30:00.000Z',read);assert.equal(ghsaRequests,1);
 await refreshPackages(db,'owner','2026-11-05T01:00:00.000Z',read);assert.equal(ghsaRequests,2);
}finally{sql.close()}});
test('native CVE discovers verified GHSA alias through OSV during GitHub outage',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const native={id:cve,aliases:[id],affected:[{database_specific:{source:`https://storage.googleapis.com/cve-osv-conversion/osv-output/${cve}.json`},ranges:[]}]};
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))throw new SourceHttpError(403);if(url.endsWith(cve))return native;if(url.endsWith(id))return osv;throw Error('unexpected')});
 const advisory=sql.prepare("SELECT normalized_json FROM package_advisories WHERE source='osv' AND advisory_id=?").get(id);assert.ok(advisory);assert.equal(JSON.parse(advisory.normalized_json).packages[0].name,'log4j-core');assert.equal(sql.prepare('SELECT last_error_code FROM osv_alias_queue WHERE advisory_id=?').get(id).last_error_code,null);assert.equal(sql.prepare('SELECT alias_scan_at FROM osv_cve_state WHERE cve_id=?').get(cve).alias_scan_at,at);
}finally{sql.close()}});
test('GitHub primary reset and Retry-After gate all GHSA calls without blocking OSV',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 const details={reason:'primary_rate_limit',remaining:0,resetAt:'2026-11-05T03:00:00.000Z',retryAfterSeconds:14400,invalidRetryAfter:false};
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))throw new SourceHttpError(403,details);return osv});
 let policy=sql.prepare('SELECT * FROM ghsa_retry_policy').get();assert.equal(policy.retry_not_before,'2026-11-05T04:00:00.000Z');assert.equal(policy.suspended,0);
 let ghsaCalls=0,osvCalls=0;await refreshPackages(db,'owner','2026-11-05T02:00:00.000Z',async url=>{if(url.includes('api.github.com'))ghsaCalls++;else osvCalls++;return url.includes('api.github.com')?ghsa:osv});assert.equal(ghsaCalls,0);assert.ok(osvCalls>0);
 await refreshPackages(db,'owner','2026-11-05T04:00:01.000Z',async url=>url.includes('api.github.com')?ghsa:osv);assert.equal(sql.prepare('SELECT * FROM ghsa_retry_policy').get(),undefined);
}finally{sql.close()}});
test('GHSA persistent rate limits stop after five failures and permanent forbidden suspends',async()=>{const {sql,db}=setup();try{
 const detail={reason:'secondary_rate_limit',remaining:1,resetAt:null,retryAfterSeconds:null,invalidRetryAfter:false};
 for(let i=0;i<5;i++){const now=new Date(Date.parse(at)+(2**i-1)*3600000).toISOString();await refreshPackages(db,'owner',now,async url=>{if(url.includes('api.github.com'))throw new SourceHttpError(403,detail);return osv});}
 assert.equal(sql.prepare('SELECT failures,suspended FROM ghsa_retry_policy').get().failures,5);assert.equal(sql.prepare('SELECT suspended FROM ghsa_retry_policy').get().suspended,1);let attempts=0;
 await refreshPackages(db,'owner','2026-12-05T00:00:00.000Z',async url=>{if(url.includes('api.github.com'))attempts++;return osv});assert.equal(attempts,0);
 sql.prepare('DELETE FROM ghsa_retry_policy').run();sql.prepare('DELETE FROM package_feed_state').run();await refreshPackages(db,'owner','2026-12-06T00:00:00.000Z',async url=>{if(url.includes('api.github.com'))throw new SourceHttpError(403,{...detail,reason:'forbidden'});return osv});assert.equal(sql.prepare('SELECT suspended FROM ghsa_retry_policy').get().suspended,1);
}finally{sql.close()}});
test('eligible previously rate-limited GHSA CVE is retried before untouched background entries',async()=>{const {sql,db}=setup();try{
 const old='CVE-2010-5326',recent='CVE-2026-99999';sql.prepare('INSERT INTO kev_catalog VALUES(?,?,?,?,?,?,?,?,?)').run(recent,'Vendor','Product','2026-11-04','{}','v',at,at,at);
 sql.prepare("INSERT INTO package_source_state(source,cve_id,last_attempt_at,last_error_code,coverage_complete) VALUES('ghsa',?,?,'source_http_403',0)").run(old,at);
 sql.prepare('INSERT INTO package_feed_state(singleton,baseline_at,last_attempt_at,last_success_at,last_error_code) VALUES(1,?,?,?,NULL)').run(at,'2026-11-05T00:20:00.000Z','2026-11-05T00:20:00.000Z');
 const seen=[];await refreshPackages(db,'owner','2026-11-05T00:30:00.000Z',async url=>{if(url.includes('cve_id=')){seen.push(new URL(url).searchParams.get('cve_id'));return []}if(url.includes('api.github.com'))return [];return osv});assert.deepEqual(seen,[old]);assert.equal(sql.prepare("SELECT last_error_code FROM package_source_state WHERE source='ghsa' AND cve_id=?").get(old).last_error_code,null);
}finally{sql.close()}});

test('expired suspended primary rate limit gets one bounded recovery probe and clears on success',async()=>{const {sql,db}=setup();try{
 sql.prepare("INSERT INTO ghsa_retry_policy(singleton,failures,retry_not_before,suspended,reason,last_status,remaining,reset_at) VALUES(1,5,?,1,'primary_rate_limit',403,0,?)").run('2026-11-05T01:00:01.000Z','2026-11-05T01:00:00.000Z');
 let calls=0;const okay=async url=>{if(url.includes('api.github.com'))calls++;return url.includes('api.github.com')?[]:osv};
 await refreshPackages(db,'owner','2026-11-05T01:00:00.000Z',okay);assert.equal(calls,0);
 await refreshPackages(db,'owner','2026-11-05T02:00:00.000Z',okay);assert.equal(calls,1);assert.equal(sql.prepare('SELECT * FROM ghsa_retry_policy').get(),undefined);
}finally{sql.close()}});
test('persistent primary limit uses daily cooldown, invalid reset remains suspended',async()=>{const {sql,db}=setup();try{
 sql.prepare("INSERT INTO ghsa_retry_policy(singleton,failures,retry_not_before,suspended,reason,last_status,remaining,reset_at) VALUES(1,5,?,1,'primary_rate_limit',403,0,?)").run('2026-11-05T01:00:01.000Z','2026-11-05T01:00:00.000Z');
 let calls=0;const fail=async url=>{if(url.includes('api.github.com')){calls++;throw new SourceHttpError(403,{reason:'primary_rate_limit',remaining:0,resetAt:'2026-11-05T03:00:00.000Z',retryAfterSeconds:null,invalidRetryAfter:false})}return osv};
 await refreshPackages(db,'owner','2026-11-05T02:00:00.000Z',fail);assert.equal(calls,1);assert.equal(sql.prepare('SELECT retry_not_before FROM ghsa_retry_policy').get().retry_not_before,'2026-11-06T02:00:00.000Z');
 await refreshPackages(db,'owner','2026-11-06T01:00:00.000Z',fail);assert.equal(calls,1);
 sql.prepare("UPDATE ghsa_retry_policy SET reason='invalid_retry_after'").run();await refreshPackages(db,'owner','2026-11-07T01:00:00.000Z',fail);assert.equal(calls,1);
}finally{sql.close()}});
test('OSV errors preserve safe cause and cached data, and alias 404 is dated absence',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 sql.prepare('INSERT INTO osv_alias_queue(cve_id,advisory_id) VALUES(?,?)').run(cve,id);
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))return [];if(url.endsWith(id))throw new SourceHttpError(404);throw new SourceHttpError(429)});
 assert.equal(sql.prepare('SELECT last_error_code FROM osv_cve_state WHERE cve_id=?').get(cve).last_error_code,'source_http_429');
 const alias=sql.prepare('SELECT last_error_code,last_success_at FROM osv_alias_queue WHERE advisory_id=?').get(id);assert.equal(alias.last_error_code,'record_not_found');assert.equal(alias.last_success_at,at);
 let aliasCalls=0;await refreshPackages(db,'owner','2026-11-05T02:00:00.000Z',async url=>{if(url.endsWith(id))aliasCalls++;if(url.endsWith(cve))throw new SyntaxError('secret upstream content');return []});
 assert.equal(aliasCalls,0);assert.equal(sql.prepare('SELECT last_error_code FROM osv_cve_state WHERE cve_id=?').get(cve).last_error_code,'source_invalid_json');
}finally{sql.close()}});
test('HTTP 200 OSV native record lacking affected is dated absence, not an outage',async()=>{const {sql,db}=setup();try{
 sql.prepare('INSERT INTO briefings VALUES(?,?,?,?)').run('b','https://example.test',at,at);sql.prepare('INSERT INTO briefing_cves VALUES(?,?)').run('b',cve);
 await refreshPackages(db,'owner',at,async url=>url.endsWith(cve)?{id:cve}:[]);
 const state=sql.prepare('SELECT last_error_code,last_success_at FROM osv_cve_state WHERE cve_id=?').get(cve);assert.equal(state.last_error_code,'record_no_affected_data');assert.equal(state.last_success_at,at);
 assert.equal(sql.prepare("SELECT count(*) n FROM package_advisories WHERE source='osv'").get().n,0);
}finally{sql.close()}});
test('missing OSV GHSA alias does not stall batch and remains a dated per-alias absence',async()=>{const {sql,db}=setup();try{
 await refreshPackages(db,'owner',at,async url=>{if(url.includes('api.github.com'))return ghsa;throw new SourceHttpError(404)});
 const state=sql.prepare("SELECT last_error_code,coverage_complete FROM package_source_state WHERE source='osv' AND cve_id=?").get(cve);
 assert.equal(state.last_error_code,null);assert.equal(state.coverage_complete,1);
 const alias=sql.prepare('SELECT last_error_code,last_success_at FROM osv_alias_queue WHERE cve_id=? AND advisory_id=?').get(cve,id);
 assert.equal(alias.last_error_code,'record_not_found');assert.equal(alias.last_success_at,at);
}finally{sql.close()}});
