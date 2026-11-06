import {test} from 'node:test';import assert from 'node:assert/strict';import {githubFailure} from '../src/ingestion/source-http-error.ts';
test('classifies and bounds GitHub rate-limit metadata without exposing body',async()=>{
 const now=Date.parse('2026-11-05T14:00:00Z');let r=new Response('{"message":"API rate limit exceeded"}',{status:403,headers:{'x-ratelimit-remaining':'0','x-ratelimit-reset':String((now+3600000)/1000),'retry-after':'7200'}});let x=await githubFailure(r,now);assert.equal(x.reason,'primary_rate_limit');assert.equal(x.resetAt,'2026-11-05T15:00:00.000Z');assert.equal(x.retryAfterSeconds,7200);assert.equal('message' in x,false);
 r=new Response('{"message":"secondary rate limit"}',{status:403,headers:{'x-ratelimit-remaining':'12'}});assert.equal((await githubFailure(r,now)).reason,'secondary_rate_limit');
 r=new Response('{"message":"permission denied"}',{status:403,headers:{'retry-after':'9999999999'}});x=await githubFailure(r,now);assert.equal(x.reason,'forbidden');assert.equal(x.invalidRetryAfter,true);
});

test('retains rate-limit headers if the error body stream fails',async()=>{const now=Date.parse('2026-11-05T14:00:00Z');const body=new ReadableStream({start(controller){controller.error(new Error('broken body'))}});const r=new Response(body,{status:403,headers:{'x-ratelimit-remaining':'0','x-ratelimit-reset':String((now+3600000)/1000)}});const x=await githubFailure(r,now);assert.equal(x.reason,'primary_rate_limit');assert.equal(x.resetAt,'2026-11-05T15:00:00.000Z');});
