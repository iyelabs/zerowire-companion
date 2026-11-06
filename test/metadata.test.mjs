import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {PROJECT_VERSION,SOURCE_USER_AGENT} from '../src/shared/version.ts';
test('release metadata and source user agent match the private package',()=>{
 const pkg=JSON.parse(readFileSync(new URL('../package.json',import.meta.url),'utf8'));const lock=JSON.parse(readFileSync(new URL('../package-lock.json',import.meta.url),'utf8'));
 assert.equal(pkg.private,true);assert.equal(pkg.license,'MIT');assert.equal(pkg.version,PROJECT_VERSION);assert.equal(lock.version,PROJECT_VERSION);assert.equal(lock.packages[''].version,PROJECT_VERSION);assert.equal(SOURCE_USER_AGENT,`ZeroWireCompanion-AI/${PROJECT_VERSION}`);
});
