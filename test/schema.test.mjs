import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";

const migration = readFileSync(new URL("../migrations/0001_intelligence_foundation.sql", import.meta.url), "utf8");
const observed = "2026-11-04T00:00:00Z";

test("foundation migration enforces identity, relationships, valid snapshots and event deduplication", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("PRAGMA foreign_keys=ON");
    db.exec(migration);
    const insert = db.prepare("INSERT INTO briefings VALUES (?, ?, ?, ?)");
    insert.run("zw:synthetic", "https://example.invalid/synthetic", observed, observed);
    assert.throws(() => insert.run("zw:other", "https://example.invalid/synthetic", observed, observed), /UNIQUE/);
    const snapshot = db.prepare("INSERT INTO briefing_snapshots (briefing_id, revision, normalizer_version, semantic_hash, normalized_json, observed_at) VALUES (?, ?, ?, ?, ?, ?)");
    snapshot.run("zw:synthetic", 1, "v1", "a".repeat(64), "{}", observed);
    snapshot.run("zw:synthetic", 2, "v1", "b".repeat(64), "{}", observed);
    snapshot.run("zw:synthetic", 3, "v1", "a".repeat(64), "{}", observed);
    assert.throws(() => snapshot.run("zw:missing", 1, "v1", "a".repeat(64), "{}", observed), /FOREIGN KEY/);
    assert.throws(() => snapshot.run("zw:synthetic", 4, "v1", "a".repeat(64), "invalid JSON", observed), /CHECK/);
    db.prepare("INSERT INTO briefing_cves VALUES (?, ?)").run("zw:synthetic", "CVE-2099-10001");
    db.prepare("INSERT INTO briefing_cves VALUES (?, ?)").run("zw:synthetic", "CVE-2099-10002");
    insert.run("zw:no-cve", "https://example.invalid/no-cve", observed, observed);
    const event = db.prepare("INSERT INTO change_events (event_id, briefing_id, from_revision, to_revision, event_kind, observed_at, diff_json) VALUES (?, ?, ?, ?, ?, ?, ?)");
    event.run("event-1", "zw:synthetic", 1, 2, "changed", observed, "{}");
    event.run("event-2", "zw:synthetic", 2, 3, "changed", observed, "{}");
    assert.throws(() => event.run("event-duplicate", "zw:synthetic", 1, 2, "changed", observed, "{}"), /UNIQUE/);
    assert.throws(() => event.run("event-invalid", "zw:synthetic", null, 3, "changed", observed, "{}"), /CHECK/);
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM change_events").get().total, 2);
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM source_state").get().total, 0);
    assert.equal(db.prepare("SELECT version FROM schema_meta").get().version, 1);
  } finally { db.close(); }
});

test("state survives reopening and failed transactions preserve earlier snapshots", () => {
  const dir = mkdtempSync(join(tmpdir(), "zwc-schema-"));
  const filename = join(dir, "state.sqlite");
  let db = new DatabaseSync(filename);
  try {
    db.exec("PRAGMA foreign_keys=ON");db.exec(migration);
    db.prepare("INSERT INTO briefings VALUES (?, ?, ?, ?)").run("zw:test", "https://example.invalid/test", observed, observed);
    db.exec("BEGIN");
    db.prepare("INSERT INTO briefing_tags VALUES (?, ?, ?)").run("zw:test", "php", "PHP");
    assert.throws(() => db.prepare("INSERT INTO briefing_tags VALUES (?, ?, ?)").run("zw:missing", "tls", "TLS"), /FOREIGN KEY/);
    db.exec("ROLLBACK");db.close();db = new DatabaseSync(filename);
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM briefings").get().total, 1);
    assert.equal(db.prepare("SELECT COUNT(*) AS total FROM briefing_tags").get().total, 0);
    const plan = db.prepare("EXPLAIN QUERY PLAN SELECT briefing_id FROM briefing_cves WHERE cve_id = ? LIMIT 25").all("CVE-2099-10001");
    assert.ok(plan.some(row => row.detail.includes("briefing_cves_by_cve")));
  } finally { db.close();rmSync(dir, { recursive: true, force: true }); }
});
