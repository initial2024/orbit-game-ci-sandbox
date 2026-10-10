import test from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {readFile} from "node:fs/promises";
const schema=await readFile(new URL("../schema/game_identity_bridge.sql",import.meta.url),"utf8");
const open=()=>{const d=new DatabaseSync(":memory:");d.exec(schema);return d};
test("account game link migration is additive, idempotent and syntax-valid on SQLite",()=>{
 assert.doesNotMatch(schema,/\bDROP\s+TABLE\b|\bDELETE\s+FROM\s+(?:mailboxes|messages|local_accounts)\b/i);
 const d=open();d.exec(schema);
 const tables=d.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'account_game_%' ORDER BY name").all();
 assert.deepEqual(tables.map(x=>x.name),["account_game_deprovision_delivery","account_game_link_codes"]);d.close();
});
test("unique account index prevents simultaneous valid codes for the same subject",()=>{
 const d=open(),ins=d.prepare("INSERT INTO account_game_link_codes(code_hash,subject_id,created_at,expires_at,consumed_at) VALUES(?,?,?,?,NULL)");
 const now=Date.now();ins.run("hash-1","acct-fixture-1",now,now+600000);
 assert.throws(()=>ins.run("hash-2","acct-fixture-1",now,now+600000),/UNIQUE constraint failed/);
 ins.run("hash-3","acct-fixture-2",now,now+600000);
 assert.equal(d.prepare("SELECT COUNT(*) AS n FROM account_game_link_codes").get().n,2);d.close();
});
test("replacement code and expired code checks preserve one-time semantics",()=>{
 const d=open(),now=Date.now(),ins=d.prepare("INSERT INTO account_game_link_codes(code_hash,subject_id,created_at,expires_at,consumed_at) VALUES(?,?,?,?,NULL)");
 ins.run("old-hash","acct-fixture-1",now,now+600000);
 d.exec("BEGIN IMMEDIATE");d.prepare("DELETE FROM account_game_link_codes WHERE subject_id=?").run("acct-fixture-1");ins.run("new-hash","acct-fixture-1",now,now+600000);d.exec("COMMIT");
 assert.equal(d.prepare("SELECT COUNT(*) AS n FROM account_game_link_codes WHERE subject_id=?").get("acct-fixture-1").n,1);
 const consume=d.prepare("UPDATE account_game_link_codes SET consumed_at=? WHERE code_hash=? AND subject_id=? AND consumed_at IS NULL AND expires_at>?");
 assert.equal(consume.run(now+1,"old-hash","acct-fixture-1",now).changes,0);
 assert.equal(consume.run(now+2,"new-hash","acct-fixture-1",now).changes,1);
 assert.equal(consume.run(now+3,"new-hash","acct-fixture-1",now).changes,0);
 assert.equal(consume.run(now+4,"new-hash","acct-fixture-1",now+600001).changes,0);d.close();
});
test("deprovision acknowledgements are persistent and idempotent",()=>{
 const d=open(),now=Date.now();
 const ins=d.prepare("INSERT OR IGNORE INTO account_game_deprovision_delivery(account_id,attempts,retry_after,delivered_at,updated_at) VALUES(?,0,0,NULL,?)");
 assert.equal(ins.run("acct-fixture-1",now).changes,1);
 assert.equal(ins.run("acct-fixture-1",now).changes,0);
 assert.equal(d.prepare("UPDATE account_game_deprovision_delivery SET attempts=attempts+1,delivered_at=?,updated_at=? WHERE account_id=?").run(now,now,"acct-fixture-1").changes,1);
 const saved=d.prepare("SELECT * FROM account_game_deprovision_delivery WHERE account_id=?").get("acct-fixture-1");
 assert.equal(saved.attempts,1);assert.equal(saved.delivered_at,now);d.close();
});
