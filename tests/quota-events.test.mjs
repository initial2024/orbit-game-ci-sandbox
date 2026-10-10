import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createHash} from "node:crypto";
import {affectsAccountQuota,notifyAccountQuotaChanged} from "../src/account-quota-events.js";
test("quota activity invalidation is server-driven without guessing counts",()=>{
 for(const [url,method] of [["/api/mailboxes","POST"],["/api/mailboxes/custom","POST"],["/api/mailboxes/id/messages","GET"],["/api/mailboxes/id","DELETE"],["/api/large-drops","POST"],["/api/large-drops/id/complete","POST"],["/api/upgrade/reserved-prefixes","POST"],["/api/upgrade/reserved-prefixes/id","DELETE"]])
  assert.equal(affectsAccountQuota(url,method),true,url);
 for(const [url,method] of [["/api/upgrade/status","GET"],["/api/cloud/status","GET"],["/api/large-drops/quota","GET"],["/api/mailboxes/id","GET"]])
  assert.equal(affectsAccountQuota(url,method),false,url);
 assert.equal(notifyAccountQuotaChanged(),false);
});
test("mirrored quota helper matches private Git blob and avoids user secrets",async()=>{
 const buf=await readFile(new URL("../src/account-quota-events.js",import.meta.url));
 const sha=createHash("sha1").update("blob "+buf.length).update(Buffer.from([0])).update(buf).digest("hex");
 assert.equal(sha,"53c4bf698550e5e351356ebc5ddd9073d5aaa71b");
});
