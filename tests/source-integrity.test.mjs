import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFile} from "node:fs/promises";
const root=new URL("../",import.meta.url);
test("public test module matches the private PR's reviewed Git blob exactly",async()=>{
 const manifest=JSON.parse(await readFile(new URL("source-manifest.json",root),"utf8"));
 const bytes=await readFile(new URL(manifest.sandboxFile,root));
 const hash=createHash("sha1").update("blob "+bytes.length+"\0").update(bytes).digest("hex");
 assert.equal(hash,manifest.gitBlobSha);
 assert.equal(manifest.sourcePR,487);
});
test("sandbox contains no embedded private key material, bearer secrets, or real user values",async()=>{
 const text=await readFile(new URL("src/game-link-issuer.js",root),"utf8");
 assert.doesNotMatch(text,/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/);
 assert.doesNotMatch(text,/github_pat_[A-Za-z0-9_]{20}/);
 assert.doesNotMatch(text,/ghp_[A-Za-z0-9]{20}/);
 assert.doesNotMatch(text,/sk_live_[A-Za-z0-9]{16}/);
 assert.doesNotMatch(text,/\b(?:GAME_LINK_EXCHANGE_SECRET|GAME_LINK_ED25519_PRIVATE_JWK)\s*:\s*["'][^"']{32}/);
});

test("mirrored additive game identity schema matches its reviewed private Git blob",async()=>{
 const manifest=JSON.parse(await readFile(new URL("source-manifest.json",root),"utf8"));
 const bytes=await readFile(new URL(manifest.schemaPath,root));
 const hash=createHash("sha1").update("blob "+bytes.length).update(Buffer.from([0])).update(bytes).digest("hex");
 assert.equal(hash,manifest.schemaGitBlobSha);
});
