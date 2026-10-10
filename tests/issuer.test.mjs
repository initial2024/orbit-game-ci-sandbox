import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {handleGameLinkRequest,orbitLinkTokenForTests,retryGameAccountDeprovision} from "../src/game-link-issuer.js";

const site="https://mail.test.example";
const secret="sandbox-synthetic-token-not-used-in-production-1234567890";
function database(){
 const accounts=new Set(["acct-591","acct-792"]),closed=new Set(),closing=new Set(),codes=new Map(),deliveries=new Map();
 const normalize=x=>x.replace(/\s+/g," ").trim();
 const store={
  accounts,closed,closing,codes,deliveries,
  prepare(sql){
   const query=normalize(sql);
   return {bind(...values){
    return {
     async first(){
      if(query.includes("SELECT id FROM local_accounts WHERE id=?"))return accounts.has(values[0])?{id:values[0]}:null;
      if(query.includes("FROM account_closures WHERE account_id=?"))return closed.has(values[0])?{account_id:values[0]}:null;
      if(query.includes("FROM account_closure_requests WHERE account_id=?"))return closing.has(values[0])?{state:"pending"}:null;
      if(query.includes("SELECT subject_id FROM account_game_link_codes WHERE code_hash=?")){const item=codes.get(values[0]);return item&&!item.consumed_at&&item.expires_at>values[1]?{subject_id:item.subject_id}:null;}
      if(query.includes("SELECT attempts FROM account_game_deprovision_delivery"))return{attempts:deliveries.get(values[0])?.attempts||0};
      return null;
     },
     async run(){
      if(query.startsWith("DELETE FROM account_game_link_codes WHERE subject_id=?")){
       for(const [key,v] of codes)if(v.subject_id===values[0])codes.delete(key);
       return{meta:{changes:1}};
      }
      if(query.startsWith("INSERT INTO account_game_link_codes")){
       const [code_hash,subject_id,created_at,expires_at]=values;
       if(codes.has(code_hash))return{meta:{changes:0}};
       codes.set(code_hash,{subject_id,created_at,expires_at,consumed_at:null});
       return{meta:{changes:1}};
      }
      if(query.startsWith("UPDATE account_game_link_codes SET consumed_at=?")){
       const [stamp,key,sub,expires]=values,item=codes.get(key);
       if(!item||item.subject_id!==sub||item.consumed_at!==null||item.expires_at<=expires)return{meta:{changes:0}};
       item.consumed_at=stamp;return{meta:{changes:1}};
      }
      if(query.startsWith("INSERT OR IGNORE INTO account_game_deprovision_delivery")){
       const [sub,created]=values;if(!deliveries.has(sub))deliveries.set(sub,{attempts:0,retry_after:0,delivered_at:null,updated_at:created});
       return{meta:{changes:1}};
      }
      if(query.startsWith("UPDATE account_game_deprovision_delivery SET attempts=attempts+1")){
       const entry=deliveries.get(values.at(-1));entry.attempts++;
       if(query.includes("delivered_at=?"))entry.delivered_at=values[0];
       else entry.retry_after=values[0];return{meta:{changes:1}};
      }
      return{meta:{changes:0}};
     },
     async all(){
      if(query.includes("FROM account_closures c LEFT JOIN account_game_deprovision_delivery")){
       return{results:[...closed].filter(sub=>{const row=deliveries.get(sub);return !row||(!row.delivered_at&&row.retry_after<=values[0])}).slice(0,5).map(account_id=>({account_id}))};
      }
      return{results:[]};
     }
    };
   }};
  },
  async batch(statements){const out=[];for(const s of statements)out.push(await s.run());return out;}
 };
 return store;
}
async function fixture(){
 const pair=await webcrypto.subtle.generateKey({name:"Ed25519"},true,["sign","verify"]);
 const priv=await webcrypto.subtle.exportKey("jwk",pair.privateKey),pub=await webcrypto.subtle.exportKey("jwk",pair.publicKey);
 const DB=database();
 const env={DB,GAME_LINK_ENABLED:"true",GAME_LINK_EXCHANGE_SECRET:secret,GAME_LINK_ED25519_PRIVATE_JWK:JSON.stringify(priv),
  GAME_LINK_ISSUER:"synthetic-orbit-game-issuer",GAME_LINK_AUDIENCE:"synthetic-orbit-city",GAME_LINK_DEPROVISION_ENDPOINT:""};
 return {env,pub,DB};
}
function request(path,payload={},options={}){
 return new Request(site+path,{method:options.method||"POST",headers:{
 "origin":options.origin??site,"content-type":"application/json",
 "x-test-client":options.client||"test-one",
 ...(options.bearer?{authorization:"Bearer "+options.bearer}:{})
 },body:JSON.stringify(payload)});
}
function issueRequest(payload={},options={}){
 return request("/api/account/game-link/code",payload,options);
}
function redeemRequest(code,bearer=secret,options={}){
 return request("/api/account/game-link/redeem",{code},{...options,bearer});
}
const deps=(sub="acct-591",approved=true)=>({
 session:async()=>sub?{subject_id:sub}:null,
 verifyStepUp:async(_env,_subject,payload)=>approved&&payload.confirm==="TEST_ONLY"?{ok:true}:{ok:false,error:"GAME_LINK_STEP_UP_REQUIRED"}
});
const decode=t=>{const [h,p,s]=String(t).split(".");return{header:JSON.parse(Buffer.from(h,"base64url").toString()),claims:JSON.parse(Buffer.from(p,"base64url").toString()),signature:Buffer.from(s,"base64url"),message:new TextEncoder().encode(h+"."+p)}};
test("issue fails closed if keys or enable switch are absent",async()=>{
 const {env}=await fixture();
 env.GAME_LINK_ENABLED="false";
 const r=await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps());
 assert.equal(r.status,503);assert.equal((await r.json()).error,"GAME_LINK_NOT_CONFIGURED");
});
test("issuer never accepts cross-origin step-up or missing account session",async()=>{
 const{env}=await fixture();
 assert.equal((await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"},{origin:"https://hostile.invalid"}),env,deps())).status,403);
 assert.equal((await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps(null))).status,403);
});
test("admin, revoked and pending-closure subjects cannot receive a binding code",async()=>{
 const{env,DB}=await fixture();
 assert.equal((await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps("admin:1"))).status,403);
 DB.closed.add("acct-591");
 assert.equal((await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).status,403);
 DB.closed.clear();DB.closing.add("acct-591");
 assert.equal((await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).status,403);
});
test("a second-factor failure cannot create any code",async()=>{
 const{env,DB}=await fixture();
 const r=await handleGameLinkRequest(issueRequest({confirm:"DENIED"}),env,deps());
 assert.equal(r.status,401);assert.equal(DB.codes.size,0);
});
test("real issuer module sends only an opaque, hashed, expiring single-use code",async()=>{
 const{env,DB}=await fixture();
 const r=await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps());
 assert.equal(r.status,200);
 const body=await r.json();
 assert.match(body.code,/^[A-HJ-NP-Z2-9]{12}$/);
 assert.ok(body.expires_at>Date.now()&&body.expires_at-Date.now()<=600000);
 assert.equal(DB.codes.size,1);
 const dbCode=[...DB.codes.keys()][0];
 assert.match(dbCode,/^[0-9a-f]{64}$/);
 assert.notEqual(dbCode,body.code);
 assert.ok(!JSON.stringify([...DB.codes.values()]).includes(body.code));
});
test("authorized redemption returns a cryptographically verifiable short-lived EdDSA JWT",async()=>{
 const{env,pub}=await fixture();
 const issued=await (await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 const r=await handleGameLinkRequest(redeemRequest(issued.code),env,{});
 assert.equal(r.status,200);
 const {ticket}=await r.json(),decoded=decode(ticket),key=await webcrypto.subtle.importKey("jwk",pub,{name:"Ed25519"},false,["verify"]);
 assert.equal(await webcrypto.subtle.verify("Ed25519",key,decoded.signature,decoded.message),true);
 assert.equal(decoded.header.alg,"EdDSA");
 assert.equal(decoded.claims.sub,"acct-591");
 assert.equal(decoded.claims.iss,env.GAME_LINK_ISSUER);
 assert.equal(decoded.claims.aud,env.GAME_LINK_AUDIENCE);
 assert.equal(decoded.claims.purpose,"game_login");
 assert.ok(decoded.claims.exp-decoded.claims.iat<=90);
 assert.ok(decoded.claims.nbf<=decoded.claims.iat);
 assert.ok(!ticket.includes("synthetic-token"));
});
test("replayed or concurrently redeemed codes are rejected by atomic consume",async()=>{
 const {env}=await fixture();
 const issued=await(await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 const results=await Promise.all(Array.from({length:6},()=>handleGameLinkRequest(redeemRequest(issued.code),env,{})));
 assert.equal(results.filter(x=>x.status===200).length,1);
 assert.equal(results.filter(x=>x.status!==200).length,5);
});
test("incorrect exchange secret cannot redeem a valid game link code",async()=>{
 const {env}=await fixture();
 const issued=await(await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 const bad=await handleGameLinkRequest(redeemRequest(issued.code,secret+"wrong"),env,{});
 assert.equal(bad.status,401);
 const good=await handleGameLinkRequest(redeemRequest(issued.code),env,{});
 assert.equal(good.status,200);
});
test("expired code cannot be redeemed and issuer does not silently renew it",async()=>{
 const {env,DB}=await fixture();
 const issued=await(await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 for(const c of DB.codes.values())c.expires_at=Date.now()-1;
 const r=await handleGameLinkRequest(redeemRequest(issued.code),env,{});
 assert.equal(r.status,401);
});
test("rate-limit service failure and brute-force bursts are blocked, not bypassed",async()=>{
 const {env}=await fixture();
 env.__testRateDbDown=true;
 const bad=await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps());
 assert.equal(bad.status,503);
 env.__testRateDbDown=false;
 let statuses=[];
 for(let i=0;i<5;i++)statuses.push((await handleGameLinkRequest(issueRequest({confirm:"DENIED"}),env,deps())).status);
 assert.equal(statuses.at(-1),429);
});
test("new link code invalidates the prior outstanding code for the same account",async()=>{
 const {env,DB}=await fixture();
 const first=await(await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 const second=await(await handleGameLinkRequest(issueRequest({confirm:"TEST_ONLY"}),env,deps())).json();
 assert.notEqual(first.code,second.code);assert.equal(DB.codes.size,1);
 assert.equal((await handleGameLinkRequest(redeemRequest(first.code),env,{})).status,401);
 assert.equal((await handleGameLinkRequest(redeemRequest(second.code),env,{})).status,200);
});
test("deprovisioning produces a purpose-separated ticket, never a game-login token",async()=>{
 const {env,pub}=await fixture();
 const jwt=await orbitLinkTokenForTests(env,"acct-591","account_deprovision");
 const d=decode(jwt),key=await webcrypto.subtle.importKey("jwk",pub,{name:"Ed25519"},false,["verify"]);
 assert.equal(d.claims.purpose,"account_deprovision");
 assert.equal(await webcrypto.subtle.verify("Ed25519",key,d.signature,d.message),true);
 await assert.rejects(orbitLinkTokenForTests(env,"admin:1","game_login"));
 await assert.rejects(orbitLinkTokenForTests(env,"acct-591","arbitrary_purpose"));
 assert.deepEqual(await retryGameAccountDeprovision({...env,GAME_LINK_ENABLED:"false"}),{enabled:false});
});
