// Orbit game identity bridge — main account site only. No credentials are shared with the game.
// Disabled until migrations, key pair, and the separate game verification service are reviewed.
import {claimRequestRateLimit,readJsonBodyLimited} from "./security-guard.js";
const ALPHABET="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const enc=new TextEncoder();
const json=(value,status=200)=>Response.json(value,{status,headers:{"cache-control":"no-store","x-content-type-options":"nosniff","referrer-policy":"no-referrer","vary":"Origin"}});
const err=(code,status=400)=>json({ok:false,error:code},status);
const codePattern=/^[A-HJ-NP-Z2-9]{12}$/;
const subjectPattern=/^[-A-Za-z0-9_:]{5,128}$/;
const stamp=()=>Date.now(),seconds=()=>Math.floor(Date.now()/1000);
const b64=bytes=>btoa(Array.from(bytes,v=>String.fromCharCode(v)).join("")).split("+").join("-").split("/").join("_").replace(/=+$/,"");
const randomToken=()=>b64(crypto.getRandomValues(new Uint8Array(24)));
const randomCode=()=>Array.from(crypto.getRandomValues(new Uint8Array(12)),v=>ALPHABET[v&31]).join("");
const issuerReady=env=>String(env.GAME_LINK_ENABLED||"")==="true"&&typeof env.GAME_LINK_ED25519_PRIVATE_JWK==="string"&&
 String(env.GAME_LINK_EXCHANGE_SECRET||"").length>=32&&/^[-a-zA-Z0-9_:.\/]{6,160}$/.test(String(env.GAME_LINK_ISSUER||""))&&
 /^[-a-zA-Z0-9_:.-]{6,160}$/.test(String(env.GAME_LINK_AUDIENCE||""))&&Boolean(env.DB);
async function codeHash(env,code){
 const key=await crypto.subtle.importKey("raw",enc.encode(env.GAME_LINK_EXCHANGE_SECRET),"HMAC",false,["sign"]);
 return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC",key,enc.encode("orbit-game-link:v1:"+code))),v=>v.toString(16).padStart(2,"0")).join("");
}
async function signTicket(env,subject,purpose="game_login"){
 const jwk=JSON.parse(env.GAME_LINK_ED25519_PRIVATE_JWK);
 if(jwk.kty!=="OKP"||jwk.crv!=="Ed25519"||typeof jwk.x!=="string"||typeof jwk.d!=="string")throw Error("INVALID_SIGNING_KEY");
 if(!subjectPattern.test(subject)||subject.startsWith("admin:")||!["game_login","account_deprovision"].includes(purpose))throw Error("INVALID_CLAIMS");
 const key=await crypto.subtle.importKey("jwk",jwk,{name:"Ed25519"},false,["sign"]);
 const now=seconds(),claims={iss:env.GAME_LINK_ISSUER,aud:env.GAME_LINK_AUDIENCE,sub:subject,
  purpose,jti:randomToken(),iat:now,nbf:now,exp:now+90};
 const head=b64(enc.encode(JSON.stringify({alg:"EdDSA",typ:"JWT"})));
 const payload=b64(enc.encode(JSON.stringify(claims)));
 const part=head+"."+payload;
 const sig=await crypto.subtle.sign({name:"Ed25519"},key,enc.encode(part));
 return part+"."+b64(new Uint8Array(sig));
}
export async function orbitLinkTokenForTests(env,sub,purpose){return signTicket(env,sub,purpose);}
const sameOrigin=request=>request.headers.get("origin")===new URL(request.url).origin;
async function checkGate(env,request,scope,limit){
 try{const result=await claimRequestRateLimit(env,request,"orbit-game-link-"+scope,limit,{windowMs:60000});
 return result.allowed?null:err("GAME_LINK_RATE_LIMITED",429);}
 catch{return err("GAME_LINK_SECURITY_UNAVAILABLE",503);}
}
async function accountAllowed(env,sub){
 if(!subjectPattern.test(sub)||sub.startsWith("admin:"))return false;
 const row=await env.DB.prepare("SELECT id FROM local_accounts WHERE id=?").bind(sub).first();
 if(!row)return false;
 const revoked=await env.DB.prepare("SELECT account_id FROM account_closures WHERE account_id=? LIMIT 1").bind(sub).first();
 if(revoked)return false;
 const closing=await env.DB.prepare("SELECT state FROM account_closure_requests WHERE account_id=? AND state IN ('pending','finalizing') LIMIT 1").bind(sub).first();
 return !closing;
}
async function issue(request,env,{session,verifyStepUp}){
 if(!sameOrigin(request))return err("GAME_LINK_ORIGIN_REJECTED",403);
 if(!issuerReady(env))return err("GAME_LINK_NOT_CONFIGURED",503);
 const gate=await checkGate(env,request,"issue",4);if(gate)return gate;
 const auth=await session(env,request),sub=String(auth?.subject_id||"");
 if(!auth||!await accountAllowed(env,sub))return err("GAME_LINK_ACCOUNT_NOT_ALLOWED",403);
 const parsed=await readJsonBodyLimited(request,1024);
 if(!parsed.ok)return err("GAME_LINK_INVALID_BODY",400);
 const strong=await verifyStepUp(env,sub,parsed.payload);
 if(!strong?.ok)return err(strong?.error||"GAME_LINK_STEP_UP_REQUIRED",401);
 const code=randomCode(),hash=await codeHash(env,code),now=stamp(),expires=now+10*60*1000;
 await env.DB.batch([
  env.DB.prepare("DELETE FROM account_game_link_codes WHERE subject_id=?").bind(sub),
  env.DB.prepare("INSERT INTO account_game_link_codes(code_hash,subject_id,created_at,expires_at,consumed_at) VALUES(?,?,?,?,NULL)").bind(hash,sub,now,expires)
 ]);
 return json({ok:true,code,expires_at:expires,purpose:"game_login",single_use:true});
}
async function redeem(request,env){
 if(!issuerReady(env))return err("GAME_LINK_NOT_CONFIGURED",503);
 const gate=await checkGate(env,request,"redeem",12);if(gate)return gate;
 const raw=String(request.headers.get("authorization")||"");
 const bearer=raw.startsWith("Bearer ")?raw.slice(7):"";
 // Compare cryptographic digests in constant time before touching any account rows.
 const expected=enc.encode(String(env.GAME_LINK_EXCHANGE_SECRET||""));
 const given=enc.encode(bearer);
 if(given.length!==expected.length)return err("GAME_LINK_SERVICE_UNAUTHORIZED",401);
 let mask=0;for(let i=0;i<expected.length;i++)mask|=expected[i]^given[i];
 if(mask!==0)return err("GAME_LINK_SERVICE_UNAUTHORIZED",401);
 const parsed=await readJsonBodyLimited(request,1024);
 if(!parsed.ok)return err("GAME_LINK_INVALID_BODY",400);
 const code=String(parsed.payload?.code||"").trim().toUpperCase();
 if(!codePattern.test(code))return err("GAME_LINK_INVALID_CODE",400);
 const key=await codeHash(env,code),now=stamp();
 const row=await env.DB.prepare("SELECT subject_id FROM account_game_link_codes WHERE code_hash=? AND consumed_at IS NULL AND expires_at>?").bind(key,now).first();
 if(!row||!await accountAllowed(env,String(row.subject_id)))return err("GAME_LINK_CODE_INVALID_OR_EXPIRED",401);
 const ticket=await signTicket(env,String(row.subject_id));
 const cas=await env.DB.prepare("UPDATE account_game_link_codes SET consumed_at=? WHERE code_hash=? AND subject_id=? AND consumed_at IS NULL AND expires_at>?")
   .bind(now,key,row.subject_id,now).run();
 if(Number(cas.meta?.changes||0)!==1)return err("GAME_LINK_CODE_ALREADY_USED",409);
 return json({ok:true,ticket,token_type:"EdDSA",expires_in:90});
}
export async function handleGameLinkRequest(request,env,dependencies){
 const path=new URL(request.url).pathname;
 if(!["/api/account/game-link/code","/api/account/game-link/redeem"].includes(path))return null;
 if(request.method!=="POST")return err("METHOD_NOT_ALLOWED",405);
 if(path.endsWith("/code"))return issue(request,env,dependencies);
 return redeem(request,env);
}
// GDPR-style account closure is asynchronous and retried. No game database is exposed to the mail Worker.
export async function retryGameAccountDeprovision(env){
 if(!issuerReady(env))return {enabled:false};
 const url=String(env.GAME_LINK_DEPROVISION_ENDPOINT||"");
 let safe=false;try{const parsed=new URL(url);safe=parsed.protocol==="https:"&&parsed.pathname==="/api/account/deprovision"&&!parsed.username&&!parsed.password&&!parsed.hash;}catch{}
 if(!safe)return {enabled:false};
 const rows=await env.DB.prepare("SELECT c.account_id FROM account_closures c LEFT JOIN account_game_deprovision_delivery d ON d.account_id=c.account_id WHERE d.account_id IS NULL OR (d.delivered_at IS NULL AND d.retry_after<=?) ORDER BY c.closed_at ASC LIMIT 5").bind(stamp()).all();
 let delivered=0;
 for(const row of rows.results||[]){
  const sub=String(row.account_id||"");if(!subjectPattern.test(sub)||sub.startsWith("admin:"))continue;
  const now=stamp();
  await env.DB.prepare("INSERT OR IGNORE INTO account_game_deprovision_delivery(account_id,attempts,retry_after,delivered_at,updated_at) VALUES(?,0,0,NULL,?)").bind(sub,now).run();
  const ticket=await signTicket(env,sub,"account_deprovision");
  let ok=false;
  try{
   const result=await fetch(url,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({ticket}),redirect:"error",signal:AbortSignal.timeout(8000)});
   ok=result.status===200&&(await result.json())?.ok===true;
  }catch{}
  const prev=await env.DB.prepare("SELECT attempts FROM account_game_deprovision_delivery WHERE account_id=?").bind(sub).first();
  const delay=Math.min(6*3600000,5*60000*Math.pow(2,Math.min(6,Number(prev?.attempts||0))));
  if(ok){await env.DB.prepare("UPDATE account_game_deprovision_delivery SET attempts=attempts+1,delivered_at=?,updated_at=? WHERE account_id=?").bind(now,now,sub).run();delivered++;}
  else await env.DB.prepare("UPDATE account_game_deprovision_delivery SET attempts=attempts+1,retry_after=?,updated_at=? WHERE account_id=?").bind(now+delay,now,sub).run();
 }
 return {enabled:true,attempted:(rows.results||[]).length,delivered};
}
export async function cleanupGameLinkCodes(env,now=stamp()){
 if(!issuerReady(env))return;
 await env.DB.prepare("DELETE FROM account_game_link_codes WHERE expires_at<? OR (consumed_at IS NOT NULL AND consumed_at<?)").bind(now-3600000,now-3600000).run();
}
