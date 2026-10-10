// TEST-ONLY SECURITY ADAPTER.
// The production security-guard.js (trusted CF IP + encrypted rate-limit fingerprints)
// remains PRIVATE and is intentionally NOT mirrored here.
export async function claimRequestRateLimit(env,request,scope,limit,{windowMs=60000}={}){
 if(env.__testRateDbDown)throw Error("SIMULATED_RATE_LIMIT_UNAVAILABLE");
 const store=env.__testRateLimits||(env.__testRateLimits=new Map());
 const marker=String(request.headers.get("x-test-client")||"synthetic-user").slice(0,80);
 const key=scope+":"+marker+":"+Math.floor(Date.now()/windowMs);
 const next=(store.get(key)||0)+1;
 store.set(key,next);
 return {allowed:next<=limit,retry_after_ms:windowMs,count:next};
}
export async function readJsonBodyLimited(request,maximum=1024){
 try{
  const raw=await request.text();
  if(new TextEncoder().encode(raw).byteLength>maximum)return{ok:false,status:413,error:"BODY_TOO_LARGE"};
  const payload=JSON.parse(raw);
  if(!payload||typeof payload!=="object"||Array.isArray(payload))return{ok:false,status:400,error:"BAD_BODY"};
  return{ok:true,payload};
 }catch{return{ok:false,status:400,error:"BAD_JSON"}}
}
