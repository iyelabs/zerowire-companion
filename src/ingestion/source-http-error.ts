/** Only bounded GitHub rate-limit metadata; never arbitrary source body or credentials. */
export type GhsaFailure = { reason: 'primary_rate_limit' | 'secondary_rate_limit' | 'rate_limited' | 'forbidden'; remaining:number|null; resetAt:string|null; retryAfterSeconds:number|null; invalidRetryAfter:boolean };
export class SourceHttpError extends Error {
 readonly status: number;
 readonly ghsa: GhsaFailure|null;
 constructor(status: number, ghsa:GhsaFailure|null=null) { super('source_http_error'); this.status = status; this.ghsa=ghsa; }
}
export async function githubFailure(response:Response, now=Date.now()):Promise<GhsaFailure> {
 const number=(value:string|null):number|null=>value!==null&&/^\d{1,10}$/.test(value)?Number(value):null;
 const remaining=number(response.headers.get('x-ratelimit-remaining'));
 const reset=number(response.headers.get('x-ratelimit-reset'));
 const resetMs=reset!==null?reset*1000:NaN;
 const resetAt=Number.isFinite(resetMs)&&resetMs>now&&resetMs<=now+7*86400000?new Date(resetMs).toISOString():null;
 const raw=response.headers.get('retry-after');let retryAfterSeconds=number(raw);
 if(raw && retryAfterSeconds===null){const t=Date.parse(raw);if(Number.isFinite(t)&&t>now)retryAfterSeconds=Math.ceil((t-now)/1000);}
 // An unreasonably long Retry-After cannot be safely capped to an earlier retry.
 const invalidRetryAfter=!!raw&&(retryAfterSeconds===null||retryAfterSeconds>7*86400);
 if(invalidRetryAfter)retryAfterSeconds=null;
 let message='';const reader=response.body?.getReader();
 if(reader){try{const part=await reader.read();message=new TextDecoder().decode(part.value?.subarray(0,4096));}catch{/* Header-based limits remain authoritative when the body fails. */}finally{await reader.cancel().catch(()=>undefined);reader.releaseLock();}}
 const secondary=/secondary rate limit/i.test(message);
 const reason=remaining===0?'primary_rate_limit':secondary?'secondary_rate_limit':response.status===429?'rate_limited':'forbidden';
 return {reason,remaining,resetAt,retryAfterSeconds,invalidRetryAfter};
}
