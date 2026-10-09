// Local smoke test for SecureMonitor AI. Run: node smoke-test.js [base-url]
// Uses a fresh throwaway account. Do not point this at production unless you intend to create a test account.
const base=(process.argv[2]||'http://127.0.0.1:3000').replace(/\/$/,'');
const suffix=Date.now().toString(36);
const user={name:'SecureMonitor Smoke Test',email:`smoke-${suffix}@example.com`,password:'SmokeTest123'};
async function req(path,options={}){
 const r=await fetch(base+path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});
 let body={};try{body=await r.json()}catch{}
 return {status:r.status,body,headers:r.headers};
}
(async()=>{
 const health=await req('/api/health');
 if(health.status!==200||health.body.app!=='securemonitor')throw new Error('Health check failed: '+JSON.stringify(health));
 const reg=await req('/api/auth/register',{method:'POST',body:JSON.stringify(user)});
 if(reg.status!==201||typeof reg.body.accessToken!=='string')throw new Error('Register failed: '+JSON.stringify({status:reg.status,body:reg.body}));
 const login=await req('/api/auth/login',{method:'POST',body:JSON.stringify({email:user.email,password:user.password})});
 if(login.status!==200||typeof login.body.accessToken!=='string')throw new Error('Login failed: '+JSON.stringify({status:login.status,body:login.body}));
 const me=await req('/api/auth/me',{headers:{Authorization:`Bearer ${login.body.accessToken}`}});
 if(me.status!==200||me.body.email!==user.email)throw new Error('Current-user check failed: '+JSON.stringify(me));
 const bad=await req('/api/auth/login',{method:'POST',body:JSON.stringify({email:user.email,password:'WrongPassword123'})});
 if(bad.status!==401)throw new Error('Wrong-password check failed: '+JSON.stringify({status:bad.status,body:bad.body}));
 console.log(JSON.stringify({health:'PASS',register:'PASS',login:'PASS',currentUser:'PASS',wrongPasswordRejected:'PASS',testEmail:user.email},null,2));
})().catch(e=>{console.error(e.message);process.exitCode=1});
