// SecureMonitor AI backend. Node 18+, no dependencies.  Run: node server.js  ->  http://localhost:3000
const http=require('http'),fs=require('fs'),c=require('crypto'),path=require('path');
const PORT=process.env.PORT||3000, PROD=process.env.NODE_ENV==='production';
const SECRET=process.env.JWT_SECRET||c.randomBytes(32).toString('hex');   // set JWT_SECRET in production
const ORIGINS=(process.env.ALLOW_ORIGIN||'').split(',').map(x=>x.trim().replace(/\/$/,'')).filter(Boolean); // comma-separated; only if the frontend is hosted on another origin
const N8N=process.env.N8N_RESET_WEBHOOK||'';                              // n8n webhook that emails the reset link
const N8N_ALERT=process.env.N8N_ALERT_WEBHOOK||'', COOL=(+process.env.ALERT_COOLDOWN_MIN||10)*60e3;
const DATA=process.env.DATA_DIR||__dirname; try{fs.mkdirSync(DATA,{recursive:true})}catch{}
const DB=path.join(DATA,'users.json'), COOKIE=PROD?'__Host-refresh_token':'refresh_token';
const SAMESITE=process.env.COOKIE_SAMESITE||'Lax';   // use 'None' (needs HTTPS) only if the frontend is on a different site
if(PROD&&!process.env.JWT_SECRET)console.warn('[WARN] JWT_SECRET is not set: a random secret is used and all users are signed out on every restart.');
let U=[];try{U=JSON.parse(fs.readFileSync(DB))}catch{}
const save=()=>fs.writeFileSync(DB,JSON.stringify(U,null,1));
const devs=new Map(), alertsDb=[], sessions=new Map(), resets=new Map(), tries=new Map();
const sha=s=>c.createHash('sha256').update(s).digest('hex');
const hmac=p=>c.createHmac('sha256',SECRET).update(p).digest('base64url');
const hash=(p,s=c.randomBytes(16).toString('hex'))=>s+':'+c.scryptSync(p,s,32).toString('hex');
const same=(a,b)=>a.length===b.length&&c.timingSafeEqual(Buffer.from(a),Buffer.from(b));
const access=u=>{const p=Buffer.from(JSON.stringify({id:u.id,exp:Date.now()+15*60e3})).toString('base64url');return p+'.'+hmac(p)};
const who=req=>{try{const[p,s]=(req.headers.authorization||'').slice(7).split('.');if(!same(s,hmac(p)))return;const d=JSON.parse(Buffer.from(p,'base64url'));return d.exp>Date.now()&&U.find(u=>u.id===d.id)}catch{}};
const pwOk=p=>typeof p==='string'&&p.length>=8&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/\d/.test(p);
const cookies=req=>Object.fromEntries((req.headers.cookie||'').split(/;\s*/).filter(Boolean).map(x=>x.split(/=(.*)/s).slice(0,2)));
const setRefresh=(res,u)=>{const t=c.randomBytes(32).toString('hex');sessions.set(sha(t),{id:u.id,exp:Date.now()+30*864e5});
  res.setHeader('Set-Cookie',`${COOKIE}=${t}; HttpOnly; SameSite=${SAMESITE}; Path=/; Max-Age=${30*86400}${PROD||SAMESITE==='None'?'; Secure':''}`)};
const clearRefresh=res=>res.setHeader('Set-Cookie',`${COOKIE}=; HttpOnly; SameSite=${SAMESITE}; Path=/; Max-Age=0${PROD||SAMESITE==='None'?'; Secure':''}`);
const send=(res,code,obj)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(obj))};
const pub=u=>({id:u.id,name:u.name,email:u.email});
const REC={cpu:'Review active applications and close unnecessary processes.',ram:'Close unused applications to reduce memory usage.',disk:'Free storage by removing unnecessary files or unused applications.',net:'Review active applications and network connections.',temp:'Stop heavy applications and allow the device to cool.',batt:'Connect the device to a charger.',itemp:'Check the hardware environment and allow the device to cool.',volt:'Check the power supply and sensor wiring.',cur:'Check connected electrical loads and wiring.'};
const RULES={laptop:[['cpu','>',85,2,'High CPU usage','cpu'],['cpu','>',95,1,'Very high CPU usage','cpu'],['ram','>',85,2,'High RAM usage','ram'],['ram','>',95,1,'Very high RAM usage','ram'],['disk','>',90,2,'Storage almost full','disk'],['download_mb','>',500,1,'Unusual network download','net'],['upload_mb','>',200,1,'Unusual network upload','net']],
 mobile:[['batteryPercent','<',20,2,'Low battery','batt'],['batteryPercent','<',10,1,'Critically low battery','batt'],['temperature','>',42,2,'High device temperature','temp'],['storagePercent','>',90,2,'Storage almost full','disk']],
 iot:[['temperature','>',50,2,'High temperature','itemp'],['temperature','>',70,1,'Very high temperature','itemp'],['voltage','<',3,2,'Abnormal voltage','volt'],['voltage','>',5.5,2,'Abnormal voltage','volt'],['current','>',2,2,'Abnormal current','cur']]};
function assess(type,t){let sc=0,why=[],rec=[];
 for(const[f,op,th,pt,lb,rk]of RULES[type]){const v=t[f];if(typeof v!=='number')continue;if(op==='>'?v>th:v<th){sc+=pt;if(!why.includes(lb))why.push(lb);if(!rec.includes(REC[rk]))rec.push(REC[rk])}}
 const risk=sc>=3?'HIGH':sc>=1?'MEDIUM':'NORMAL';if(risk!=='NORMAL')rec.push('Monitor the device for repeated abnormal behaviour.');
 return{risk,score:sc,why,reason:risk==='NORMAL'?'No unusual behaviour detected.':(risk==='HIGH'?'Multiple abnormal behaviour indicators detected: ':'One or more unusual behaviour indicators detected: ')+why.join(', ')+'.',recommendations:rec}}
function ingest(o,type,t){
 const a=assess(type,t),dm=devs.get(o.id)||new Map();devs.set(o.id,dm);
 const rec={id:t.deviceId,name:t.deviceId,type,metrics:Object.fromEntries(Object.entries(t).filter(([k])=>k!=='deviceId'&&k!=='timestamp')),...a,updatedAt:new Date().toISOString()};
 dm.set(t.deviceId,rec);
 if(a.risk==='NORMAL')return;
 const key=t.deviceId+a.risk+a.reason;
 if(alertsDb.find(x=>x.userId===o.id&&x.key===key&&Date.now()-Date.parse(x.time)<COOL))return; // cooldown / dedupe
 const al={id:c.randomUUID(),key,userId:o.id,deviceId:t.deviceId,device:type[0].toUpperCase()+type.slice(1),alertType:a.why[0],risk:a.risk,anomalyScore:a.score,reason:a.reason,recommendations:a.recommendations,status:'OPEN',time:rec.updatedAt,metrics:rec.metrics};
 alertsDb.unshift(al);if(alertsDb.length>2000)alertsDb.pop();
 if(N8N_ALERT)fetch(N8N_ALERT,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:'SecureMonitor AI Alert',email:o.email,deviceId:t.deviceId,deviceType:type,riskLevel:a.risk,anomalyScore:a.score,timestamp:rec.updatedAt,reason:a.reason,currentMetrics:rec.metrics,recommendedActions:a.recommendations,disclaimer:'This alert does not by itself confirm hacking or compromise.'})}).catch(()=>{})}
const shape=d=>({...d,connected:Date.now()-Date.parse(d.updatedAt)<120e3,anomalyScore:d.score});
const body=req=>new Promise(r=>{let d='';req.on('data',x=>{d+=x;if(d.length>1e5)req.destroy()});req.on('end',()=>{try{r(JSON.parse(d||'{}'))}catch{r({})}})});

http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://x'),p=url.pathname,m=req.method;let mm;
 res.setHeader('X-Content-Type-Options','nosniff');
 const org=req.headers.origin;
 if(org&&ORIGINS.includes(org)){res.setHeader('Access-Control-Allow-Origin',org);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Credentials','true');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Device-Key');res.setHeader('Access-Control-Allow-Methods','GET,POST,PATCH,PUT,OPTIONS');res.setHeader('Access-Control-Max-Age','600')}
 if(m==='OPTIONS'){res.writeHead(204);return res.end()}   // preflight never reaches auth
 if(!p.startsWith('/api/')){ // serve the frontend
  return fs.readFile(path.join(__dirname,'securemonitor.html'),(e,d)=>{if(e){res.writeHead(404);return res.end('securemonitor.html not found')}res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});res.end(d)})}
 if(p==='/api/health')return send(res,200,{ok:true,status:'ok',app:'securemonitor',version:'1.0.0',timestamp:new Date().toISOString(),geminiConfigured:!!process.env.GEMINI_API_KEY,n8nConfigured:!!(N8N||N8N_ALERT)});
 const b=m==='POST'||m==='PATCH'||m==='PUT'?await body(req):{};
 if((mm=p.match(/^\/api\/telemetry\/(laptop|mobile|iot)$/))&&m==='POST'){ // agents authenticate with a per-user device key, never a client-supplied user id
  const k=req.headers['x-device-key'],o=k&&U.find(x=>x.keyHash&&x.keyHash===sha(String(k)));
  if(!o)return send(res,401,{error:'invalid device key'});
  if(!/^[\w-]{1,64}$/.test(String(b.deviceId||'')))return send(res,400,{error:'invalid'});
  for(const[f,v]of Object.entries(b))if(v!==null&&!['number','boolean','string'].includes(typeof v))return send(res,400,{error:'invalid'});
  ingest(o,mm[1],b);return send(res,202,{ok:true})}
 const em=String(b.email||'').trim().toLowerCase();
 if(p==='/api/auth/register'&&m==='POST'){
  const name=String(b.name||'').trim();
  if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)||!pwOk(b.password))return send(res,400,{error:'invalid'});
  if(U.find(u=>u.email===em))return send(res,409,{error:'exists'});
  const u={id:c.randomUUID(),name,email:em,pw:hash(b.password)};U.push(u);save();setRefresh(res,u);return send(res,201,{accessToken:access(u),user:pub(u)})}
 if(p==='/api/auth/login'&&m==='POST'){
  const k=String(req.headers['x-forwarded-for']||req.socket.remoteAddress).split(',')[0].trim()+em,t=(tries.get(k)||[]).filter(x=>Date.now()-x<60e3);
  if(t.length>=8)return send(res,429,{error:'rate'});
  const u=U.find(x=>x.email===em);
  const ok=u&&u.pw&&same(hash(String(b.password||''),u.pw.split(':')[0]),u.pw);
  if(!ok){t.push(Date.now());tries.set(k,t);return send(res,401,{error:'invalid'})}
  setRefresh(res,u);return send(res,200,{accessToken:access(u),user:pub(u)})}
 if(p==='/api/auth/refresh'&&m==='POST'){
  const t=cookies(req)[COOKIE],s=t&&sessions.get(sha(t));
  if(!s||s.exp<Date.now())return send(res,401,{error:'expired'});
  sessions.delete(sha(t));const u=U.find(x=>x.id===s.id);if(!u)return send(res,401,{});setRefresh(res,u);return send(res,200,{accessToken:access(u)})}
 if(p==='/api/auth/logout'&&m==='POST'){const t=cookies(req)[COOKIE];if(t)sessions.delete(sha(t));clearRefresh(res);return send(res,200,{ok:true})}
 if(p==='/api/auth/forgot-password'&&m==='POST'){
  const u=U.find(x=>x.email===em);
  if(u){const t=c.randomBytes(32).toString('hex');resets.set(sha(t),{id:u.id,exp:Date.now()+30*60e3});
   const publicUrl=process.env.PUBLIC_URL||process.env.RENDER_EXTERNAL_URL||'http://localhost:'+PORT;
   const link=`${publicUrl.replace(/\/$/,'')}/#/reset-password?token=${t}`;
   if(N8N)fetch(N8N,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'password-reset',email:u.email,link})}).catch(()=>{});
   else console.log('[DEV] Password reset link for',u.email,'->',link)}
  return send(res,200,{ok:true})} // identical response whether or not the account exists
 if(p==='/api/auth/reset-password'&&m==='POST'){
  const k=sha(String(b.token||'')),r=resets.get(k);
  if(!r||r.exp<Date.now()||!pwOk(b.password))return send(res,400,{error:'invalid'});
  resets.delete(k);const u=U.find(x=>x.id===r.id);u.pw=hash(b.password);save();
  for(const[h,s]of sessions)if(s.id===u.id)sessions.delete(h);return send(res,200,{ok:true})}
 const u=who(req);
 if(!u)return send(res,401,{error:'unauthorized'});
 if(p==='/api/auth/me')return send(res,200,pub(u));
 const mine=()=>[...(devs.get(u.id)||new Map()).values()];
 if(p==='/api/devices'&&m==='GET')return send(res,200,mine().map(shape));
 if(p==='/api/devices/agent-key'&&m==='POST'){const k='smk_'+c.randomBytes(24).toString('hex');u.keyHash=sha(k);save();return send(res,200,{key:k})}
 if((mm=p.match(/^\/api\/devices\/([\w-]+)\/(laptop|mobile|iot|assessment|recommendations)$/))&&m==='GET'){
  const d=(devs.get(u.id)||new Map()).get(mm[1]);if(!d)return send(res,404,{error:'not found'});const sh=shape(d);
  return send(res,200,mm[2]==='assessment'?{assessment:sh.reason,note:'Rule-based anomaly detection determines the primary risk classification. AI assessment is an additional layer.',generatedAt:d.updatedAt}:mm[2]==='recommendations'?{recommendations:sh.recommendations}:sh)}
 if(p==='/api/alerts'&&m==='GET')return send(res,200,alertsDb.filter(a=>a.userId===u.id).slice(0,100).map(({userId,key,...r})=>r));
 if((mm=p.match(/^\/api\/alerts\/([\w-]+)$/))&&m==='PATCH'){const a=alertsDb.find(x=>x.id===mm[1]&&x.userId===u.id);if(!a)return send(res,404,{error:'not found'});if(b.status==='RESOLVED'||b.status==='OPEN')a.status=b.status;return send(res,200,{ok:true})}
 if(p==='/api/settings/notifications'){
  if(m==='PUT'){u.settings={email:!!b.email,push:!!b.push,cats:Object.fromEntries(['temp','batt','stor','net','iot'].map(k=>[k,!!(b.cats&&b.cats[k])]))};save();return send(res,200,{ok:true})}
  if(m==='GET')return send(res,200,u.settings||{email:true,push:false,cats:{temp:true,batt:true,stor:true,net:true,iot:true}})}
 send(res,404,{error:'not found'});
}).listen(PORT,'0.0.0.0',()=>console.log('SecureMonitor AI running on http://localhost:'+PORT));
