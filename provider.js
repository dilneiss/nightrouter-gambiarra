const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const {spawn} = require('node:child_process');
const crypto = require('node:crypto');
const ROOT = __dirname, ENV = path.join(ROOT, '.env');
const STATE = path.join(ROOT, '.provider-rate.json');
const PORT = Number(process.env.NIGHTROUTER_PROXY_PORT || 18765);
const UPSTREAM = 'https://api.nightrouter.ai';
let state = {};
try { state = JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
function keys() {
  const text = fs.readFileSync(ENV, 'utf8');
  return [...new Set([...text.matchAll(/^NIGHTROUTER_(?:ACCOUNT_\d+_KEY|KEY_[A-Za-z0-9_]+)\s*=\s*"?([^"\r\n\s]+)"?\s*$/gm)].map(m => m[1]))];
}
function reserve() {
  const now = Date.now(); let best = null, earliest = Infinity;
  for (const key of keys()) {
    const id = crypto.createHash('sha256').update(key).digest('hex');
    const times = (state[id] || []).filter(t => Number.isFinite(t) && t > now - 61000 && t <= now + 61000);
    state[id] = times;
    if (times.length < 3 && !best) best = {key, id};
    if (times.length >= 3) earliest = Math.min(earliest, times[0] + 61000);
  }
  if (!best) return {wait: Number.isFinite(earliest) ? Math.max(1, Math.ceil((earliest-now)/1000)) : 0};
  state[best.id].push(now);
  const tmp = STATE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(state), {mode:0o600}); fs.renameSync(tmp, STATE);
  return best;
}
const server = http.createServer((req, res) => {
  if (!['GET','POST'].includes(req.method) || !/^\/v1\/(models(?:\/[^/?]+)?|chat\/completions|responses)(?:\?.*)?$/.test(req.url)) {res.writeHead(404).end(); return;}
  let body = [], size = 0;
  req.on('data', chunk => {size += chunk.length; if(size > 20*1024*1024) req.destroy(); else body.push(chunk);});
  req.on('end', () => {
    let choice; try {choice = reserve();} catch(e) {res.writeHead(500, {'Content-Type':'application/json'}).end(JSON.stringify({error:{message:e.message}}));return;}
    if (!choice.key) {res.writeHead(choice.wait ? 429 : 503, {'Content-Type':'application/json', ...(choice.wait ? {'Retry-After':String(choice.wait)} : {})}).end(JSON.stringify({error:{message:choice.wait ? 'Todas as contas estão no limite local.' : 'Nenhuma chave encontrada no .env.'}}));return;}
    const args = ['--silent','--show-error','--no-buffer','--max-time','600','--include','--request',req.method,'--header','Content-Type: application/json','--header','Accept: '+(req.headers.accept || 'application/json'),'--header','Authorization: Bearer '+choice.key];
    if (req.method === 'POST') args.push('--data-binary','@-');
    args.push(UPSTREAM + req.url);
    const child = spawn('curl.exe',args,{stdio:['pipe','pipe','pipe'],windowsHide:true});
    let pending=Buffer.alloc(0), started=false;
    child.stdin.on('error',()=>{}); child.stdin.end(Buffer.concat(body));
    child.stdout.on('data',chunk=>{
      if(started) {if(!res.write(chunk)) child.stdout.pause(); return;}
      pending=Buffer.concat([pending,chunk]); let pos=pending.indexOf('\r\n\r\n'); if(pos<0) {if(pending.length>65536) child.kill(); return;}
      const header=pending.subarray(0,pos).toString('latin1'); const lines=header.split('\r\n'); const match=lines.shift().match(/^HTTP\/\S+\s+(\d+)/);
      if(!match){child.kill();return;} const status=Number(match[1]);
      if(status===100 || (status===200 && /connection established/i.test(header))) {pending=pending.subarray(pos+4); return;}
      const headers={}; for(const line of lines){const i=line.indexOf(':'); if(i>0){const name=line.slice(0,i).trim().toLowerCase(); if(['content-type','retry-after','cache-control'].includes(name)) headers[name]=line.slice(i+1).trim();}}
      res.writeHead(status,headers); started=true; const rest=pending.subarray(pos+4); if(rest.length) res.write(rest); pending=null;
    });
    res.on('drain',()=>child.stdout.resume());
    child.on('error',()=>{if(!res.headersSent) res.writeHead(502); res.end();});
    child.on('close',code=>{if(!res.headersSent) res.writeHead(502,{'Content-Type':'application/json'}); if(!res.writableEnded) res.end(code && !started ? JSON.stringify({error:{message:'Falha na conexão com NightRouter'}}) : undefined);});
    res.on('close',()=>{if(!res.writableFinished) child.kill();});
  });
});
server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`A porta ${PORT} já está em uso. O provider pode já estar em execução; confira antes de iniciar outra instância.`);
  else console.error(`Não foi possível iniciar o provider: ${err.message}`);
  process.exitCode = 1;
});
server.listen(PORT,'127.0.0.1',()=>console.log(`NightRouter proxy: http://127.0.0.1:${PORT}/v1`));
