"""SentinelLog live demo. Wraps the real `sentinellog` CLI; synthetic logs only."""
import json
import os
import shutil
import subprocess
import sys
from typing import Literal, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="SentinelLog Live Demo", docs_url=None, redoc_url=None)

MAX_CHARS = 100_000
MAX_LINES = 2_000


def _exe() -> str:
    found = shutil.which("sentinellog")
    if found:
        return found
    return os.path.join(os.path.dirname(sys.executable), "sentinellog")


class AnalyzeRequest(BaseModel):
    log: str = Field(..., min_length=1)
    rule: Optional[Literal["AUTH-001", "AUTH-002", "AUTH-003"]] = None
    threshold: Optional[int] = Field(None, ge=1, le=100)
    window: Optional[int] = Field(None, ge=1, le=3600)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    if len(req.log) > MAX_CHARS or req.log.count("\n") > MAX_LINES:
        return JSONResponse({"error": "Log too large. Limit: 2,000 lines / 100 KB."}, status_code=413)

    cmd = [_exe(), "-", "--json"]
    if req.rule:
        cmd += ["--rule", req.rule]
    if req.threshold:
        cmd += ["--threshold", str(req.threshold)]
    if req.window:
        cmd += ["--window", str(req.window)]

    try:
        proc = subprocess.run(cmd, input=req.log, capture_output=True, text=True, timeout=10, shell=False)
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "Analysis timed out."}, status_code=504)
    except FileNotFoundError:
        return JSONResponse({"error": "sentinellog is not installed on the server."}, status_code=500)

    out = proc.stdout.strip()
    try:
        data = json.loads(out) if out else []
    except json.JSONDecodeError:
        data = {"raw_output": out}
    return {"result": data, "stderr": proc.stderr.strip()[:500], "exit_code": proc.returncode}


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SentinelLog: live detection demo</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0d1b2a; --panel:#13263b; --line:#254463; --text:#e8eef5; --muted:#8fa6bd;
  --amber:#f2b134; --coral:#ff6b57; --ice:#7fd1e8;
  --serif:'Fraunces',Georgia,serif; --sans:'IBM Plex Sans',system-ui,sans-serif; --mono:'IBM Plex Mono',ui-monospace,monospace;
}
*{box-sizing:border-box}
html{color-scheme:dark}
body{margin:0;background:var(--ink);color:var(--text);font-family:var(--sans);line-height:1.5;
  padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}
main{max-width:980px;margin:0 auto;padding:28px 18px 60px}
h1{font-family:var(--serif);font-size:clamp(2rem,6vw,3.2rem);line-height:1.05;margin:0 0 10px;letter-spacing:-.01em}
.sub{color:var(--muted);max-width:60ch;margin:0 0 28px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
h2{font-size:1rem;margin:0 0 10px;font-weight:500}
textarea{width:100%;min-height:300px;background:#0a1623;color:var(--text);border:1px solid var(--line);border-radius:6px;
  padding:12px;font:13px/1.55 var(--mono);resize:vertical}
textarea:focus,select:focus,input:focus,button:focus-visible{outline:2px solid var(--ice);outline-offset:2px}
.row{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0 0;align-items:end}
label{display:flex;flex-direction:column;font-size:.8rem;color:var(--muted);gap:4px}
select,input{background:#0a1623;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px;font:13px var(--mono);width:110px}
select{width:140px}
button{font:500 14px var(--sans);border-radius:6px;border:1px solid var(--line);padding:10px 14px;cursor:pointer;background:transparent;color:var(--text)}
button.primary{background:var(--ice);color:#06202b;border-color:var(--ice)}
button:disabled{opacity:.5;cursor:wait}
.alert{border-left:4px solid var(--amber);background:#0a1623;border-radius:6px;padding:12px 14px;margin:0 0 10px}
.alert.high{border-left-color:var(--coral)}
.alert header{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:6px}
.rule{font:500 14px var(--mono)}
.sev{font:500 12px var(--mono);padding:2px 8px;border-radius:99px;background:var(--amber);color:#2a1b00}
.high .sev{background:var(--coral);color:#2b0700}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;font:12.5px var(--mono);color:var(--muted)}
.kv b{color:var(--text);font-weight:400;word-break:break-word}
.empty{color:var(--muted);font-size:.95rem}
.err{color:var(--coral)}
pre{margin:0;white-space:pre-wrap;word-break:break-word;font:12px var(--mono);color:var(--muted)}
footer{margin-top:26px;color:var(--muted);font-size:.8rem;max-width:70ch}
footer a{color:var(--ice)}
</style>
</head>
<body>
<main>
  <h1>Paste a login log. See what SentinelLog flags.</h1>
  <p class="sub">This page runs the real SentinelLog engine on the server. Alerts are investigation signals, not proof of compromise. Use synthetic data only.</p>

  <div class="grid">
    <section class="panel" aria-labelledby="in">
      <h2 id="in">Authentication log</h2>
      <textarea id="log" spellcheck="false" aria-label="Authentication log input"></textarea>
      <div class="row">
        <button type="button" id="sNorm">Load attack sample</button>
        <button type="button" id="sSsh">Load OpenSSH sample</button>
        <button type="button" id="sClear">Clear</button>
      </div>
      <div class="row">
        <label>Rule
          <select id="rule">
            <option value="">All rules</option>
            <option>AUTH-001</option><option>AUTH-002</option><option>AUTH-003</option>
          </select>
        </label>
        <label>Threshold<input id="th" type="number" min="1" max="100" placeholder="default"></label>
        <label>Window (s)<input id="win" type="number" min="1" max="3600" placeholder="default"></label>
        <button type="button" class="primary" id="run">Analyze log</button>
      </div>
    </section>

    <section class="panel" aria-labelledby="out" aria-live="polite">
      <h2 id="out">Alerts</h2>
      <div id="alerts" class="empty">Load a sample and select Analyze log.</div>
    </section>
  </div>

  <footer>
    Detection rules: AUTH-001 repeated failures for one source and user, AUTH-002 repeated failures from one source across users, AUTH-003 success after repeated failures. Logs are processed in memory and not stored. Source code:
    <a href="https://github.com/Debrajdutta-Developer/SentinelLog">github.com/Debrajdutta-Developer/SentinelLog</a>
  </footer>
</main>

<script>
const $ = id => document.getElementById(id);
const pad = n => String(n).padStart(2, '0');
function ts(base, sec){
  const d = new Date(base.getTime() + sec * 1000);
  return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+'T'+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+'Z';
}
function attackSample(){
  const base = new Date(); base.setUTCSeconds(0,0);
  const L = [];
  for(let i=0;i<5;i++) L.push(`${ts(base,i*10)} user=alice ip=192.0.2.10 result=failed`);
  L.push(`${ts(base,60)} user=alice ip=192.0.2.10 result=success`);
  ['bob','carol','dave','erin','frank'].forEach((u,i)=>L.push(`${ts(base,70+i*8)} user=${u} ip=198.51.100.7 result=failed`));
  L.push(`${ts(base,130)} user=grace ip=203.0.113.5 result=success`);
  return L.join('\n');
}
function sshSample(){
  const L = [];
  for(let i=0;i<5;i++) L.push(`Oct  3 08:00:0${i} lab sshd[100${i}]: Failed password for alice from 192.0.2.10 port 22 ssh2`);
  L.push('Oct  3 08:00:09 lab sshd[1009]: Accepted password for alice from 192.0.2.10 port 22 ssh2');
  return L.join('\n');
}
$('sNorm').onclick = () => $('log').value = attackSample();
$('sSsh').onclick  = () => $('log').value = sshSample();
$('sClear').onclick = () => { $('log').value=''; $('alerts').className='empty'; $('alerts').textContent='Load a sample and select Analyze log.'; };

function pick(o, keys){ for(const k of keys) if(o[k]!==undefined && o[k]!==null) return o[k]; return null; }

function card(a){
  const el = document.createElement('article');
  const sev = String(pick(a,['severity','level']) || '');
  el.className = 'alert' + (/high|critical/i.test(sev) ? ' high' : '');
  const head = document.createElement('header');
  const r = document.createElement('span'); r.className='rule'; r.textContent = pick(a,['rule_id','rule','id','name']) || 'Alert';
  head.appendChild(r);
  if(sev){ const s=document.createElement('span'); s.className='sev'; s.textContent=sev; head.appendChild(s); }
  el.appendChild(head);
  const kv = document.createElement('div'); kv.className='kv';
  Object.entries(a).forEach(([k,v])=>{
    if(['rule_id','rule','id','name','severity','level'].includes(k)) return;
    const kk=document.createElement('span'); kk.textContent=k;
    const vv=document.createElement('b'); vv.textContent = (typeof v==='object') ? JSON.stringify(v) : String(v);
    kv.append(kk,vv);
  });
  el.appendChild(kv);
  return el;
}

function render(result){
  const box = $('alerts'); box.className=''; box.replaceChildren();
  let list = Array.isArray(result) ? result : (result && Array.isArray(result.alerts) ? result.alerts : null);
  if(list === null){ const p=document.createElement('pre'); p.textContent=JSON.stringify(result,null,2); box.appendChild(p); return; }
  if(!list.length){ box.className='empty'; box.textContent='No alerts. No rule crossed its threshold in this log.'; return; }
  const n=document.createElement('p'); n.className='empty'; n.textContent = list.length + (list.length===1?' alert':' alerts') + ' found'; box.appendChild(n);
  list.forEach(a => box.appendChild(card(a)));
}

$('run').onclick = async () => {
  const log = $('log').value.trim();
  const box = $('alerts');
  if(!log){ box.className='err'; box.textContent='Add a log first: paste one or load a sample.'; return; }
  const body = { log };
  if($('rule').value) body.rule = $('rule').value;
  if($('th').value) body.threshold = parseInt($('th').value,10);
  if($('win').value) body.window = parseInt($('win').value,10);
  $('run').disabled = true; box.className='empty'; box.textContent='Analyzing...';
  try{
    const res = await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const data = await res.json();
    if(!res.ok){ box.className='err'; box.textContent = data.error || 'Request failed. Check the values and try again.'; }
    else { render(data.result); }
  }catch(e){ box.className='err'; box.textContent='Could not reach the server. It may be waking up; retry in 30 seconds.'; }
  finally{ $('run').disabled = false; }
};
$('log').value = attackSample();
</script>
</body>
</html>
"""
