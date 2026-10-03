"""SentinelLog showcase. Runs the real `sentinellog` CLI behind a step-by-step walkthrough. Synthetic logs only."""
import json
import os
import shutil
import subprocess
import sys
from typing import Literal, Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

app = FastAPI(title="SentinelLog", docs_url=None, redoc_url=None)
MAX_CHARS, MAX_LINES = 100_000, 2_000


def _exe() -> str:
    return shutil.which("sentinellog") or os.path.join(os.path.dirname(sys.executable), "sentinellog")


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
        p = subprocess.run(cmd, input=req.log, capture_output=True, text=True, timeout=10, shell=False)
    except subprocess.TimeoutExpired:
        return JSONResponse({"error": "Analysis timed out."}, status_code=504)
    except FileNotFoundError:
        return JSONResponse({"error": "sentinellog is not installed on the server."}, status_code=500)
    out = p.stdout.strip()
    try:
        data = json.loads(out) if out else []
    except json.JSONDecodeError:
        data = {"raw_output": out}
    return {"result": data, "stderr": p.stderr.strip()[:500], "exit_code": p.returncode}


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SentinelLog: from raw login logs to security alerts</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,600&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--ink:#0d1b2a;--panel:#13263b;--deep:#0a1623;--line:#254463;--text:#e8eef5;--muted:#93a9bf;--amber:#f2b134;--coral:#ff6b57;--ice:#7fd1e8;
--serif:'Fraunces',Georgia,serif;--sans:'IBM Plex Sans',system-ui,sans-serif;--mono:'IBM Plex Mono',ui-monospace,monospace}
*{box-sizing:border-box}html{color-scheme:dark}
body{margin:0;background:var(--ink);color:var(--text);font:16px/1.55 var(--sans);padding:env(safe-area-inset-top) 0 env(safe-area-inset-bottom)}
main{max-width:920px;margin:0 auto;padding:30px 18px 70px}
h1{font:600 clamp(2rem,6.4vw,3.3rem)/1.05 var(--serif);margin:0 0 12px;letter-spacing:-.01em}
.lead{color:var(--muted);max-width:62ch;margin:0 0 30px}
.step{border-left:2px solid var(--line);padding:0 0 26px 18px;margin-left:8px;position:relative}
.step:before{content:attr(data-n);position:absolute;left:-15px;top:0;width:28px;height:28px;border-radius:50%;background:var(--ink);border:2px solid var(--ice);
 color:var(--ice);font:500 13px/24px var(--mono);text-align:center}
h2{font:500 1.1rem/1.3 var(--sans);margin:2px 0 4px}
.why{color:var(--muted);font-size:.92rem;margin:0 0 12px;max-width:68ch}
.box{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;overflow-x:auto}
textarea{width:100%;min-height:210px;background:var(--deep);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:12px;font:13px/1.55 var(--mono);resize:vertical}
:focus-visible{outline:2px solid var(--ice);outline-offset:2px}
.row{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;align-items:end}
button{font:500 14px var(--sans);border-radius:6px;border:1px solid var(--line);padding:9px 13px;cursor:pointer;background:transparent;color:var(--text)}
label{display:flex;flex-direction:column;font-size:.8rem;color:var(--muted);gap:4px}
input{background:var(--deep);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:8px;font:13px var(--mono);width:110px}
table{border-collapse:collapse;width:100%;font:12.5px var(--mono)}
th{color:var(--muted);font-weight:400;text-align:left;padding:4px 10px 6px 0;border-bottom:1px solid var(--line)}
td{padding:4px 10px 4px 0;white-space:nowrap}
.f{color:var(--coral)}.s{color:var(--ice)}
.legend{display:flex;gap:16px;font-size:.8rem;color:var(--muted);margin-top:8px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
.rules{display:grid;gap:8px;margin:0 0 14px;padding:0;list-style:none}
.rules li{background:var(--deep);border:1px solid var(--line);border-radius:8px;padding:9px 12px;font-size:.88rem;color:var(--muted)}
.rules b{font:500 13px var(--mono);color:var(--text);margin-right:8px}
.alert{border-left:4px solid var(--amber);background:var(--deep);border-radius:6px;padding:12px 14px;margin:0 0 10px}
.alert.high{border-left-color:var(--coral)}
.alert header{display:flex;justify-content:space-between;gap:10px;margin-bottom:6px}
.rule{font:500 14px var(--mono)}
.sev{font:500 12px var(--mono);padding:2px 8px;border-radius:99px;background:var(--amber);color:#2a1b00}
.high .sev{background:var(--coral);color:#2b0700}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;font:12.5px var(--mono);color:var(--muted)}
.kv b{color:var(--text);font-weight:400;word-break:break-word}
.muted{color:var(--muted)}.err{color:var(--coral)}
.facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px;margin:0;padding:0;list-style:none;font-size:.9rem}
.facts li{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.facts a,footer a{color:var(--ice)}
footer{color:var(--muted);font-size:.8rem;margin-top:10px}
</style></head>
<body><main>
<h1>Login logs are noisy. SentinelLog finds the attack inside them.</h1>
<p class="lead">Failed logins are easy to miss when you read logs by hand. SentinelLog reads the log, understands each event, connects events that belong together, and raises an alert only when a pattern matches. Scroll through the four steps below and change the log to see it work.</p>

<section class="step" data-n="1">
<h2>Start with a raw log</h2>
<p class="why">This is what a server writes. Two formats work: SentinelLog's own format and standard OpenSSH. The sample contains one brute-force attempt and one password-spraying attempt.</p>
<textarea id="log" spellcheck="false" aria-label="Authentication log"></textarea>
<div class="row"><button id="sA">Attack sample</button><button id="sB">OpenSSH sample</button><button id="sC">Clean log (no attack)</button></div>
</section>

<section class="step" data-n="2">
<h2>The parser turns each line into a structured event</h2>
<p class="why">Whatever the format, every line becomes the same four facts: when, who, from where, and whether it worked. Rules only ever see this clean version. (This table is an illustration of that step.)</p>
<div class="box" id="parsed"></div>
</section>

<section class="step" data-n="3">
<h2>Patterns become visible over time</h2>
<p class="why">Each row is one source IP. Many red dots close together is a brute-force attempt. A blue dot right after red ones means the attacker may have got in.</p>
<div class="box"><div id="tl"></div>
<div class="legend"><span><i class="dot" style="background:var(--coral)"></i>failed login</span><span><i class="dot" style="background:var(--ice)"></i>successful login</span></div></div>
</section>

<section class="step" data-n="4">
<h2>The detection engine raises alerts</h2>
<p class="why">This step runs the real SentinelLog engine on the server. Change the threshold or time window and the alerts update, because the policy is configurable.</p>
<ul class="rules" id="rules"></ul>
<div class="row" style="margin:0 0 12px">
<label>Failures needed<input id="th" type="number" min="1" max="100" placeholder="default"></label>
<label>Time window (sec)<input id="win" type="number" min="1" max="3600" placeholder="default"></label>
<button id="reset">Reset to defaults</button></div>
<div id="alerts" class="muted">Analyzing...</div>
<p class="why" style="margin-top:10px">Alerts are investigation signals, not proof of compromise.</p>
</section>

<section class="step" data-n="5" style="border-left-color:transparent">
<h2>What is under the hood</h2>
<ul class="facts">
<li>Immutable event model and bounded time-window correlation</li>
<li>No runtime dependencies beyond the Python standard library</li>
<li>Unit tests, CI on Python 3.11, 3.12 and 3.13</li>
<li>Defensive by design: <a href="https://github.com/Debrajdutta-Developer/SentinelLog/blob/main/docs/THREAT_MODEL.md">threat model</a> and <a href="https://github.com/Debrajdutta-Developer/SentinelLog/blob/main/SECURITY.md">security policy</a></li>
</ul>
<footer>Logs are processed in memory and never stored. Use synthetic data only. Source: <a href="https://github.com/Debrajdutta-Developer/SentinelLog">github.com/Debrajdutta-Developer/SentinelLog</a></footer>
</section>
</main>
<script>
const $=id=>document.getElementById(id), pad=n=>String(n).padStart(2,'0');
const iso=(b,s)=>{const d=new Date(b.getTime()+s*1000);return d.getUTCFullYear()+'-'+pad(d.getUTCMonth()+1)+'-'+pad(d.getUTCDate())+'T'+pad(d.getUTCHours())+':'+pad(d.getUTCMinutes())+':'+pad(d.getUTCSeconds())+'Z'};
const base=()=>{const b=new Date();b.setUTCSeconds(0,0);return b};
function attack(){const b=base(),L=[];
 for(let i=0;i<5;i++)L.push(`${iso(b,i*10)} user=alice ip=192.0.2.10 result=failed`);
 L.push(`${iso(b,60)} user=alice ip=192.0.2.10 result=success`);
 ['bob','carol','dave','erin','frank'].forEach((u,i)=>L.push(`${iso(b,70+i*8)} user=${u} ip=198.51.100.7 result=failed`));
 L.push(`${iso(b,130)} user=grace ip=203.0.113.5 result=success`);return L.join('\n')}
function clean(){const b=base();return [`${iso(b,0)} user=alice ip=192.0.2.10 result=success`,`${iso(b,40)} user=bob ip=192.0.2.11 result=failed`,`${iso(b,90)} user=bob ip=192.0.2.11 result=success`,`${iso(b,200)} user=carol ip=192.0.2.12 result=success`].join('\n')}
function ssh(){const L=[];for(let i=0;i<5;i++)L.push(`Oct  3 08:00:0${i} lab sshd[100${i}]: Failed password for alice from 192.0.2.10 port 22 ssh2`);
 L.push('Oct  3 08:00:09 lab sshd[1009]: Accepted password for alice from 192.0.2.10 port 22 ssh2');return L.join('\n')}

function parse(text){const ev=[],y=new Date().getUTCFullYear();
 text.split('\n').forEach(line=>{line=line.trim();if(!line)return;let m;
  if(m=line.match(/^(\S+)\s+user=(\S+)\s+ip=(\S+)\s+result=(\w+)/)){const t=Date.parse(m[1]);if(!isNaN(t))ev.push({raw:m[1],t,user:m[2],ip:m[3],ok:/succ|ok|accept/i.test(m[4])})}
  else if(m=line.match(/^(\w{3})\s+(\d+)\s+([\d:]+)\s+\S+\s+sshd\[\d+\]:\s+(Failed|Accepted)\s+\w+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)/)){
   const t=Date.parse(`${m[1]} ${m[2]} ${y} ${m[3]} UTC`);if(!isNaN(t))ev.push({raw:`${m[1]} ${m[2]} ${m[3]}`,t,user:m[5],ip:m[6],ok:m[4]==='Accepted'})}});
 return ev.sort((a,b)=>a.t-b.t)}

function el(tag,cls,txt){const e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e}

function drawParsed(ev){const box=$('parsed');box.replaceChildren();
 if(!ev.length){box.appendChild(el('span','muted','No recognizable lines yet.'));return}
 const t=el('table');const h=el('tr');['time','user','source ip','result'].forEach(x=>h.appendChild(el('th',0,x)));t.appendChild(h);
 ev.slice(0,40).forEach(e=>{const r=el('tr');r.append(el('td',0,e.raw),el('td',0,e.user),el('td',0,e.ip),el('td',e.ok?'s':'f',e.ok?'success':'failed'));t.appendChild(r)});
 box.appendChild(t);if(ev.length>40)box.appendChild(el('p','muted','Showing first 40 of '+ev.length+' events.'))}

function drawTimeline(ev){const box=$('tl');box.replaceChildren();if(!ev.length)return;
 const ips=[...new Set(ev.map(e=>e.ip))],t0=ev[0].t,t1=ev[ev.length-1].t,span=Math.max(t1-t0,1),W=620,L=110,R=16,rowH=30,H=ips.length*rowH+24;
 const NS='http://www.w3.org/2000/svg',svg=document.createElementNS(NS,'svg');svg.setAttribute('viewBox',`0 0 ${W} ${H}`);svg.setAttribute('width','100%');svg.setAttribute('role','img');svg.setAttribute('aria-label','Login events over time by source IP');
 const mk=(n,a)=>{const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);return e};
 ips.forEach((ip,i)=>{const y=i*rowH+16;svg.appendChild(mk('line',{x1:L,x2:W-R,y1:y,y2:y,stroke:'#254463','stroke-width':1}));
  const lb=mk('text',{x:0,y:y+4,fill:'#93a9bf','font-size':12,'font-family':'IBM Plex Mono, monospace'});lb.textContent=ip;svg.appendChild(lb)});
 ev.forEach(e=>{const x=L+((e.t-t0)/span)*(W-L-R-8)+4,y=ips.indexOf(e.ip)*rowH+16;
  svg.appendChild(mk('circle',{cx:x,cy:y,r:6,fill:e.ok?'#7fd1e8':'#ff6b57',opacity:.92}))});
 const ax=mk('text',{x:L,y:H-4,fill:'#93a9bf','font-size':11,'font-family':'IBM Plex Mono, monospace'});ax.textContent='time \u2192  ('+Math.round(span/1000)+'s span)';svg.appendChild(ax);
 box.appendChild(svg)}

function drawRules(){const th=parseInt($('th').value)||null,w=parseInt($('win').value)||300,u=$('rules');u.replaceChildren();
 [['AUTH-001',`${th||5} failed logins for the same user from the same IP within ${w}s.`],
  ['AUTH-002',`${th||5} failed logins from one IP across 2+ different users within ${w}s (password spraying).`],
  ['AUTH-003',`A successful login after ${th||3} failures within ${w}s (possible account takeover).`]].forEach(([id,txt])=>{
  const li=el('li');li.append(el('b',0,id),document.createTextNode(txt));u.appendChild(li)})}

function card(a){const sev=String(a.severity??a.level??'');const c=el('article','alert'+(/high|critical/i.test(sev)?' high':''));
 const h=el('header');h.appendChild(el('span','rule',a.rule_id??a.rule??a.id??a.name??'Alert'));if(sev)h.appendChild(el('span','sev',sev));c.appendChild(h);
 const kv=el('div','kv');Object.entries(a).forEach(([k,v])=>{if(['rule_id','rule','id','name','severity','level'].includes(k))return;kv.append(el('span',0,k),el('b',0,typeof v==='object'?JSON.stringify(v):String(v)))});
 c.appendChild(kv);return c}

function drawAlerts(r){const box=$('alerts');box.className='';box.replaceChildren();
 const list=Array.isArray(r)?r:(r&&Array.isArray(r.alerts)?r.alerts:null);
 if(list===null){const p=el('pre','muted',JSON.stringify(r,null,2));p.style.whiteSpace='pre-wrap';box.appendChild(p);return}
 if(!list.length){box.className='muted';box.textContent='No alerts. No rule crossed its threshold in this log.';return}
 box.appendChild(el('p','muted',list.length+(list.length===1?' alert':' alerts')+' raised by the engine'));list.forEach(a=>box.appendChild(card(a)))}

let timer,seq=0;
async function analyze(){const text=$('log').value,ev=parse(text);drawParsed(ev);drawTimeline(ev);drawRules();
 const box=$('alerts');if(!text.trim()){box.className='muted';box.textContent='Add a log in step 1.';return}
 const body={log:text},th=parseInt($('th').value),w=parseInt($('win').value);if(th)body.threshold=th;if(w)body.window=w;
 const my=++seq;box.className='muted';box.textContent='Analyzing...';
 try{const res=await fetch('/api/analyze',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const d=await res.json();
  if(my!==seq)return;if(!res.ok){box.className='err';box.textContent=d.error||'Request failed. Check the values and try again.'}else drawAlerts(d.result)}
 catch(e){if(my===seq){box.className='err';box.textContent='Could not reach the server. It may be waking up; try again in 30 seconds.'}}}
const later=()=>{clearTimeout(timer);timer=setTimeout(analyze,450)};
['log','th','win'].forEach(i=>$(i).addEventListener('input',later));
$('sA').onclick=()=>{$('log').value=attack();analyze()};$('sB').onclick=()=>{$('log').value=ssh();analyze()};$('sC').onclick=()=>{$('log').value=clean();analyze()};
$('reset').onclick=()=>{$('th').value='';$('win').value='';analyze()};
$('log').value=attack();analyze();
</script></body></html>
"""
