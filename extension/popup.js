const $=s=>document.querySelector(s);
let tabId=null,paused=false;
function bg(msg){return new Promise(resolve=>chrome.runtime.sendMessage(msg,res=>resolve(res||{ok:false,message:chrome.runtime.lastError?.message||'No response'})));}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function addMsg(text,who='bot'){const d=document.createElement('div');d.className=who;d.textContent=text;$('#messages').appendChild(d);$('#messages').scrollTop=$('#messages').scrollHeight;}
function updateKill(){$('#kill').classList.toggle('continue',paused);$('#kill span').textContent=paused?'▶':'⏸';$('#kill b').textContent=paused?'Continue':'Kill switch';$('#kill small').textContent=paused?'RESUME AI ACTION':'STOP AI ACTION';}
async function refresh(){const s=await bg({type:'GET_STATE'});paused=!!s.paused;updateKill();$('#backendStatus').textContent=s.backendOnline?'BACKEND • ONLINE':'BACKEND • OFFLINE';$('#backendStatus').className=s.backendOnline?'online':'offline';renderPII(s.pii||[]);renderLogs(s.logs||[]);}
function renderPII(items){$('#piiCount').textContent=`${items.length} ITEMS`;$('#piiList').innerHTML=items.length?items.map(x=>`<div class="pii"><div><b>${esc(x.type)}</b><small>${esc(x.field||'Page text')}${x.maskedValue?' · '+esc(x.maskedValue):''}</small></div><strong class="${x.hidden?'ok':'no'}">${x.hidden?'✓':'✕'}</strong></div>`).join(''):'<div class="empty">No sensitive data detected yet.</div>';}
function renderLogs(items){$('#logs').innerHTML=items.length?items.slice(0,20).map(x=>`<div class="log"><b>${esc(x.action)}</b><small>${new Date(x.time).toLocaleTimeString()} · ${esc(x.detail||'')}</small></div>`).join(''):'<div class="empty">No actions yet.</div>';}
async function scan(){
  const r=await bg({type:'SCAN_ALL',tabId});
  if(!r.ok){addMsg(`Scan failed: ${r.message||'No page frame responded.'}`);return;}
  const all=(r.results||[]).flatMap(x=>x.data||[]);
  await chrome.storage.local.set({pii:all}); renderPII(all);
  const snapshots=(r.results||[]).map(x=>x.snapshot).filter(Boolean);
  const payload={text:snapshots.map(x=>x.text||'').join('\n'),fields:snapshots.flatMap(x=>x.fields||[])};
  const br=await bg({type:'BACKEND_SCAN',payload});
  await bg({type:'LOG',entry:{action:'BACKEND_SCAN',detail:br.ok?`Backend detected ${br.count||0} PII item(s) in memory; plaintext not stored`:'Backend unavailable; client scan used'}});
  addMsg(`Scan complete — ${all.length} sensitive item(s) detected. Backend: ${br.ok?'connected':'offline'}.`);
  await refresh();
}
async function redact(){const r=await bg({type:'REDACT_ALL',tabId});if(!r.ok){addMsg(`Redact failed: ${r.message||'Page unavailable'}`);return;}const all=(r.results||[]).flatMap(x=>x.data||[]);await chrome.storage.local.set({pii:all});renderPII(all);addMsg(`Capture + Redact complete — ${all.filter(x=>x.hidden).length} item(s) hidden locally.`);await refresh();}
async function runCommand(command){if(paused){addMsg('AI action is stopped. Tap Continue to resume.');return;}if(!command.trim())return;addMsg(command,'user');$('#command').value='';const r=await bg({type:'COMMAND_ALL',tabId,command});addMsg(r.message||'Command completed.');if(r.data?.length){await chrome.storage.local.set({pii:r.data});renderPII(r.data);}await refresh();}
$('#kill').onclick=async()=>{paused=!paused;await bg({type:'SET_PAUSED',value:paused});await bg({type:'LOG',entry:{action:paused?'KILL_SWITCH_ON':'CONTINUE',detail:paused?'AI actions stopped':'AI actions resumed'}});addMsg(paused?'AI actions stopped.':'AI actions resumed.');updateKill();};
$('#run').onclick=()=>runCommand($('#command').value);$('#command').addEventListener('keydown',e=>{if(e.key==='Enter')runCommand($('#command').value);});
document.querySelectorAll('.quick button').forEach(b=>b.onclick=()=>runCommand(b.dataset.cmd));
$('#scan').onclick=scan;$('#redact').onclick=redact;
$('#analyse').onclick=async()=>{const r=await bg({type:'ANALYSE_ALL',tabId});if(!r.ok){addMsg(`Analyze failed: ${r.message||'Page unavailable'}`);return;}const ds=(r.results||[]).map(x=>x.data).filter(Boolean);const n=ds.reduce((sum,x)=>sum+(x.fields?.length||0),0);const payload=ds[0]||{};const br=await bg({type:'BACKEND_ANALYZE',payload});addMsg(`Page analysis: ${n} form field(s) mapped. Backend: ${br.ok?'connected':'offline'}.`);await refresh();};
$('#save').onclick=async()=>{const r=await bg({type:'SAVE_ALL',tabId});if(!r.ok){addMsg(`Save failed: ${r.message||'Page unavailable'}`);return;}const n=(r.results||[]).reduce((sum,x)=>sum+(x.count||0),0);addMsg(`Saved ${n} field(s). Sensitive + non-sensitive values encrypted; backend receives ciphertext only.`);await refresh();};
$('#clearLog').onclick=async()=>{await chrome.storage.local.set({logs:[]});renderLogs([]);};
$('#chatSend').onclick=chat;$('#chatInput').addEventListener('keydown',e=>{if(e.key==='Enter')chat();});
async function chat(){const q=$('#chatInput').value.trim();if(!q)return;$('#chatInput').value='';addMsg(q,'user');const r=await bg({type:'CHAT_CONTEXT_ALL',tabId});const ds=(r.results||[]).map(x=>x.data).filter(Boolean);const d=ds[0]||{};const br=await bg({type:'BACKEND_CHAT',payload:{question:q,title:d.title||'',url:d.url||'',headings:d.headings||[],fields:ds.flatMap(x=>x.fields||[])}});let answer=br.ok?br.answer:null;if(!answer){const low=q.toLowerCase();if(/title|page name/.test(low))answer=`The page title is "${d.title||'unknown'}".`;else if(/url|site|website|domain/.test(low))answer=`This page is ${d.url||'unknown'}.`;else if(/form|field|input/.test(low))answer=`I found ${ds.reduce((n,x)=>n+(x.fields?.length||0),0)} form field(s).`;else if(/heading|section/.test(low))answer=`Visible headings: ${(d.headings||[]).join(', ')||'none detected'}.`;else answer='More than my chat. I do not understand that webpage question yet.';}addMsg(answer);await bg({type:'LOG',entry:{action:'PAGE_CHAT',detail:'Answered webpage question using local page context/backend'}});await refresh();}
(async()=>{const tabs=await chrome.tabs.query({active:true,currentWindow:true});tabId=tabs[0]?.id||null;if(tabs[0]){$('#pageTitle').textContent=tabs[0].title||'Untitled page';$('#pageUrl').textContent=tabs[0].url||'';}await refresh();})();
