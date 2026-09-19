const BACKEND = 'http://127.0.0.1:8765';
const DEFAULTS = { paused:false, logs:[], pii:[], backendOnline:false, vaultVersion:2 };

chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(Object.keys(DEFAULTS));
  await chrome.storage.local.set({...DEFAULTS, ...current});
});

function log(entry={}) {
  const safe = {
    action: String(entry.action || 'ACTION'),
    detail: String(entry.detail || '').slice(0,500),
    url: String(entry.url || '').slice(0,500),
    title: String(entry.title || '').slice(0,200),
    frame: String(entry.frame || '').slice(0,200),
    time: new Date().toISOString()
  };
  chrome.storage.local.get({logs:[]}).then(({logs}) =>
    chrome.storage.local.set({logs:[safe,...logs].slice(0,250)})
  );
}

async function backend(path, body) {
  try {
    const options = {method: body === undefined ? 'GET' : 'POST'};
    if (body !== undefined) {
      options.headers = {'Content-Type':'application/json'};
      options.body = JSON.stringify(body);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    options.signal = controller.signal;
    const response = await fetch(BACKEND + path, options);
    clearTimeout(timer);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Backend HTTP ${response.status}`);
    return data;
  } catch (error) {
    return {ok:false, error:error?.message || 'Backend unavailable'};
  }
}

async function updateBackendStatus(){
  const result = await backend('/health');
  await chrome.storage.local.set({backendOnline: result.ok === true});
  return result.ok === true;
}

async function getFrameIds(tabId){
  try {
    const frames = await chrome.webNavigation.getAllFrames({tabId});
    return [...new Set((frames || []).map(frame => frame.frameId))].sort((a,b)=>a-b);
  } catch {
    return [0];
  }
}

function sendToFrame(tabId, frameId, message){
  return new Promise(resolve => {
    chrome.tabs.sendMessage(tabId, message, {frameId}, response => {
      if (chrome.runtime.lastError) resolve({ok:false, frameId, message:chrome.runtime.lastError.message});
      else resolve({...response, frameId});
    });
  });
}

async function ensureContentScript(tabId, frameId){
  const ping = await sendToFrame(tabId, frameId, {type:'PING'});
  if (ping.ok) return true;
  try {
    await chrome.scripting.executeScript({target:{tabId,frameIds:[frameId]},files:['content.js']});
    const again = await sendToFrame(tabId, frameId, {type:'PING'});
    return !!again.ok;
  } catch {
    return false;
  }
}

async function allFrames(tabId, type, extra={}){
  const ids = await getFrameIds(tabId);
  const results=[];
  for (const frameId of ids){
    if (!(await ensureContentScript(tabId, frameId))) continue;
    const response = await sendToFrame(tabId, frameId, {type, ...extra});
    if (response?.ok) results.push(response);
  }
  return results;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'LOG') { log(msg.entry); return; }
  if (msg.type === 'SET_PAUSED') { chrome.storage.local.set({paused:!!msg.value}); return; }
  if (msg.type === 'GET_STATE') {
    Promise.all([chrome.storage.local.get(DEFAULTS), updateBackendStatus()]).then(([state]) => sendResponse(state));
    return true;
  }
  if (msg.type === 'BACKEND_SCAN') { backend('/api/scan', msg.payload).then(sendResponse); return true; }
  if (msg.type === 'BACKEND_ANALYZE') { backend('/api/analyze', msg.payload).then(sendResponse); return true; }
  if (msg.type === 'BACKEND_CHAT') { backend('/api/chat', msg.payload).then(sendResponse); return true; }
  if (msg.type === 'BACKEND_VAULT_SAVE') { backend('/api/vault/save', msg.payload).then(sendResponse); return true; }
  if (msg.type === 'BACKEND_VAULT_LOAD') { backend('/api/vault/load', msg.payload).then(sendResponse); return true; }

  const map = {SCAN_ALL:'SCAN', REDACT_ALL:'REDACT', ANALYSE_ALL:'ANALYSE', CHAT_CONTEXT_ALL:'CHAT_CONTEXT', SAVE_ALL:'SAVE_FORM'};
  if (map[msg.type]) {
    (async()=>{
      try {
        const results = await allFrames(msg.tabId, map[msg.type]);
        sendResponse({ok:true, results});
      } catch(error) {
        sendResponse({ok:false, results:[], message:error?.message || 'Frame operation failed'});
      }
    })();
    return true;
  }
  if (msg.type === 'COMMAND_ALL') {
    (async()=>{
      try {
        const results = await allFrames(msg.tabId, 'COMMAND', {command:msg.command});
        const response = results.find(x=>x.ok && x.message) || results[0];
        sendResponse(response || {ok:false,message:'No accessible page frame responded.'});
      } catch(error) {
        sendResponse({ok:false,message:error?.message || 'Command failed'});
      }
    })();
    return true;
  }
});

updateBackendStatus();
