(()=>{
  if (window.__privacyPilotLoaded) return;
  window.__privacyPilotLoaded = true;

  const state = {paused:false,lastScan:[]};
  const PII_PATTERNS = [
    {type:'Email', re:/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi},
    {type:'Phone', re:/(?:\+91[\s-]?)?[6-9]\d{9}\b/g},
    {type:'Aadhaar', re:/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g},
    {type:'PAN', re:/\b[A-Z]{5}\d{4}[A-Z]\b/gi},
    {type:'Credit Card', re:/\b(?:\d[ -]*?){13,19}\b/g},
    {type:'IPv4', re:/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g},
    {type:'IBAN', re:/\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/gi}
  ];
  const SENSITIVE_NAME = /email|e-mail|phone|mobile|telephone|tel|aadhaar|aadhar|pan|password|passcode|otp|cvv|cvc|card|credit|debit|ssn|social.?security|dob|birth|address|secret|token|api.?key|account|upi|bank|routing|passport|license|username|user.?id/i;

  const log = (action, detail) => {
    chrome.runtime.sendMessage({type:'LOG',entry:{action,detail,url:location.href,title:document.title,frame:location.host}}).catch(()=>{});
  };
  const visible = e => {
    if (!e) return false;
    const r=e.getBoundingClientRect(), s=getComputedStyle(e);
    return r.width>0 && r.height>0 && s.visibility!=='hidden' && s.display!=='none';
  };
  const fields = () => [...document.querySelectorAll('input,textarea,select')].filter(visible);
  const fieldName = e => {
    const label = e.labels?.[0]?.innerText?.trim();
    return e.getAttribute('aria-label') || e.getAttribute('data-label') || e.name || e.id || label || e.getAttribute('placeholder') || 'Unnamed field';
  };
  const stableKey = e => {
    const parts = [e.name,e.id,e.getAttribute('autocomplete'),e.type,fieldName(e)].filter(Boolean).map(x=>String(x).trim().toLowerCase());
    return parts.join('|') || `field-${[...fields()].indexOf(e)}`;
  };
  const norm = s => String(s??'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim();
  const classify = e => {
    const meta=[fieldName(e),e.name,e.id,e.placeholder,e.type,e.autocomplete].filter(Boolean).join(' ');
    if (/password/i.test(meta)) return 'Password';
    if (/email/i.test(meta)) return 'Email';
    if (/phone|mobile|telephone|tel/i.test(meta)) return 'Phone';
    if (/aadhaar|aadhar/i.test(meta)) return 'Aadhaar';
    if (/pan/i.test(meta)) return 'PAN';
    if (/cvv|cvc/i.test(meta)) return 'CVV';
    if (/otp|one.?time/i.test(meta)) return 'OTP';
    if (/credit|debit|card/i.test(meta)) return 'Credit Card';
    if (/dob|birth/i.test(meta)) return 'Date of Birth';
    if (/address/i.test(meta)) return 'Address';
    if (/ssn|social.?security/i.test(meta)) return 'SSN';
    if (/passport/i.test(meta)) return 'Passport';
    if (/license|licence/i.test(meta)) return 'License';
    if (/bank|routing|account|upi/i.test(meta)) return 'Bank/Account';
    if (/username|user.?id/i.test(meta)) return 'Username';
    if (/pin/i.test(meta)) return 'PIN';
    return null;
  };
  const textNodes = () => {
    if (!document.body) return [];
    const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);
    const result=[]; let node;
    while(node=walker.nextNode()){
      const p=node.parentElement;
      if(p && !/^(SCRIPT|STYLE|NOSCRIPT|SVG|INPUT|TEXTAREA|OPTION)$/i.test(p.tagName) && node.nodeValue.trim()) result.push(node);
    }
    return result;
  };
  const freshRegex = re => new RegExp(re.source,re.flags);

  function scan(){
    const found=[], seen=new Set();
    const add=(type,value,field='Page text',el=null,reason='pattern')=>{
      const clean=String(value??'');
      const key=[type,field,clean].join('|');
      if(seen.has(key)) return;
      seen.add(key);
      found.push({id:crypto.randomUUID(),type,value:clean,field,hidden:false,fieldKey:el?stableKey(el):null,reason});
    };
    for(const node of textNodes()){
      for(const p of PII_PATTERNS){
        for(const match of node.nodeValue.matchAll(freshRegex(p.re))) add(p.type,match[0],'Page text',null,'pattern');
      }
    }
    for(const e of fields()){
      const name=fieldName(e), value=e.value||'', kind=classify(e);
      if(kind) add(kind,value||'[empty]',name,e,'sensitive-field');
      for(const p of PII_PATTERNS){
        for(const match of value.matchAll(freshRegex(p.re))) add(p.type,match[0],name,e,'pattern');
      }
    }
    state.lastScan=found;
    return found;
  }

  function maskField(e){
    if(e.dataset.ppMasked==='true') return false;
    e.dataset.ppOriginalValue=e.value;
    e.dataset.ppOriginalType=e.type;
    e.dataset.ppMasked='true';
    try { if(e.type!=='password') e.type='password'; } catch {}
    e.value='••••••••';
    e.setAttribute('data-privacy-pilot-masked','true');
    e.dispatchEvent(new Event('input',{bubbles:true}));
    e.dispatchEvent(new Event('change',{bubbles:true}));
    return true;
  }

  function redact(){
    const found=state.lastScan.length?state.lastScan:scan();
    let hidden=0;
    for(const e of fields()){
      const value=e.value||'', key=stableKey(e), kind=classify(e);
      const hit=!!kind || found.some(x => x.fieldKey===key || (x.value && x.value!=='[empty]' && value.includes(x.value)));
      if(hit && maskField(e)) hidden++;
    }
    for(const node of textNodes()){
      let value=node.nodeValue, changed=false;
      for(const item of found){
        if(item.value && item.value!=='[empty]' && value.includes(item.value)){
          value=value.split(item.value).join('████████'); changed=true;
        }
      }
      if(changed){node.nodeValue=value; hidden++;}
    }
    state.lastScan=found.map(x=>({...x,hidden:true}));
    log('PII_REDACTED',`${hidden} sensitive element(s) hidden locally`);
    return state.lastScan;
  }

  function analyse(){
    const mapped=fields().map((e,index)=>({
      index,name:fieldName(e),key:stableKey(e),type:e.type||e.tagName.toLowerCase(),
      sensitive:!!classify(e),valuePresent:!!e.value,required:!!e.required,autocomplete:e.autocomplete||''
    }));
    const result={title:document.title,url:location.href,origin:location.origin,headings:[...document.querySelectorAll('h1,h2,h3')].map(x=>x.innerText.trim()).filter(Boolean).slice(0,30),fields:mapped};
    log('PAGE_ANALYSED',`${mapped.length} form field(s) mapped locally`);
    return result;
  }

  function findField(target){
    const q=norm(target), words=q.split(' ').filter(Boolean);
    let best=null,bestScore=0;
    for(const e of fields()){
      const hay=norm([fieldName(e),e.name,e.id,e.placeholder,e.type,e.autocomplete].join(' '));
      let score=0;
      if(hay===q) score+=20;
      for(const word of words) if(hay.includes(word)) score+=2;
      if(score>bestScore){bestScore=score;best=e;}
    }
    return best;
  }

  function setValue(e,value){
    const text=String(value??'');
    if(e.tagName==='SELECT'){
      const option=[...e.options].find(o=>o.value===text || o.textContent.trim().toLowerCase()===text.trim().toLowerCase());
      e.value=option?option.value:text;
    } else {
      const proto=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;
      const setter=Object.getOwnPropertyDescriptor(proto,'value')?.set;
      if(setter) setter.call(e,text); else e.value=text;
    }
    e.dataset.ppMasked='false'; delete e.dataset.ppOriginalValue; delete e.dataset.ppOriginalType;
    e.dispatchEvent(new Event('input',{bubbles:true}));
    e.dispatchEvent(new Event('change',{bubbles:true}));
    e.dispatchEvent(new Event('blur',{bubbles:true}));
  }

  async function getKey(){
    let {skey}=await chrome.storage.local.get({skey:null});
    if(!skey){
      const cryptoKey=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
      const raw=await crypto.subtle.exportKey('raw',cryptoKey);
      skey=btoa(String.fromCharCode(...new Uint8Array(raw)));
      await chrome.storage.local.set({skey});
    }
    const raw=Uint8Array.from(atob(skey),c=>c.charCodeAt(0));
    return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
  }
  const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
  async function encrypt(obj){
    const key=await getKey(), iv=crypto.getRandomValues(new Uint8Array(12));
    const plaintext=new TextEncoder().encode(JSON.stringify(obj));
    const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,plaintext);
    return {version:2,algorithm:'AES-GCM-256',iv:b64(iv),ct:b64(ciphertext)};
  }
  async function decrypt(box){
    if(!box?.iv || !box?.ct) throw new Error('Invalid encrypted vault record');
    const key=await getKey();
    const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(box.iv)},key,unb64(box.ct));
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  async function save(){
    const values={};
    for(const e of fields()){
      let value=e.value||'';
      if(e.dataset.ppMasked==='true' && e.dataset.ppOriginalValue!==undefined) value=e.dataset.ppOriginalValue;
      if(value!=='') values[stableKey(e)]={name:fieldName(e),value,type:e.type,sensitive:!!classify(e),autocomplete:e.autocomplete||''};
    }
    const payload={schema:2,origin:location.origin,hostname:location.hostname,path:location.pathname,values,savedAt:new Date().toISOString()};
    const box=await encrypt(payload);
    const vaultId=`${location.origin}${location.pathname}`.slice(0,1000);
    const response=await new Promise(resolve=>chrome.runtime.sendMessage({type:'BACKEND_VAULT_SAVE',payload:{vaultId,ciphertext:box}},resolve));
    if(!response?.ok){
      const {localVault={}}=await chrome.storage.local.get({localVault:{}});
      localVault[vaultId]=box;
      await chrome.storage.local.set({localVault});
      log('FORM_SAVED',`${Object.keys(values).length} field(s) encrypted locally; backend unavailable, local fallback used`);
    } else {
      await chrome.storage.local.set({lastVaultSync:response.savedAt||new Date().toISOString()});
      log('FORM_SAVED',`${Object.keys(values).length} field(s) encrypted; backend received ciphertext only`);
    }
    return Object.keys(values).length;
  }

  async function loadBox(){
    const vaultId=`${location.origin}${location.pathname}`.slice(0,1000);
    const response=await new Promise(resolve=>chrome.runtime.sendMessage({type:'BACKEND_VAULT_LOAD',payload:{vaultId}},resolve));
    if(response?.ok && response.ciphertext) return response.ciphertext;
    const {localVault={}}=await chrome.storage.local.get({localVault:{}});
    return localVault[vaultId] || null;
  }

  async function fillSaved(){
    const box=await loadBox();
    if(!box) {log('FORM_AUTOFILLED','No saved form found for this page');return 0;}
    let saved;
    try { saved=await decrypt(box); } catch(error) { log('AUTOFILL_ERROR','Encrypted vault could not be decrypted on this device'); return 0; }
    let count=0;
    const savedValues=Object.values(saved.values||{});
    for(const e of fields()){
      const direct=saved.values?.[stableKey(e)];
      const targetName=norm(fieldName(e));
      const targetAuto=norm(e.autocomplete||'');
      const match=direct || savedValues.find(item=>norm(item.name)===targetName || (targetAuto && norm(item.autocomplete)===targetAuto));
      if(match){setValue(e,match.value);count++;}
    }
    log('FORM_AUTOFILLED',`${count} saved field(s) restored locally, including sensitive fields`);
    return count;
  }

  function submit(){
    const activeForm=document.activeElement?.form;
    const form=activeForm || fields().find(e=>e.form)?.form;
    if(form){ if(form.requestSubmit) form.requestSubmit(); else form.submit(); log('FORM_SUBMITTED','Form submit triggered locally'); return true; }
    const button=[...document.querySelectorAll('button,input[type=submit],input[type=button]')].find(e=>visible(e)&&/submit|send|continue|apply|register|login/i.test(e.innerText||e.value||''));
    if(button){button.click();log('FORM_SUBMITTED','Submit control clicked locally');return true;}
    return false;
  }

  async function command(raw){
    if(state.paused) return {ok:false,message:'AI action is stopped. Tap Continue to resume.'};
    const c=String(raw||'').trim(); if(!c) return {ok:false,message:'Enter a command first.'};
    const low=c.toLowerCase();
    if(/^(scan|scan page|analyze page|analyse page)$/.test(low) || /scan.*page/.test(low)){
      const data=scan();log('PAGE_SCANNED',`${data.length} sensitive item(s) detected locally`);return{ok:true,message:`Page scanned — ${data.length} sensitive item(s) found.`,data};
    }
    if(/^(redact|redact page|hide sensitive|mask sensitive)/.test(low) || /redact|mask|hide.*sensitive/.test(low)){
      const data=redact();return{ok:true,message:`Sensitive data hidden locally — ${data.filter(x=>x.hidden).length} item(s).`,data};
    }
    if(/fill.*saved|saved.*form|autofill|fill this form/.test(low)){
      const count=await fillSaved();return{ok:true,message:`Autofilled ${count} saved field(s), including sensitive fields, locally.`};
    }
    if(/submit.*after.*fill|fill.*then.*submit|fill.*and.*submit/.test(low)){ const filled=await fillSaved(); const submitted=submit(); return submitted?{ok:true,message:`Filled ${filled} saved field(s) and triggered submit locally.`}:{ok:false,message:`Filled ${filled} saved field(s), but no submit control was found.`}; }
    if(/submit/.test(low)) return submit()?{ok:true,message:'Submit action triggered locally.'}:{ok:false,message:'No submit control found.'};
    const match=c.match(/(?:fill|type|enter|set)\s+(?:the\s+)?["“]?(.+?)["”]?\s+(?:with|as|to)\s+["“](.*?)["”]$/i) || c.match(/(?:fill|type|enter|set)\s+["“]?(.+?)["”]?\s*[:=]\s*["“]?(.*?)["”]?$/i);
    if(match){
      const e=findField(match[1]);
      if(!e) return{ok:false,message:`Couldn't find a field matching "${match[1]}".`};
      setValue(e,match[2]);log('FIELD_FILLED',`${fieldName(e)} filled by local command`);return{ok:true,message:`Filled ${fieldName(e)} locally.`};
    }
    return{ok:false,message:'More than my chat. Try scan page, redact, fill saved form, submit, or fill a named field.'};
  }

  chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{
    if(msg.type==='PING'){sendResponse({ok:true});return;}
    if(msg.type==='PAUSE'){state.paused=!!msg.value;return;}
    try{
      if(msg.type==='SCAN'){const data=scan();const snapshot={text:document.body?.innerText||'',fields:fields().map(e=>({name:fieldName(e),value:e.dataset.ppMasked==='true'?(e.dataset.ppOriginalValue||''):e.value||'',type:e.type||e.tagName.toLowerCase(),autocomplete:e.autocomplete||'',sensitive:!!classify(e)}))};sendResponse({ok:true,data,snapshot});return;}
      if(msg.type==='REDACT'){sendResponse({ok:true,data:redact()});return;}
      if(msg.type==='ANALYSE'){sendResponse({ok:true,data:analyse()});return;}
      if(msg.type==='CHAT_CONTEXT'){sendResponse({ok:true,data:analyse()});return;}
      if(msg.type==='SAVE_FORM'){save().then(count=>sendResponse({ok:true,count})).catch(e=>sendResponse({ok:false,message:e?.message||'Save failed'}));return true;}
      if(msg.type==='COMMAND'){command(msg.command).then(sendResponse).catch(e=>sendResponse({ok:false,message:e?.message||'Command failed'}));return true;}
    }catch(error){sendResponse({ok:false,message:error?.message||'Page operation failed'});}
  });
})();
