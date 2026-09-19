from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from datetime import datetime, timezone
import json, re

HOST='127.0.0.1'; PORT=8765
DATA=Path(__file__).parent/'data'; DATA.mkdir(parents=True,exist_ok=True)
VAULT=DATA/'vault.json'
app=FastAPI(title='PrivacyPilot Local AI Backend',version='6.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['*'],allow_methods=['*'],allow_headers=['*'])

PATTERNS={
 'Email':re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),
 'Phone':re.compile(r'(?:\+91[\s-]?)?[6-9]\d{9}\b'),
 'Aadhaar':re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
 'PAN':re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b',re.I),
 'Credit Card':re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
 'IPv4':re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'),
 'IBAN':re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',re.I),
}
SENSITIVE=re.compile(r'email|e-mail|phone|mobile|telephone|tel|aadhaar|aadhar|pan|password|passcode|otp|cvv|cvc|card|credit|debit|ssn|social.?security|dob|birth|address|secret|token|api.?key|account|upi|bank|routing|passport|license|username|user.?id|pin',re.I)

def mask(value):
    value=str(value or '')
    return '••••' if len(value)<=4 else '••••••••'+value[-4:]

def canonical_type(value):
    v=str(value or '').strip().lower()
    aliases={'email':'Email','phone':'Phone','mobile':'Phone','aadhaar':'Aadhaar','aadhar':'Aadhaar','pan':'PAN','password':'Password','cvv':'CVV','cvc':'CVV','otp':'OTP','credit card':'Credit Card','debit card':'Credit Card','card':'Credit Card','date of birth':'Date of Birth','dob':'Date of Birth','address':'Address','ssn':'SSN','passport':'Passport','license':'License','bank/account':'Bank/Account','account/upi':'Bank/Account','username':'Username','pin':'PIN'}
    return aliases.get(v, value or 'Sensitive Field')

def detect(text,fields):
    result=[]; seen=set()
    def add(kind,field,value):
        key=(kind,field,value)
        if key in seen:return
        seen.add(key); result.append({'type':kind,'field':field,'maskedValue':mask(value) if value else '[empty]'})
    for kind,pattern in PATTERNS.items():
        for match in pattern.finditer(text or ''): add(kind,'Page text',match.group(0))
    for field in fields or []:
        name=str(field.get('name') or 'Unnamed field'); value=str(field.get('value') or '')
        if field.get('sensitive') or SENSITIVE.search(name): add(canonical_type(field.get('type')),name,value)
        for kind,pattern in PATTERNS.items():
            for match in pattern.finditer(value): add(kind,name,match.group(0))
    return result

class ScanRequest(BaseModel):
    text:str=''; fields:list[dict]=Field(default_factory=list)
class AnalyzeRequest(BaseModel):
    title:str=''; url:str=''; headings:list[str]=Field(default_factory=list); fields:list[dict]=Field(default_factory=list)
class ChatRequest(BaseModel):
    question:str=''; title:str=''; url:str=''; headings:list[str]=Field(default_factory=list); fields:list[dict]=Field(default_factory=list)
class VaultRequest(BaseModel):
    vaultId:str; ciphertext:dict|None=None

def read_vault():
    if not VAULT.exists(): return {}
    try:return json.loads(VAULT.read_text(encoding='utf-8'))
    except:return {}

def write_vault(data):
    temp=VAULT.with_suffix('.tmp')
    temp.write_text(json.dumps(data,indent=2),encoding='utf-8')
    temp.replace(VAULT)

@app.get('/health')
def health():
    return {'ok':True,'service':'PrivacyPilot Local AI Backend','bind':'127.0.0.1','cloud_upload':False,'plaintext_storage':False}

@app.post('/api/scan')
def scan(req:ScanRequest):
    # Request plaintext exists only in process memory while this request is handled.
    items=detect(req.text,req.fields)
    return {'ok':True,'items':items,'count':len(items),'processed':'local-memory-only'}

@app.post('/api/analyze')
def analyze(req:AnalyzeRequest):
    return {'ok':True,'title':req.title,'url':req.url,'headingCount':len(req.headings),'fieldCount':len(req.fields),'sensitiveFieldCount':sum(bool(f.get('sensitive')) for f in req.fields)}

@app.post('/api/chat')
def chat(req:ChatRequest):
    q=req.question.lower()
    if 'title' in q or 'page name' in q: answer=f'The page title is "{req.title or "unknown"}".'
    elif any(x in q for x in ('url','website','site','domain')): answer=f'The current page is {req.url or "unknown"}.'
    elif any(x in q for x in ('form','field','input')): answer=f'I found {len(req.fields)} mapped form field(s), including {sum(bool(f.get("sensitive")) for f in req.fields)} sensitive field(s).'
    elif any(x in q for x in ('heading','section')): answer='Visible headings: '+(', '.join(req.headings) if req.headings else 'none detected')+'.'
    else: answer='More than my chat. I do not understand that webpage question yet.'
    return {'ok':True,'answer':answer,'processed':'local-backend'}

@app.post('/api/vault/save')
def vault_save(req:VaultRequest):
    if not req.ciphertext or not req.ciphertext.get('ct') or not req.ciphertext.get('iv'):
        return {'ok':False,'error':'Only encrypted ciphertext is accepted.'}
    vault=read_vault(); now=datetime.now(timezone.utc).isoformat()
    vault[req.vaultId]={'ciphertext':req.ciphertext,'savedAt':now}
    write_vault(vault)
    return {'ok':True,'savedAt':now,'storage':'encrypted-ciphertext-only'}

@app.post('/api/vault/load')
def vault_load(req:VaultRequest):
    record=read_vault().get(req.vaultId)
    if not record:return {'ok':False,'error':'No saved form'}
    return {'ok':True,'ciphertext':record['ciphertext'],'savedAt':record['savedAt']}

if __name__=='__main__':
    import uvicorn
    uvicorn.run(app,host=HOST,port=PORT,log_level='warning')
