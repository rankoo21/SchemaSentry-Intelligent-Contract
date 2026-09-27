# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""Consensus-backed API schema drift detector."""
from genlayer import *
from urllib.parse import urlparse
import hashlib, json

def enc(v): return json.dumps(v, sort_keys=True, separators=(",", ":"))
def ident(v):
    v=v.strip().upper()
    if not 3<=len(v)<=64 or not all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in v): raise gl.vm.UserError("invalid contract ID")
    return v
def https(v):
    p=urlparse(v.strip())
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.fragment: raise gl.vm.UserError("clean HTTPS URL required")
    return v.strip()
def schema(raw):
    x=json.loads(raw)
    if type(x) is not dict or not 1<=len(x)<=80: raise ValueError("schema must be an object")
    out={}
    for k,v in x.items():
        if not isinstance(k,str) or not k or len(k)>120 or v not in ("string","number","boolean","object","array","null"): raise ValueError("invalid schema entry")
        out[k]=v
    return out
def result(raw):
    x=json.loads(raw)
    if type(x) is not dict or set(x)!={"status","summary","breaking_paths"} or x["status"] not in ("COMPATIBLE","DRIFTED","UNAVAILABLE"): raise ValueError("bad audit")
    if not isinstance(x["breaking_paths"],list) or len(x["breaking_paths"])>80: raise ValueError("bad paths")
    return {"status":x["status"],"summary":str(x["summary"])[:400],"breaking_paths":[str(v)[:120] for v in x["breaking_paths"]]}
def assess(packet):
    """Deterministic schema comparison after the nondeterministic web fetch.

    Keeping the state-driving classification deterministic prevents model-format
    variance from turning an otherwise identical web response into a consensus
    failure. The fetched bytes remain consensus-checked and are permanently
    committed via their digest.
    """
    try:
        body=json.loads(packet["body"])
    except Exception:
        return {"status":"UNAVAILABLE","summary":"response is not valid JSON","breaking_paths":[]}
    if type(body) is not dict:
        return {"status":"DRIFTED","summary":"response root is not an object","breaking_paths":["$/*"]}
    breaks=[]
    for path,kind in packet["expected"].items():
        if path not in body:
            breaks.append(path)
            continue
        v=body[path]
        actual=("boolean" if type(v) is bool else "number" if type(v) in (int,float) else
                "string" if isinstance(v,str) else "object" if type(v) is dict else
                "array" if type(v) is list else "null")
        if actual!=kind: breaks.append(path)
    if breaks:
        return {"status":"DRIFTED","summary":"one or more expected fields are missing or changed","breaking_paths":breaks[:80]}
    return {"status":"COMPATIBLE","summary":"all expected fields match the registered schema","breaking_paths":[]}

class SchemaSentry(gl.Contract):
    contracts: TreeMap[str,str]
    def __init__(self): pass
    def key(self,o,i): return str(o).lower()+":"+ident(i)
    @gl.public.write
    def register_contract(self,contract_id:str,endpoint_url:str,expected_schema_json:str)->None:
        owner=str(gl.message.sender_address).lower(); key=self.key(owner,contract_id)
        if self.contracts.get(key,""): raise gl.vm.UserError("contract ID already exists")
        u=https(endpoint_url)
        try: expected=schema(expected_schema_json)
        except Exception: raise gl.vm.UserError("invalid expected schema")
        self.contracts[key]=enc({"id":ident(contract_id),"owner":owner,"endpoint":u,"expected":expected,"state":"OPEN","status":"","summary":"","breaking_paths":[],"digest":"","fingerprint":""})
    @gl.public.write
    def audit_contract(self,contract_id:str)->None:
        key=self.key(str(gl.message.sender_address),contract_id); r=json.loads(self.contracts.get(key,"{}"))
        if not r or r["state"]!="OPEN": raise gl.vm.UserError("contract is not open")
        def run():
            body=gl.nondet.web.get(r["endpoint"]).body.decode("utf-8")
            if not 2<=len(body)<=100000: raise gl.vm.UserError("endpoint unavailable")
            out=assess({"expected":r["expected"],"body":body})
            return enc({**out,"digest":hashlib.sha256(body.encode()).hexdigest(),"fingerprint":hashlib.sha256(enc(r["expected"]).encode()).hexdigest()})
        def valid(x):
            if not isinstance(x,gl.vm.Return): return False
            try:
                body=gl.nondet.web.get(r["endpoint"]).body.decode("utf-8")
                out=assess({"expected":r["expected"],"body":body})
                expected={**out,"digest":hashlib.sha256(body.encode()).hexdigest(),"fingerprint":hashlib.sha256(enc(r["expected"]).encode()).hexdigest()}
                return json.loads(x.calldata)==expected
            except Exception: return False
        r.update(json.loads(gl.vm.run_nondet_unsafe(run,valid))); r["state"]="AUDITED"; self.contracts[key]=enc(r)
    @gl.public.view
    def get_contract(self,owner:str,contract_id:str)->str: return self.contracts.get(self.key(owner,contract_id),"{}")
