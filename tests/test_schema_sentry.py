import json,pytest
from test_harness import load
@pytest.fixture
def e(): return load('schema_sentry.py','SchemaSentry','contracts')
def test_audit_receipt(e):
 _,c,q,b,U=e;c.register_contract('API-1','https://api.example/data','{"data.id":"string","data.items":"array"}');body='{"data":{"id":"x","items":[]}}';b.extend([body,body]);q.extend(['{"status":"COMPATIBLE","summary":"All declared paths match.","breaking_paths":[]}']*2);c.audit_contract('api-1');r=json.loads(c.get_contract('0xowner','API-1'));assert r['state']=='AUDITED' and len(r['digest'])==64
def test_guards(e):
 _,c,q,b,U=e
 with pytest.raises(U): c.register_contract('BAD','http://api.example/data','{"id":"string"}')
 c.register_contract('API-1','https://api.example/data','{"id":"string"}')
 with pytest.raises(U): c.register_contract(' api-1 ','https://other.example/data','{"id":"string"}')
def test_forged_validator_rejected(e):
 _,c,q,b,U=e;c.register_contract('API-2','https://api.example/data','{"id":"string"}');b.extend(['{"id":1}','{"id":"validator-view"}'])
 with pytest.raises(U): c.audit_contract('API-2')
