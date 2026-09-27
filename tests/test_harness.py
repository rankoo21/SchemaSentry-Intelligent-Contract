import importlib.util,pickle,sys,types
from pathlib import Path
class Map(dict):
 @classmethod
 def __class_getitem__(c,_): return c
class Return:
 def __init__(s,v): s.calldata=v
class UserError(Exception): pass
class Response:
 def __init__(s,v): s.body=v.encode()
def load(filename,cls,slot):
 prompts=[]; bodies=[]
 def prompt(x): return prompts.pop(0)
 def get(_): return Response(bodies.pop(0))
 def run(a,b):
  v=a(); assert pickle.loads(pickle.dumps(v))==v
  if not b(Return(v)): raise UserError('disagreement')
  return v
 ident=lambda f:f
 gl=types.SimpleNamespace(Contract=object,public=types.SimpleNamespace(write=ident,view=ident),message=types.SimpleNamespace(sender_address='0xowner'),vm=types.SimpleNamespace(Return=Return,UserError=UserError,run_nondet_unsafe=run),nondet=types.SimpleNamespace(exec_prompt=prompt,web=types.SimpleNamespace(get=get)))
 m=types.ModuleType('genlayer');m.gl=gl;m.TreeMap=Map;m.__all__=['gl','TreeMap'];sys.modules['genlayer']=m
 p=importlib.util.spec_from_file_location(cls,Path(__file__).parent/filename);mod=importlib.util.module_from_spec(p);p.loader.exec_module(mod);c=getattr(mod,cls).__new__(getattr(mod,cls));setattr(c,slot,Map());c.__init__();return mod,c,prompts,bodies,UserError
