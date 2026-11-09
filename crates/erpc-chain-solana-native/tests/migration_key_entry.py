# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual Rust-created stdin frame/hash loader; only the final host probe is inert."""
import base64
import json
import shlex
import subprocess
import sys
import zlib
command=base64.b64decode(sys.stdin.buffer.readline().strip(),validate=True).decode()
packet=base64.b64decode(sys.stdin.buffer.readline().strip(),validate=True)
parts=shlex.split(command)
assert parts[:5]==['sudo','-n','/usr/bin/python3','-I','-c'] and len(parts)==6
program=parts[5]
# Exercise the exact bootstrap/compiled module dispatch; replace only the host
# observation at its final call boundary so no NSS, file, key or RPC is touched.
shim='''import os,builtins
os.geteuid=lambda:0
original=builtins.exec
def execute(code,namespace=None,locals=None):
 if namespace is None:return original(code,globals())
 result=original(code,namespace,locals)
 if namespace.get('__name__')=='native_migration_key':
  def inspect(request,withdrawer):
   if request!={'network':'testnet'} or withdrawer is not None:raise ValueError('fixture scope differs')
   return {'observed_original':True,'private_exported':False}
  namespace['inspect']=inspect
 return result
builtins.exec=execute
'''
def run(body):
 return subprocess.run([sys.executable,'-I','-c',shim+'\n'+program],input=body,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
result=run(packet)
assert result.returncode==0 and json.loads(result.stdout)=={'observed_original':True,'private_exported':False},result.stderr
for body in (b'',b'x'*65537+b'\n',base64.b64encode(zlib.compress(b"print('INERT_PRIVATE_MARKER')"))+b'\n{}',packet.split(b'\n',1)[0]+b'\n{"legacy":{},"withdrawer":null,"key_file":"INERT_PRIVATE_MARKER"}'):
 result=run(body)
 assert result.returncode!=0 and result.stdout==b'' and b'INERT_PRIVATE_MARKER' not in result.stderr
print('actual public frame dispatch and four wrong-source/request boundaries passed')
