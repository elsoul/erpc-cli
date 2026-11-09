# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual emitted private loader with inert source and descriptor-bound run files."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
COMMAND=sys.stdin.read();ARGV=shlex.split(COMMAND)
assert ARGV[:5]==['sudo','-n','/usr/bin/python3','-I','-c']
SOURCE=ARGV[5]
PROFILE=ARGV[10] if len(ARGV)==11 else 'arbitrum'
assert PROFILE in ('arbitrum','robinhood-mainnet','robinhood-testnet')


class Private(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve();self.run='r-private-fixture'
        self.directory=self.root/'opt/erpc/runs'/self.run
        self.node=self.directory/'bundle/validator/node';self.node.mkdir(parents=True)
        self.events=self.root/'events';self.drift=self.root/'drift';self.private_reads=0;self.secret='INERT_PRIVATE_STAGE';self.provider=False
        script='''import json,sys
from pathlib import Path
import wallet_stage,provider_stage
class Control:
    def __init__(self,value):self.expected=value
def main():
    value=json.load(sys.stdin)
    assert value['secret']==SECRET
    with open(EVENTS,'a') as out:out.write('import\\n')
    print('{"original_verified":true}')
'''.replace('SECRET',repr(self.secret)).replace('EVENTS',repr(str(self.events)))
        check='''from pathlib import Path
def check(instance,intent,restore):
    with open(EVENTS,'a') as out:out.write('check\\n')
    if Path(DRIFT).exists():raise ValueError('inert original namespace drift')
'''.replace('EVENTS',repr(str(self.events))).replace('DRIFT',repr(str(self.drift)))
        self.files={'control.py':script.encode(),'wallet_stage.py':check.encode(),'entry.py':b'# inert\n','upstreams.py':b'# inert\n',
                    'provider_stage.py':check.replace('intent,restore','intent').encode()}
        digest=hashlib.sha256()
        for name,raw in sorted(self.files.items()):
            (self.node/name).write_bytes(raw);digest.update(name.encode()+b'\0'+hashlib.sha256(raw).digest())
        self.helpers=digest.hexdigest();archive=b'inert public archive';self.bundle=hashlib.sha256(archive).hexdigest()
        (self.directory/'bundle.tar.gz').write_bytes(archive)
        self.request='d'*64;self.contract={'wallet':'0x'+'1'*40}
        if PROFILE!='arbitrum':self.contract.update(family='robinhood',role='defensive-validator',network=PROFILE.removeprefix('robinhood-'))
        self.approval={'contract':self.contract,'wallet':self.contract['wallet'],'requires_import':True,'observer_required':False,'intent':'e'*32,'restore':False}
        self.public={'schema':'erpc-arbitrum-public-result-v1' if PROFILE=='arbitrum' else 'erpc-robinhood-defensive-result-v1','run':self.run,'bundle_sha256':self.bundle,
                     'helpers_sha256':self.helpers,'request_sha256':self.request,'result':self.approval}
        self.write('result.json',{'status':'ok','exit_code':0,'play':'validator/ansible/control.yml'})
        self.write('sealed.json',{'bundle':self.bundle});self.write('validator-public-result.json',self.public)
        self.namespace={'__name__':'fixture'};exec(compile(SOURCE,'<actual-emitted-loader>','exec'),self.namespace)
        self.verify=self.namespace['verified']
        self.namespace['verified']=lambda *args,**kwargs:self.verify(*args,root=self.root,owner=os.getuid(),**kwargs)
        self.addCleanup(self.modules)

    def modules(self):
        for name in self.files:sys.modules.pop(name[:-3],None)

    def write(self,name,value):(self.directory/name).write_text(json.dumps(value))

    def execute(self,change=None):
        value={'action':'wallet-stage-import','contract':self.contract,'intent':'e'*32,'restore':False,'secret':self.secret}
        if self.provider:value=dict(action='provider-stage-import',contract=self.contract,intent='e'*32,secret=self.secret)
        value.update(change or {})
        events=self.events;outer=self
        class Stream(io.BytesIO):
            def read(self,*args):
                outer.private_reads+=1
                assert events.exists() and events.read_text()=='check\n','private input consumed before original-host check'
                return super().read(*args)
        previous=sys.stdin;argv=list(sys.argv);out=io.StringIO()
        try:
            sys.stdin=type('Input',(),{'buffer':Stream(json.dumps(value).encode())})()
            with contextlib.redirect_stdout(out):self.namespace['execute'](self.run,self.bundle,self.helpers,self.request,profile=PROFILE)
        finally:sys.stdin=previous;sys.argv=argv;self.modules()
        self.assertNotIn(self.secret,out.getvalue())
        return out.getvalue()

    def test_foreign_network_or_family_cannot_consume_private_stdin(self):
        if PROFILE=='arbitrum':return
        for changes in ({'network':'testnet' if PROFILE.endswith('mainnet') else 'mainnet'}, {'family':'arbitrum'},{'role':'assertion-validator'}):
            self.public['result']=dict(self.approval,contract=dict(self.contract,**changes))
            self.write('validator-public-result.json',self.public)
            with self.assertRaises(ValueError):self.execute()
            self.assertEqual(self.private_reads,0);self.assertFalse(self.events.exists())

    def provider_approval(self):
        self.provider=True
        self.public['result']={key:self.approval[key] for key in ('contract','intent','requires_import')}
        self.write('validator-public-result.json',self.public)

    def test_provider_exact_authorization_uses_same_closed_source_before_private_read(self):
        self.provider_approval()
        self.assertIn('original_verified',self.execute())
        self.assertEqual(self.events.read_text(),'check\nimport\n')

    def test_provider_authority_drift_and_wallet_action_cannot_cross_private_channel(self):
        self.provider_approval();self.drift.touch()
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.private_reads,0)
        self.drift.unlink();self.events.unlink()
        with self.assertRaises(ValueError):self.execute({'action':'wallet-stage-import','restore':False})
        self.assertEqual(self.events.read_text(),'check\n')


    def test_checked_source_executes_only_after_public_proof_and_rechecks_before_private_read(self):
        self.assertIn('original_verified',self.execute())
        self.assertEqual(self.events.read_text(),'check\nimport\n')
        self.assertNotIn(self.secret,COMMAND)
        self.assertLess(len(COMMAND.encode('utf-16-le'))//2+8192+COMMAND.count('"')+2,32767)

    def test_original_authority_drift_refuses_before_consuming_private_stdin(self):
        self.drift.touch()
        with self.assertRaises(ValueError):self.execute()
        self.assertEqual(self.private_reads,0)
        self.assertEqual(self.events.read_text(),'check\n')

    def test_wrong_result_run_or_request_never_imports_source_or_reads_private_input(self):
        for field,value in [('request_sha256','0'*64),('helpers_sha256','0'*64),('run','r-other-fixture')]:
            self.write('validator-public-result.json',dict(self.public,**{field:value}))
            with self.assertRaises(ValueError):self.execute()
            self.assertFalse(self.events.exists())
        self.write('validator-public-result.json',self.public)
        self.write('result.json',{'status':'failed','exit_code':1,'play':'validator/ansible/control.yml'})
        with self.assertRaises(ValueError):self.execute()
        self.assertFalse(self.events.exists())

    def test_writable_replaced_linked_or_changed_source_never_runs(self):
        target=self.node/'control.py';original=target.read_bytes()
        target.chmod(0o666)
        with self.assertRaises(ValueError):self.execute()
        target.chmod(0o644);target.write_bytes(original+b'\n# inert substitution\n')
        with self.assertRaises(ValueError):self.execute()
        target.write_bytes(original);alias=self.root/'alias';os.link(target,alias)
        with self.assertRaises(ValueError):self.execute()
        alias.unlink();target.unlink();target.symlink_to(self.node/'entry.py')
        with self.assertRaises(OSError):self.execute()
        self.assertFalse(self.events.exists())

    def test_source_is_executed_from_verified_descriptor_bytes_not_a_later_reopen(self):
        def replaced(*args,**kwargs):
            result=self.verify(*args,root=self.root,owner=os.getuid(),**kwargs)
            (self.node/'control.py').write_text('raise AssertionError("unverified replacement executed")')
            return result
        self.namespace['verified']=replaced
        self.execute();self.assertEqual(self.events.read_text(),'check\nimport\n')

    def test_wrong_private_operation_scope_or_restore_never_reaches_import(self):
        for value in ({'action':'prepare'},{'intent':'f'*32},{'restore':True},{'contract':{'wallet':'0x'+'2'*40}}):
            self.events.unlink(missing_ok=True)
            with self.assertRaises(ValueError):self.execute(value)
            self.assertEqual(self.events.read_text(),'check\n')


if __name__=='__main__':unittest.main()
