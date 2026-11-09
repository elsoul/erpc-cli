# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic encrypted-file fixtures; never invoke Geth or create operational keys."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).parents[1]/'templates/node/validator.py'
spec=importlib.util.spec_from_file_location('bsc_validator_custody',SOURCE)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class Refused(Exception):pass

def require(condition,message):
    if not condition:raise Refused(message)


class Custody(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup);self.addCleanup(patch.stopall)
        root=Path(directory.name)
        def writable():
            for path in [root,*root.rglob('*')]:
                if not path.is_symlink():path.chmod(0o700 if path.is_dir() else 0o600)
        self.addCleanup(writable)
        def save(state):(root/'owner.json').write_text(json.dumps(state))
        self.c=SimpleNamespace(ROOT=root,CONF=root/'config',PROC=root/'proc',require=require,save=save,binary=lambda _:root/'never-execute-geth')
        self.c.PROC.mkdir()
        self.state={'owner':'owned','network':'chapel','operator':'0x'+'2'*40,'service_uid':os.getuid(),'service_gid':os.getgid()}
        patch.object(v,'ROOT_UID',os.getuid()).start()
        (root/'identity').mkdir();peer=b'7'*64;(root/'identity/nodekey').write_bytes(peer)
        self.state['identity_sha256']=hashlib.sha256(peer).hexdigest()
        self.generated=[];self.commands=[]
        patch.object(v.secrets,'token_hex',side_effect=lambda n:'a'*(n*2)).start()
        patch.object(v,'private_run',side_effect=self.credentials).start()
        patch.object(v,'geth',side_effect=self.geth).start()

    def credentials(self,c,argv,body=None,pass_fds=()):
        self.commands.append(argv)
        if argv[:2]==['systemd-creds','setup']:return b''
        if argv[1]=='encrypt':return b'SYNTHETIC-CIPHERTEXT:'+body
        if argv[1]=='decrypt':return body.removeprefix(b'SYNTHETIC-CIPHERTEXT:')
        raise AssertionError('unexpected credential command')

    def geth(self,c,state,password,args):
        self.assertEqual(password,b'a'*64)
        self.assertNotIn(password.decode(),args)
        stage=c.ROOT/'signing-stage'
        if args[:2]==['account','new']:
            self.generated.append('consensus');directory=stage/'consensus';directory.mkdir()
            (directory/('UTC--2026-10-26T12-00-00Z--'+'3'*40)).write_text(json.dumps({'address':'3'*40,'crypto':{'synthetic':True}}))
        elif args[:3]==['bls','account','new']:
            self.generated.append('vote');directory=stage/'bls/keystore';directory.mkdir(parents=True)
            (directory/'keystore-synthetic.json').write_text(json.dumps({'pubkey':'4'*96,'crypto':{'synthetic':True}}))
        elif args[:3]==['bls','account','import']:
            self.assertIn('--importedaccountpassword',args)
            directory=stage/'bls/wallet/direct/accounts';directory.mkdir(parents=True,exist_ok=True)
            (directory/'all-accounts.keystore.json').write_text('{"synthetic":true}')
        elif args[:3]==['bls','account','list']:
            return b'\x1b[35m[BLS public key]\x1b[0m 0x'+b'4'*96+b'\n'
        elif args[:3]==['bls','account','generate-proof']:
            self.assertEqual(args[-3:],['97',self.state['operator'],'4'*96])
            return b'Proof: 0x'+b'5'*192+b'\n'
        else:raise AssertionError('unreviewed client command')
        return b''

    def persisted(self):return json.loads((self.c.ROOT/'owner.json').read_text())

    def test_sealed_publication_preserves_two_distinct_roles_and_private_credentials(self):
        v.provision(self.c,self.state)
        self.assertEqual(self.generated,['consensus','vote'])
        self.assertFalse((self.c.ROOT/'signing-stage').exists())
        self.assertEqual(v.public(self.state)['consensus'],'0x'+'3'*40)
        self.assertNotIn('credentials',v.public(self.state))
        self.assertTrue(all('a'*64 not in part for argv in self.commands for part in argv))
        v.provision(self.c,self.state)
        self.assertEqual(self.generated,['consensus','vote'])

    def test_crash_after_receipt_before_rename_reuses_exact_encrypted_material(self):
        original=self.c.save
        def save(state):
            original(state)
            if state['custody']['phase']=='sealed':raise RuntimeError('simulated power loss')
        self.c.save=save
        with self.assertRaises(RuntimeError):v.provision(self.c,self.state)
        self.c.save=original
        state=self.persisted();expected=copy.deepcopy(state['custody'])
        self.assertTrue((self.c.ROOT/'signing-stage').is_dir())
        v.provision(self.c,state)
        self.assertTrue(state['custody'].pop('published'))
        self.assertEqual(state['custody'],expected)
        state['custody']['published']=True
        self.assertEqual(self.generated,['consensus','vote'])

    def test_crash_before_sealed_receipt_does_not_generate_replacement_keys(self):
        original=self.c.save
        def save(state):
            if state['custody']['phase']=='sealed':raise RuntimeError('simulated interrupted save')
            original(state)
        self.c.save=save
        with self.assertRaises(RuntimeError):v.provision(self.c,self.state)
        self.c.save=original
        state=self.persisted();self.assertEqual(state['custody']['phase'],'preparing')
        v.provision(self.c,state)
        self.assertEqual(self.generated,['consensus','vote'])
        v.guard(self.c,state)

    def test_established_loss_or_substitution_refuses_without_new_entropy(self):
        v.provision(self.c,self.state)
        key=next((self.c.ROOT/'signer/consensus').iterdir());original=key.read_bytes()
        key.chmod(0o600);key.write_bytes(b'tampered');key.chmod(0o440)
        with self.assertRaises(Refused):v.provision(self.c,self.state)
        key.parent.chmod(0o750);key.unlink();key.parent.chmod(0o550)
        with self.assertRaises(Refused):v.provision(self.c,self.state)
        key.parent.chmod(0o750);key.write_bytes(original);key.chmod(0o440);key.parent.chmod(0o550);v.guard(self.c,self.state)
        self.assertEqual(self.generated,['consensus','vote'])

    def test_live_dedicated_account_refuses_staging_reclamation_or_key_creation(self):
        (self.c.PROC/'123').mkdir()
        with self.assertRaises(Refused):v.provision(self.c,self.state)
        self.assertEqual(self.generated,[])
        self.assertEqual(self.persisted()['custody']['phase'],'preparing')

    def test_unowned_stage_and_nonregular_key_paths_are_refused(self):
        stage=self.c.ROOT/'signing-stage';stage.mkdir()
        with self.assertRaises(Refused):v.provision(self.c,self.state)
        self.assertEqual(self.commands,[])
        stage.rmdir();v.credential_intent(self.c,self.state)
        stage.mkdir();(stage/'consensus').mkdir();target=self.c.ROOT/'unrelated';target.write_text('{}')
        (stage/'consensus'/('UTC--2026-10-26T12-00-00Z--'+'3'*40)).symlink_to(target)
        with self.assertRaises(Refused):v.provision(self.c,self.state)
        self.assertEqual(self.generated,[])

    def test_extra_wallet_identity_and_duplicate_consensus_are_refused(self):
        original=self.geth
        def geth(c,state,password,args):
            if args[:3]==['bls','account','list']:
                return b'[BLS public key] 0x'+b'4'*96+b'\n[BLS public key] 0x'+b'6'*96+b'\n'
            return original(c,state,password,args)
        with patch.object(v,'geth',side_effect=geth):
            with self.assertRaises(Refused):v.provision(self.c,self.state)
        self.assertEqual(self.persisted()['custody']['phase'],'preparing')
        self.state['operator']='0x'+'3'*40
        with self.assertRaises(Refused):v.provision(self.c,self.state)

    def backup(self):
        v.provision(self.c,self.state);(self.c.ROOT/'data').mkdir()
        v.journal(self.c,self.state,initialize=True)
        raw=v.export_backup(self.c,self.state)
        v.confirm_backup(self.c,self.state,hashlib.sha256(raw.encode()).hexdigest())
        return raw

    def lose_key(self):
        path=next((self.c.ROOT/'signer/consensus').iterdir());path.parent.chmod(0o750)
        path.unlink();path.parent.chmod(0o550)

    def test_same_owner_recovery_retains_native_history_and_original_keys(self):
        raw=self.backup();before=dict(self.state['custody']['files']);self.lose_key()
        v.restore(self.c,self.state,raw)
        self.assertEqual(self.state['custody']['files'],before)
        self.assertEqual(self.generated,['consensus','vote'])
        self.assertEqual(v.export_backup(self.c,self.state),raw)
        self.assertEqual(v.journal(self.c,self.state),0)
        self.assertEqual(len(list(self.c.ROOT.glob('signer-retained-*'))),1)

    def test_same_owner_backup_restores_original_peer_identity_without_rotating_it(self):
        raw=self.backup();path=self.c.ROOT/'identity/nodekey';before=path.read_bytes();path.unlink()
        v.restore(self.c,self.state,raw)
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual(self.generated,['consensus','vote'])
        self.assertEqual(v.export_backup(self.c,self.state),raw)

    def test_key_only_backup_never_recreates_lost_native_history(self):
        raw=self.backup();path=self.c.ROOT/'data/voteJournal'
        (path/'00000000000000000001').unlink();path.rmdir();before=len(self.commands)
        with self.assertRaises(Refused):v.restore(self.c,self.state,raw)
        self.assertEqual(len(self.commands),before)
        with self.assertRaises(Refused):v.journal(self.c,self.state,initialize=True)
        self.assertFalse(path.exists())

    def test_recovery_resumes_after_the_authoritative_publication_intent(self):
        raw=self.backup();self.lose_key();original=self.c.save;interrupted=[]
        def save(state):
            original(state)
            if state.get('custody_recovery',{}).get('phase')=='publishing' and not interrupted:
                interrupted.append(True);raise RuntimeError('publication interrupted')
        self.c.save=save
        with self.assertRaises(RuntimeError):v.restore(self.c,self.state,raw)
        self.c.save=original;state=self.persisted();v.restore(self.c,state,raw)
        self.assertNotIn('custody_recovery',state)
        self.assertEqual(v.export_backup(self.c,state),raw)
        self.assertEqual(self.generated,['consensus','vote'])

    def test_partial_recovery_file_is_retried_without_touching_existing_history(self):
        raw=self.backup();self.lose_key();replace=os.replace;interrupted=[]
        def replace_once(source,destination):
            if str(source).endswith('.recovery-new') and not interrupted:
                interrupted.append(True);raise RuntimeError('stage write interrupted')
            return replace(source,destination)
        with patch.object(v.os,'replace',side_effect=replace_once):
            with self.assertRaises(RuntimeError):v.restore(self.c,self.state,raw)
        state=self.persisted();v.restore(self.c,state,raw)
        self.assertEqual(v.export_backup(self.c,state),raw)
        self.assertEqual(v.journal(self.c,state),0)

    def test_wrong_backup_and_acknowledgement_do_not_replace_ownership(self):
        raw=self.backup();before=copy.deepcopy(self.state)
        with self.assertRaises(Refused):v.confirm_backup(self.c,self.state,'0'*64)
        changed=json.loads(raw);changed['owner']='another-owner'
        with self.assertRaises(Refused):v.restore(self.c,self.state,json.dumps(changed,sort_keys=True,separators=(',',':')))
        self.assertEqual(self.state,before)

    def test_native_journal_refuses_malformed_foreign_or_regressed_votes(self):
        self.backup();path=self.c.ROOT/'data/voteJournal/00000000000000000001'
        vote={'VoteAddress':[0x44]*48,'Signature':[1]*96,'Data':{'SourceNumber':1,'SourceHash':'0x'+'1'*64,'TargetNumber':2,'TargetHash':'0x'+'2'*64}}
        def encoded(value):return json.dumps({'index':'1','data':'+'+json.dumps(value)})+'\n'
        path.write_text(encoded(vote));self.assertEqual(v.journal(self.c,self.state),1)
        self.state['journal_checkpoint']=1;path.write_bytes(b'')
        with self.assertRaises(Refused):v.journal(self.c,self.state)
        self.state['journal_checkpoint']=0;path.write_text(encoded(vote)[:-1])
        with self.assertRaises(Refused):v.journal(self.c,self.state)
        vote['VoteAddress'][0]=0;path.write_text(encoded(vote))
        with self.assertRaises(Refused):v.journal(self.c,self.state)

    def native_segments(self,segments):
        path=self.c.ROOT/'data/voteJournal'
        for entry in path.iterdir():entry.unlink()
        vote={'VoteAddress':[0x44]*48,'Signature':[1]*96,'Data':{'SourceNumber':1,'SourceHash':'0x'+'1'*64,'TargetNumber':2,'TargetHash':'0x'+'2'*64}}
        for name,indices in segments:
            body=''.join(json.dumps({'index':str(index),'data':'+'+json.dumps(vote)})+'\n' for index in indices)
            (path/name).write_text(body)

    def test_native_recent_window_rejects_missing_prefix_middle_tail_and_overlap(self):
        self.backup();self.state['journal_checkpoint']=512
        bad=[
            [('00000000000000000512',[512])],
            [('00000000000000000001',range(1,257)),('00000000000000000258',range(258,513))],
            [('00000000000000000001',range(1,512))],
            [('00000000000000000001',range(1,401)),('00000000000000000400',range(400,513))],
        ]
        for segments in bad:
            with self.subTest(segments=[name for name,_ in segments]):
                self.native_segments(segments)
                with self.assertRaises(Refused):v.journal(self.c,self.state)
        self.native_segments([('00000000000000000001',range(1,257)),('00000000000000000257',range(257,513))])
        self.assertEqual(v.journal(self.c,self.state),512)

    def test_native_start_recovery_validates_effective_window_without_using_discarded_records(self):
        self.backup();self.state['journal_checkpoint']=512
        old=('00000000000000000001',range(1,514))
        self.native_segments([old,('00000000000000000002.START',range(2,514))])
        self.assertEqual(v.journal(self.c,self.state),513)
        self.native_segments([old,('00000000000000000500.START',range(500,514))])
        with self.assertRaises(Refused):v.journal(self.c,self.state)
        self.native_segments([old,('00000000000000000002.START',range(2,300)),('00000000000000000301',range(301,514))])
        with self.assertRaises(Refused):v.journal(self.c,self.state)
        self.native_segments([old,('00000000000000000002.START',range(2,514)),('00000000000000000003.START',range(3,515))])
        with self.assertRaises(Refused):v.journal(self.c,self.state)
        self.native_segments([('00000000000000000002',range(2,514))])
        self.assertEqual(v.journal(self.c,self.state),513)

    def test_validator_configuration_explicitly_clears_official_localhost_http(self):
        self.c.CONF.mkdir()
        raw=b'[Eth]\nNetworkId = 97\n[Node]\nHTTPHost = "localhost"\nHTTPPort = 8545\n[Node.P2P]\nListenAddr = ":30311"\n'
        (self.c.CONF/'config.toml').write_bytes(raw)
        self.c.release=lambda _:{'config_sha256':hashlib.sha256(raw).hexdigest()}
        expected=v.configuration(self.c,self.state)
        self.assertIn(b'HTTPHost = ""',expected);self.assertIn(b'WSHost = ""',expected)
        self.assertNotIn(b'localhost',expected);self.assertIn(b'ListenAddr = ":30311"',expected)
        v.write_configuration(self.c,self.state)
        self.assertEqual((self.c.CONF/'validator.toml').read_bytes(),expected)
        (self.c.CONF/'config.toml').write_bytes(raw+b'altered')
        with self.assertRaises(Refused):v.configuration(self.c,self.state)

    def test_runtime_has_no_http_ws_or_automatic_mining_and_only_password_descriptors(self):
        self.backup();material=self.c.ROOT/'descriptor-fixture';material.write_bytes(b'synthetic fixture')
        opened=[]
        def descriptor(_):
            fd=os.open(material,os.O_RDONLY);opened.append(fd);return fd
        with patch.object(v,'descriptor',side_effect=descriptor):
            try:
                args,descriptors=v.runtime_arguments(self.c,self.state,['geth','--http','--http.addr=127.0.0.1','--ws','--ws.api=eth', '--mine=false','--vote=false','--keystore=/empty','--cache=10000','--allow-insecure-unlock=false'])
                self.assertEqual(descriptors,opened)
                self.assertFalse(any(arg.startswith(('--http','--ws')) for arg in args))
                self.assertIn('--mine=false',args);self.assertIn('--vote=true',args)
                self.assertIn('--config='+str(self.c.CONF/'validator.toml'),args)
                self.assertIn('--allow-insecure-unlock=false',args)
                self.assertTrue(all('a'*64 not in arg for arg in args))
                self.assertEqual(sum(arg.startswith(('--password=/proc/self/fd/','--blspassword=/proc/self/fd/')) for arg in args),2)
            finally:
                for fd in opened:os.close(fd)

    def test_registration_view_decoding_distinguishes_absence_conflict_and_jail(self):
        self.backup()
        word=lambda n:n.to_bytes(32,'big')
        values={'059ddd22':bytes(12)+bytes.fromhex('3'*40),'6f8e2fa4':word(32)+word(48)+bytes.fromhex('4'*96)+bytes(16),'cbb04d9d':word(100)+word(0)+word(0)}
        calls=[]
        def rpc(method,params):
            calls.append((method,params));self.assertEqual(method,'eth_call')
            self.assertEqual(params[0]['to'],v.STAKE_HUB);self.assertEqual(params[1],'latest')
            return '0x'+values[params[0]['data'][2:10]].hex()
        self.c.rpc=rpc
        self.assertTrue(v.registration(self.c,self.state)['registered'])
        values['cbb04d9d']=word(100)+word(1)+word(500)
        self.assertTrue(v.registration(self.c,self.state)['jailed'])
        values['cbb04d9d']=word(100)+word(2)+word(500)
        with self.assertRaises(Refused):v.registration(self.c,self.state)
        values['cbb04d9d']=word(100)+word(0)+word(0);values['059ddd22']=bytes(12)+bytes.fromhex('6'*40)
        self.assertTrue(v.registration(self.c,self.state)['identity_conflict'])
        values['059ddd22']=bytes(32);values['6f8e2fa4']=word(32)+word(0);values['cbb04d9d']=bytes(96)
        absent=v.registration(self.c,self.state)
        self.assertFalse(absent['registered']);self.assertFalse(absent['identity_conflict'])



class Transport(unittest.TestCase):
    def test_changed_client_is_refused_before_opening_a_password_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=Path(directory)/'geth';binary.write_bytes(b'tampered')
            context=SimpleNamespace(require=require,binary=lambda _:binary,
                release=lambda _:{'binaries':{'amd64':{'size':8,'sha256':hashlib.sha256(b'original').hexdigest()}}},
                bootstrap=SimpleNamespace(digest=lambda p,_:hashlib.sha256(p.read_bytes()).hexdigest()))
            with patch.object(v,'descriptor') as descriptor,patch.object(v,'private_run') as run:
                with self.assertRaises(Refused):v.geth(context,{'platform':'amd64'},b'synthetic-password',['account','new'])
                descriptor.assert_not_called();run.assert_not_called()

    def test_native_key_commands_drop_uid_gid_and_supplementary_groups(self):
        c=SimpleNamespace(require=require,ROOT=Path('/synthetic-owned'))
        success=SimpleNamespace(returncode=0,stdout=b'public result',stderr=b'')
        with patch.object(v.subprocess,'run',return_value=success) as run:
            v.private_run(c,['reviewed-geth','account','new'],pass_fds=(9,),identity=(995,995))
            self.assertEqual(run.call_args.kwargs['user'],995);self.assertEqual(run.call_args.kwargs['group'],995)
            self.assertEqual(run.call_args.kwargs['cwd'],'/synthetic-owned/signing-stage')
            self.assertEqual(run.call_args.kwargs['extra_groups'],[]);self.assertEqual(run.call_args.kwargs['pass_fds'],(9,))
            with self.assertRaises(Refused):v.private_run(c,['reviewed-geth'],identity=(0,995))
            self.assertEqual(run.call_count,1)

    def test_private_process_errors_never_relay_stdout_stderr_or_input(self):
        c=SimpleNamespace(require=require)
        failure=SimpleNamespace(returncode=1,stdout=b'private output',stderr=b'private diagnostic')
        with patch.object(v.subprocess,'run',return_value=failure) as run:
            with self.assertRaises(Refused) as error:v.private_run(c,['reviewed-tool'],b'private input')
            self.assertNotIn('private',str(error.exception))
            self.assertEqual(run.call_args.kwargs['input'],b'private input')
            self.assertNotIn('private input',run.call_args.args[0])

    @unittest.skipUnless(hasattr(os,'memfd_create'),'Linux sealed descriptor runtime')
    def test_password_descriptor_cannot_be_changed_after_sealing(self):
        fd=v.descriptor(b'synthetic unit-test data')
        try:
            self.assertEqual(os.read(fd,64),b'synthetic unit-test data')
            with self.assertRaises(OSError):os.write(fd,b'replacement')
        finally:os.close(fd)

if __name__=='__main__':unittest.main()
