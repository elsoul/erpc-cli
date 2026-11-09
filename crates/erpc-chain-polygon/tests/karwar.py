# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Karwar fixed catalog and actual original pending-update recovery boundaries."""
import copy
import importlib.util
import hashlib
import shutil
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
import state,install,validator_activation


def fixture(name):
    spec=importlib.util.spec_from_file_location('karwar_fixture_'+name,ROOT/'tests'/(name+'.py'))
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class Catalog(unittest.TestCase):
    def test_both_networks_keep_bor_genesis_config_and_both_signed_architectures(self):
        for network in ('mainnet','amoy'):
            old=json.loads((ROOT/'tests/fixtures'/('pre-karwar-'+network+'.json')).read_text())
            new=json.loads((ROOT/'networks'/(network+'.json')).read_text())
            self.assertEqual(old['releases']['bor'],new['releases']['bor'])
            for field in ('chain_id','parent','bor_genesis_hash','heimdall_chain_id','heimdall_genesis','genesis_generation','verifier'):
                self.assertEqual(old[field],new[field])
            for kind in ('heimdall_config','heimdall_app'):
                self.assertEqual(old['configs'][kind]['sha256'],new['configs'][kind]['sha256'])
                self.assertEqual(old['configs'][kind]['bytes'],new['configs'][kind]['bytes'])
            for architecture in ('x86_64','aarch64'):
                expected=state.contract(network,'i'*26,architecture,new['bor_genesis_hash'],new['heimdall_genesis']['sha256'])
                self.assertEqual(state.target(expected,old),old)
                with self.assertRaisesRegex(ValueError,'Karwar'):state.executable(expected,old)
                self.assertEqual(state.executable(expected,new),new)
                state.monotonic(expected,old,new)
                with self.assertRaises(ValueError):state.monotonic(expected,new,old)
                changed=copy.deepcopy(new);changed['releases']['heimdall']['commit']='a'*40
                with self.assertRaises(ValueError):state.executable(expected,changed)
                future=copy.deepcopy(new);before=future['releases']['heimdall']['tag']
                future['releases']['heimdall']=json.loads(json.dumps(future['releases']['heimdall']).replace(before,'v99.0.0'))
                with self.assertRaises(ValueError):state.monotonic(expected,future,new)
    def test_qualified_handoff_cancels_actual_old_prepare_without_start_or_data_changes(self):
        f=fixture('state').State('runTest')
        f.setUp();self.addCleanup(f.doCleanups)
        old=json.loads((ROOT/'tests/fixtures/pre-karwar-amoy.json').read_text())
        f.state.reserve_target(f.expected,f.profile,'b'*64)
        qualified=f.state.read('/etc/polygon/intent.json')
        self.assertTrue(qualified['intent'].startswith('qualified:'))
        namespace={};exec((ROOT/'tests/fixtures/pre-karwar-state.py').read_text(),namespace)
        with self.assertRaisesRegex(ValueError,'downgrade'):
            namespace['OldState'].prepare(f.state,f.expected,'c'*32,old,'d'*64)
        self.assertEqual(f.calls,[]);self.assertTrue(f.active)
        self.assertEqual(f.state.read('/etc/polygon/intent.json'),qualified)
    def test_failed_floor_publication_attempts_drain_but_validation_refusal_does_not(self):
        f=fixture('state').State('runTest');f.setUp();self.addCleanup(f.doCleanups)
        refused=Mock()
        bad=copy.deepcopy(f.profile);bad['releases']['heimdall']['commit']='a'*40
        with self.assertRaises(ValueError):f.state.reserve_target(f.expected,bad,'b'*64,failure=refused)
        refused.assert_not_called()
        with patch.object(f.state,'write',side_effect=OSError('inert failed floor publication')):
            with self.assertRaises(OSError):f.state.reserve_target(f.expected,f.profile,'b'*64,failure=refused)
        refused.assert_called_once()
    def test_canonical_karwar_checkpoint_tuple_keeps_the_existing_bounded_native_abi(self):
        import checkpoint,signatures
        word=lambda value:value.to_bytes(32,'big')
        for recovery in (27,28):
            raw=checkpoint.SELECTOR+word(64)+word(128)+word(1)+b'x'+bytes(31)+word(1)+word(1)+word(signatures.ORDER//2)+word(recovery)
            self.assertEqual(checkpoint.calldata(raw),raw)
            with self.assertRaises(ValueError):checkpoint.calldata(raw+word(0))
    def test_actual_old_dispatch_refuses_new_start_protocol_without_any_native_start(self):
        namespace={};exec((ROOT/'tests/fixtures/pre-karwar-dispatch.py').read_text(),namespace)
        old=namespace['OldControl']();old.expected=lambda value:value;old.state=Mock();old.start=Mock()
        for action in ('start-v3','restart-v3'):
            with self.assertRaisesRegex(ValueError,'unsupported'):old.dispatch({'action':action,'contract':{'original':'fixture'}})
        old.start.assert_not_called()


@unittest.skipUnless(os.name=='posix','original controller uses POSIX publication')
class HandoffFailure(unittest.TestCase):
    def test_actual_failed_public_helper_publication_drains_and_retains_original_material(self):
        f=fixture('control').Lifecycle('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.activate()
        paths=[f.state.path('/etc/polygon/identity.json'),f.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json'),
               *f.state.path('/etc/credstore.encrypted/polygon/original').iterdir()]
        original={str(path):path.read_bytes() for path in paths}
        with patch.object(install,'publish_helpers',side_effect=OSError('inert immutable-source publication failure')):
            with self.assertRaises(OSError):f.control.dispatch(dict(f.request,action='publish-controller'))
        self.assertFalse(f.running);self.assertTrue(f.state.path('/etc/polygon/stopped').exists())
        self.assertEqual({str(path):path.read_bytes() for path in paths},original)
        with self.assertRaises(ValueError):f.control.dispatch(dict(f.request,action='activate'))


@unittest.skipUnless(os.name=='posix' and importlib.util.find_spec('jinja2') is not None,'actual unit rendering uses pinned Jinja on POSIX')
class Pending(unittest.TestCase):
    def setUp(self):
        self.f=fixture('validator_activation').Transition('runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.f.authorize();self.f.fixture.render();self.f.install.stop()
        self.state=self.f.state;self.controller=self.f.controller;self.expected=self.f.expected
        self.original=self.state.read('/etc/polygon/identity.json')
        self.history=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes()
        self.permit=self.state.read(validator_activation.PERMIT)
        self.mutate={};self.loaded=True;original_run=self.state.run
        def command(args,**kwargs):
            if args[:2]==['systemctl','show']:
                key=next((part.removeprefix('--property=') for part in args if part.startswith('--property=')),None);unit=args[-1]
                if (unit,key) in self.mutate:return subprocess.CompletedProcess(args,0,self.mutate[unit,key].encode(),b'')
                path=self.state.path('/etc/systemd/system/'+unit)
                if key=='LoadState':value='loaded' if self.loaded and path.exists() else 'not-found'
                elif key=='FragmentPath':value='/etc/systemd/system/'+unit
                elif key=='DropInPaths':value=''
                elif key=='DynamicUser':value='no'
                elif key=='SupplementaryGroups':value=''
                elif key=='MainPID':value='0'
                elif key and key.startswith('Exec'):
                    values=[shlex.split(line.split('=',1)[1].removeprefix('+')) for line in path.read_text().splitlines() if line.startswith(key+'=')]
                    value=' ; '.join('{ path='+parts[0]+' ; argv[]='+' '.join(parts)+' ; ignore_errors=no ; start_time=[n/a] ; }' for parts in values)
                else:value=next((line.split('=',1)[1] for line in path.read_text().splitlines() if line.startswith(str(key)+'=')),'')
                return subprocess.CompletedProcess(args,0,value.encode(),b'')
            return original_run(args,**kwargs)
        self.state.run=command
    def old_pending(self):
        import launch
        saved=self.state.read('/etc/polygon/installed.json')
        old=json.loads((ROOT/'tests/fixtures/pre-karwar-amoy.json').read_text())
        saved['profile']['releases']['heimdall']=old['releases']['heimdall']
        saved['profile_sha256']=state.profile_digest(saved['profile'])
        native=saved['binaries']['heimdall'];source=self.state.path(native['directory'])
        native['directory']=native['directory'].replace('v0.13.2','v0.12.2')
        shutil.copytree(source,self.state.path(native['directory']))
        public=state.canonical(launch.metadata(self.expected,saved['profile'],saved['binaries']))
        self.state.path('/etc/polygon/launch.json').write_bytes(public)
        saved['files']['/etc/polygon/launch.json']=hashlib.sha256(public).hexdigest()
        self.state.write('/etc/polygon/installed.json',saved)
        pending=self.state.read('/etc/polygon/intent.json');pending['profile']=saved['profile']
        self.state.write('/etc/polygon/intent.json',pending)
        self.assertEqual(install.installed(self.state,self.expected,'status',require_units=False)['profile']['releases']['heimdall']['tag'],'v0.12.2')
    def authorize(self):return self.f.authorize()
    def retained(self):
        self.assertEqual(self.state.read('/etc/polygon/identity.json'),self.original)
        self.assertEqual(self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes(),self.history)
    def test_actual_unsealed_pair_with_original_permit_can_retry_and_then_prepare(self):
        self.old_pending()
        self.assertNotIn('units',install.installed(self.state,self.expected,'status',require_units=False))
        self.assertTrue(self.authorize()['active_target_authorized']);self.retained()
        saved=self.state.read(validator_activation.PERMIT)
        self.assertEqual(saved['observer_admission'],self.permit['observer_admission'])
        self.assertEqual(saved['identity_sha256'],self.permit['identity_sha256'])
        self.state.prepare(self.expected,self.f.request['intent'],self.f.target,self.controller.helpers)
        validator_activation.require_permit(self.state,self.expected,self.f.request['intent'],self.f.target,self.controller.helpers)
        self.retained();self.assertFalse(self.f.fixture.fixture.running)
    def test_previous_activated_helper_and_new_pending_source_can_coexist_but_unknown_source_cannot(self):
        old=self.state.root/'previous-source';shutil.copytree(self.controller.source,old)
        with (old/'control.py').open('ab') as output:output.write(b'\n# inert previous immutable revision\n')
        previous=install.publish_helpers(self.state,old)
        self.state.write('/etc/polygon/activation.json',{'contract':self.expected,'helpers':previous,'profile':'d'*64,'intent':'e'*32,'firewall':{'run':'r-original-fixture','bundle':'f'*64}})
        current=self.controller.helpers;token=self.f.fixture.token
        self.controller.helpers=previous;self.f.fixture.token=dict(token,helpers=previous)
        try:self.f.fixture.render()
        finally:self.controller.helpers=current;self.f.fixture.token=token
        install.publish_helpers(self.state,self.controller.source)
        self.assertTrue(self.authorize()['active_target_authorized']);self.retained()
        saved=self.state.path('/etc/polygon/activation.json').read_bytes();self.state.path('/etc/polygon/activation.json').unlink()
        with self.assertRaises(ValueError):self.authorize()
        self.state.path('/etc/polygon/activation.json').write_bytes(saved)
        changed=self.state.path('/usr/local/lib/erpc/polygon/releases/'+previous+'/control.py')
        with changed.open('ab') as output:output.write(b'\n# unrecorded change\n')
        with self.assertRaises(ValueError):self.authorize()
        self.retained()
    def test_missing_unloaded_units_are_recoverable_but_cached_missing_files_are_not(self):
        target=self.state.path('/etc/systemd/system/polygon-bor.service');raw=target.read_bytes();target.unlink()
        self.mutate['polygon-bor.service','LoadState']='loaded'
        with self.assertRaises(ValueError):self.authorize()
        self.mutate.clear();self.loaded=False
        self.assertTrue(self.authorize()['active_target_authorized']);self.retained();target.write_bytes(raw)
    def test_existing_unit_hash_mismatch_never_enters_missing_seal_recovery(self):
        receipt=self.state.read('/etc/polygon/installed.json');receipt['units']={name:'0'*64 for name in install.unit_names(self.expected)}
        self.state.write('/etc/polygon/installed.json',receipt)
        with patch.object(install,'pending_units',side_effect=AssertionError('must not bypass an existing unit seal')):
            with self.assertRaises(ValueError):self.authorize()
        self.retained()
    def test_unknown_loaded_hook_executable_or_recipient_is_not_repaired(self):
        unit='polygon-bor.service'
        for key,value in [('ExecStartPost','{ path=/bin/false ; argv[]=/bin/false ; ignore_errors=no ; start_time=[n/a] ; }'),
                          ('ExecStart','{ path=/bin/false ; argv[]=/usr/bin/python3 -I /unrelated ; ignore_errors=no ; start_time=[n/a] ; }'),
                          ('User','0'),('DropInPaths','/etc/systemd/system/polygon-bor.service.d/99-unknown.conf')]:
            self.mutate[unit,key]=value
            with self.assertRaises(ValueError):self.authorize()
            self.mutate.clear();self.retained()
        self.assertTrue(self.authorize()['active_target_authorized'])
    def test_qualification_does_not_turn_a_first_active_request_into_active_history(self):
        permit=self.state.path(validator_activation.PERMIT).read_bytes()
        self.state.reserve_target(self.expected,self.f.target,self.controller.helpers)
        pending=self.state.read('/etc/polygon/intent.json')
        self.assertEqual(pending['profile']['validator']['phase'],'observing')
        self.assertTrue(pending['intent'].startswith('qualified:'))
        self.assertEqual(self.state.path(validator_activation.PERMIT).read_bytes(),permit)
        self.retained()
    def test_partial_public_configuration_with_intact_units_is_rebuilt_only_while_fenced(self):
        self.f.fixture.render();self.controller.dispatch(dict(self.f.fixture.request,action='seal'))
        original=self.state.read('/etc/polygon/installed.json')
        self.state.path('/etc/polygon/bor.toml').write_bytes(b'inert interrupted public configuration')
        self.assertTrue(self.authorize()['active_target_authorized']);self.retained()
        self.assertEqual(self.state.read('/etc/polygon/installed.json')['units'],original['units'])
        self.state.path('/etc/polygon/preparing').unlink()
        with self.assertRaises(ValueError):self.authorize()
        self.retained()
    def test_loaded_executable_cannot_spoof_the_known_argv(self):
        unit='polygon-bor.service'
        good=self.state.command('systemctl','show','--property=ExecStart','--value',unit).stdout.decode()
        self.mutate[unit,'ExecStart']=good.replace('path=/usr/bin/python3','path=/bin/false',1)
        with self.assertRaises(ValueError):self.authorize()
        self.retained()
    def test_absent_retained_permit_never_promotes_an_unsealed_first_signer(self):
        self.state.path(validator_activation.PERMIT).unlink()
        with self.assertRaises(ValueError):self.authorize()
        self.retained();self.assertFalse(self.state.path(validator_activation.PERMIT).exists())
    def test_unknown_file_hook_scope_source_and_history_cannot_be_adopted(self):
        path=self.state.path('/etc/systemd/system/polygon-bor.service');raw=path.read_bytes()
        path.write_bytes(raw+b'\nExecStopPost=/bin/false\n')
        with self.assertRaises(ValueError):self.authorize()
        self.assertTrue(path.read_bytes().endswith(b'ExecStopPost=/bin/false\n'));path.write_bytes(raw)
        history=self.state.path('/etc/polygon/history.json');before=history.read_bytes();history.unlink()
        with self.assertRaises((ValueError,FileNotFoundError)):self.authorize()
        history.write_bytes(before)
        original=self.state.path('/etc/polygon/identity.json');before=original.read_bytes();original.write_text('{}')
        with self.assertRaises((ValueError,KeyError)):self.authorize()
        original.write_bytes(before);self.assertTrue(self.authorize()['active_target_authorized']);self.retained()


@unittest.skipUnless(os.name=='posix' and importlib.util.find_spec('tomllib') is not None,'real native installer uses managed Python3.12 TOML')
class RpcUpdate(unittest.TestCase):
    def test_actual_native_update_retains_existing_db_private_state_keys_and_original_authority(self):
        f=fixture('installer').Installer('runTest');f.setUp();self.addCleanup(f.doCleanups)
        f.prepare()
        saved=f.state.read('/etc/polygon/installed.json');old=json.loads((ROOT/'tests/fixtures/pre-karwar-amoy.json').read_text())
        saved['profile']['releases']['heimdall']=old['releases']['heimdall']
        saved['profile_sha256']=state.profile_digest(saved['profile'])
        f.state.write('/etc/polygon/installed.json',saved)
        f.state.write('/etc/polygon/intent.json',{'profile':saved['profile'],'intent':'0'*32,'helpers':f.control.helpers})
        history=f.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json')
        history.write_bytes(b'{"height":"50019999","round":2,"step":3}')
        for component in ('heimdall','bor'):
            path=f.state.path('/var/lib/polygon/'+component+'/data/original-db');path.write_bytes(b'inert original database sentinel')
        paths=[f.state.path('/etc/polygon/contract.json'),f.state.path('/etc/polygon/storage.json'),f.state.path('/etc/polygon/identity.json'),history,
               *f.state.path('/etc/credstore.encrypted/polygon/original').iterdir(),
               f.state.path('/var/lib/polygon/heimdall/data/original-db'),f.state.path('/var/lib/polygon/bor/data/original-db')]
        before={str(path):path.read_bytes() for path in paths}
        f.prepare(dict(f.request,intent='b'*32))
        self.assertEqual({str(path):path.read_bytes() for path in paths},before)
        self.assertEqual(f.state.read('/etc/polygon/installed.json')['profile']['releases']['heimdall']['tag'],'v0.13.2')
        self.assertEqual(sum(call[0].endswith('/heimdalld') and call[1]=='init' for call in f.calls),1)
        count=len(f.calls)
        with self.assertRaises(ValueError):f.control.dispatch(dict(f.request,intent='c'*32,profile=saved['profile']))
        self.assertEqual(len(f.calls),count);self.assertEqual({str(path):path.read_bytes() for path in paths},before)


if __name__=='__main__':unittest.main()
