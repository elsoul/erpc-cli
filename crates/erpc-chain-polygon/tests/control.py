# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real lifecycle paths against inert installed files and mocked systemd/nft."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))


class FixtureAccounts:
    def preflight(self,*args):return None
    def provision(self,*args):return None
    def verify(self,*args):return {name:{'uid':uid,'gid':uid} for name,uid in [('bor',1001),('heimdall',1002),('parent',1003)]}
    def retained_uids(self,components=None):return set()


@unittest.skipUnless(os.name=='posix','managed-host lifecycle uses POSIX locks')
class Lifecycle(unittest.TestCase):
    def setUp(self):
        import control,install,state,identity
        self.module,self.install,self.identity=control,install,identity
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.source=self.root/'source';self.source.mkdir()
        for name in install.SCRIPTS:
            source=(ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py') if name=='upstreams.py' else ROOT/'templates/scripts'/name
            shutil.copyfile(source,self.source/name)
        self.calls=[];self.running=set();self.enabled=set();self.unit_recipients={};self.condition_result={};self.policy=False;self.confirmed=None;self.free=2_000_000_000_000
        self.profile=json.loads((ROOT/'networks/amoy.json').read_text())
        self.genesis=b'inert immutable genesis fixture'
        self.profile['heimdall_genesis']['sha256']=hashlib.sha256(self.genesis).hexdigest()
        self.profile['heimdall_genesis']['bytes']=len(self.genesis)
        self.contract=state.contract('amoy','i'*26,'x86_64',self.profile['bor_genesis_hash'],self.profile['heimdall_genesis']['sha256'])
        self.state=state.State(self.root,self.command,firewall=lambda:self,usage=lambda:(self.free,0),owner=os.getuid(),account=FixtureAccounts(),proof=type('FixtureAuthority',(),{'initial':lambda self:None,'can_start':lambda self,*args:None,'unoccupied':lambda self:None,'quiescent':lambda self:None,'startable':lambda self,*args:None,'listener':lambda self,*args:('fixture',)})())
        import volume_fixture
        volume_fixture.attach(self,self.state)
        for directory in ('etc','opt/erpc','var/lib/polygon','usr/local/lib/erpc/polygon/releases','etc/credstore.encrypted/polygon'):
            (self.root/directory).mkdir(parents=True,exist_ok=True)
        self.control=control.Control(self.state,self.source,verify=lambda config,network:None)
        self.request={'contract':self.contract,'profile':self.profile,'helpers':self.control.helpers,'intent':'a'*32,'advertise':'192.0.2.1'}
        # Reserve before any credential/data artifacts exist.
        (self.root/'etc/credstore.encrypted/polygon').rmdir()
        self.control.dispatch(dict(self.request,action='reserve'))
        (self.root/'etc/credstore.encrypted/polygon').mkdir()
        self.state.prepare(self.contract,self.request['intent'],self.profile,self.control.helpers)
        self.install_fixture()
        self.control.dispatch(dict(self.request,action='seal'))

    def command(self,args,**kwargs):
        self.calls.append(args)
        output=b''
        if args[:2]==['systemctl','show']:
            output=(b'123' if args[-1] in self.running else b'0') if '--property=MainPID' in args else b'loaded'
            if '--property=User' in args:output=str(self.unit_recipients[args[-1]][0]).encode()
            if '--property=Group' in args:output=str(self.unit_recipients[args[-1]][1]).encode()
            if '--property=DynamicUser' in args:output=b'no'
            if '--property=SupplementaryGroups' in args:output=b''
            if '--property=Result' in args:output=self.condition_result.get(args[-1],('success',''))[0].encode()
            if '--property=ExecCondition' in args:output=self.condition_result.get(args[-1],('success',''))[1].encode()
        elif args[:2]==['systemctl','is-active']:output=b'active' if args[-1] in self.running else b'inactive'
        elif args[:2]==['systemctl','stop'] or args[:3]==['systemctl','disable','--now']:
            self.running.difference_update(arg for arg in args if arg.endswith(('.service','.timer')))
            if args[1]=='disable':self.enabled.difference_update(arg for arg in args if arg.endswith(('.service','.timer')))
        elif args[:2]==['systemctl','start']:self.running.add(args[-1])
        elif args[:2]==['systemctl','enable']:self.enabled.add(args[-1])
        elif args[:2]==['systemd-creds','encrypt']:
            Path(args[-1]).write_bytes(b'inert encrypted '+kwargs['input'])
        return subprocess.CompletedProcess(args,0,output,b'')

    def dispatch(self,action,*token):
        # The actual shared firewall failure/rollback paths run in erpc-ops tests.
        self.calls.append(['firewall',action,*token])
        if action=='require-confirmed' and (not self.policy or token!=self.confirmed):raise ValueError('unconfirmed or superseded fixture policy')
        if action=='guard' and not self.policy:raise ValueError('no confirmed fixture policy')
        if action=='teardown':
            if self.running:raise ValueError('unsafe filter removal')
            self.policy=False
    def confirm(self,run,digest):
        self.confirmed=(run,digest);self.policy=True

    def file(self,path,data):
        file=self.state.path(path);file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(data);file.chmod(0o600)
        return file

    def install_fixture(self):
        from state import profile_digest
        helpers=self.install.publish_helpers(self.state,self.source)
        binaries={}
        for name,release in self.profile['releases'].items():
            directory='/opt/polygon/releases/'+name+'-'+release['tag']+'-x86_64'
            binary=self.file(directory+'/usr/bin/'+('bor' if name=='bor' else 'heimdalld'),('inert '+name+' binary').encode())
            binaries[name]={'directory':directory,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
        launch={'network':'amoy','binaries':{name:value['directory']+'/usr/bin/'+('bor' if name=='bor' else 'heimdalld') for name,value in binaries.items()}}
        files={}
        for path,data in [('/etc/polygon/launch.json',json.dumps(launch).encode()),('/etc/polygon/bor.toml',b'fixture="bor"'),
            ('/var/lib/polygon/genesis/amoy.json',self.genesis),
            *[('/var/lib/polygon/heimdall/config/'+name,b'fixture="heimdall"') for name in ('config.toml','app.toml','client.toml')]]:
            files[path]=hashlib.sha256(self.file(path,data).read_bytes()).hexdigest()
        for name in self.install.SCRIPTS:
            path='/usr/local/lib/erpc/polygon/releases/'+helpers+'/'+name
            files[path]=hashlib.sha256(self.state.path(path).read_bytes()).hexdigest()
        self.state.write('/etc/polygon/installed.json',{'contract':self.contract,'profile':self.profile,
            'profile_sha256':profile_digest(self.profile),'binaries':binaries,'files':files,'helpers':helpers})
        for component,unit in [('bor','polygon-bor'),('heimdall','polygon-heimdall'),('parent','polygon-l1-proxy')]:
            original=self.state.accounts.verify(self.contract)[component]
            uid,gid=str(original['uid']),str(original['gid'])
            self.unit_recipients[unit+'.service']=(original['uid'],original['gid'])
            root='/usr/local/lib/erpc/polygon/releases/'+helpers+'/'
            executable='parent.py sepolia' if component=='parent' else 'launch.py '+component
            text='[Service]\nUser='+uid+'\nGroup='+gid+'\nSupplementaryGroups=\nDynamicUser=no\nLimitCORE=0\nExecStart=/usr/bin/python3 -I '+root+executable+'\n'
            text+='ExecCondition=+'+self.install.service_condition(self.source/'control.py',root+'control.py')+' credential-condition '+component+" '"+json.dumps(self.contract)+"'\n"
            text+='ExecStartPre=+'+self.install.service_guard(self.source/'control.py',root+'control.py')+' runtime '+component+" '"+json.dumps(self.contract)+"'\n"
            self.file('/etc/systemd/system/'+unit+'.service',text.encode())
        original={'contract':self.contract,'ciphertexts':{},'bor_node_id':'inert-node-public-id'}
        for name in self.identity.FILES:
            value=('inert ciphertext '+name).encode()
            self.file('/etc/credstore.encrypted/polygon/original/'+name,value)
            original['ciphertexts'][name]=hashlib.sha256(value).hexdigest()
        initial=b'{"height":"0","round":0,"step":0}'
        self.file('/etc/credstore.encrypted/polygon/original/initial-state.json',initial)
        self.file('/var/lib/polygon/heimdall/data/priv_validator_state.json',b'preserved mutable history fixture')
        original['initial_state_sha256']=hashlib.sha256(initial).hexdigest()
        self.state.write('/etc/credstore.encrypted/polygon/original/receipt.json',original)
        self.state.write('/etc/polygon/identity.json',original)
        initialized={'contract':self.contract,'identity_sha256':hashlib.sha256(self.module.canonical(original)).hexdigest(),'state':'initialized'}
        self.state.write('/etc/credstore.encrypted/polygon/original/home-state.json',initialized)
        self.state.write('/etc/polygon/history.json',initialized)
        self.state.write('/var/lib/polygon/heimdall/erpc-home.json',self.contract)
        cipher=b'inert parent ciphertext'
        self.file('/etc/credstore.encrypted/polygon/execution.json',cipher)
        self.state.write('/etc/polygon/upstream.json',{'contract':self.contract,'parent':'sepolia','cipher_sha256':hashlib.sha256(cipher).hexdigest()})

    def activate(self):
        token={'run':'r-20261026t120000-abcdef','bundle':'b'*64}
        self.confirm(token['run'],token['bundle'])
        self.control.dispatch(dict(self.request,action='activate',firewall=token))

    def test_failed_preparation_cannot_reboot_older_enabled_credential_units(self):
        from unittest.mock import patch
        self.activate();self.assertEqual(len(self.enabled),3)
        def unavailable(*args,**kwargs):
            self.assertFalse(self.enabled);self.assertFalse(self.running)
            self.assertTrue(self.state.path('/etc/polygon/preparing').exists())
            raise ValueError('inert interrupted artifact acquisition')
        with patch.object(self.install,'prepare',side_effect=unavailable):
            with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='prepare',intent='c'*32))
        # An inert boot model starts only enabled managed units; none can load
        # their previous credentials before the replacement definitions seal.
        self.running.update(self.enabled);self.assertFalse(self.running)
        for component in self.module.host.UNITS:
            with self.assertRaises(ValueError):self.control.credential_condition(self.contract,component)

    def test_credential_condition_ignores_sync_prerequisites_but_enforces_numeric_recipients(self):
        from unittest.mock import patch
        self.activate()
        with patch.object(self.module.observe,'parent',side_effect=ValueError('inert delayed parent')):
            self.control.credential_condition(self.contract,'heimdall')
            with self.assertRaises(ValueError):self.control.runtime(self.contract,'heimdall')
        for component,unit in self.module.host.UNITS.items():
            original=self.unit_recipients[unit]
            for wrong in (('polygon-bor',original[1]),(2001,original[1]),(original[0],2001)):
                self.unit_recipients[unit]=wrong
                with self.assertRaises(ValueError):self.control.credential_condition(self.contract,component)
            self.unit_recipients[unit]=original
        self.control.credential_condition(self.contract,'bor')

    def test_successful_systemctl_exit_does_not_hide_skipped_or_failed_condition(self):
        self.activate()
        for result,condition in [('exec-condition','{ code=exited ; status=1 }'),('exit-code','{ code=exited ; status=255 }')]:
            self.condition_result['polygon-bor.service']=(result,condition)
            with self.assertRaisesRegex(ValueError,'failed or skipped'):
                self.control.dispatch(dict(self.request,action='start'))
        self.condition_result.clear()
        # A full prerequisite guard can keep retrying without falsely calling
        # the asynchronous request a running/healthy service.
        self.condition_result['polygon-bor.service']=('exit-code','{ code=exited ; status=0 }')
        result=self.control.dispatch(dict(self.request,action='start'))
        self.assertTrue(result['startup_requested']);self.assertNotIn('started',result)
        self.assertIn('pending',result['service_readiness'])

    def test_foreign_same_network_inventory_cannot_mutate_or_read_credentials(self):
        foreign=dict(self.contract,owner='j'*26)
        for action in ('reserve','prepare','credential','activate','stop','destroy','backup','restore','start','restart'):
            before=len(self.calls)
            with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,contract=foreign,action=action))
            self.assertEqual(len(self.calls),before)

    def test_activation_requires_current_confirmation_and_preparing_blocks_reboot(self):
        with self.assertRaises(ValueError):self.control.runtime(self.contract,'parent')
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='activate',firewall={'run':'r-old','bundle':'c'*64}))
        self.assertFalse(self.running)
        self.activate()
        self.assertEqual(len(self.running),3)
        self.control.runtime(self.contract,'parent')
        self.policy=False
        with self.assertRaises(ValueError):self.control.runtime(self.contract,'parent')

    def test_delayed_parent_and_heimdall_readiness_allow_guarded_retry_without_new_activation(self):
        from unittest.mock import patch
        self.activate()
        with patch.object(self.module.observe,'parent',side_effect=ValueError('inert unavailable parent')):
            with self.assertRaises(ValueError):self.control.runtime(self.contract,'heimdall')
        with patch.object(self.module.observe,'parent',return_value={'ready':True}):
            self.control.runtime(self.contract,'heimdall')
        with patch.object(self.module.observe,'heimdall',return_value={'ready':False}):
            with self.assertRaises(ValueError):self.control.runtime(self.contract,'bor')
        with patch.object(self.module.observe,'heimdall',return_value={'ready':True}):
            self.control.runtime(self.contract,'bor')
        # Readiness retry never grants new ownership or alters a consensus identity.
        self.assertEqual(self.state.read('/etc/polygon/activation.json')['intent'],self.request['intent'])

    def test_stop_invalidates_old_activation_and_retirement_drains_before_filter_removal(self):
        self.activate()
        self.control.dispatch(dict(self.request,action='stop'))
        self.assertFalse(self.running)
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='activate',firewall={'run':self.confirmed[0],'bundle':self.confirmed[1]}))
        self.control.dispatch(dict(self.request,action='start'))
        self.assertEqual(len(self.running),3)
        self.control.dispatch(dict(self.request,action='destroy'))
        self.assertFalse(self.running);self.assertFalse(self.policy)
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='start'))

    def failed_cancellation(self,action='stop'):
        from unittest.mock import patch
        original=self.state.write
        def write(path,value):
            if path=='/etc/polygon/intent.json':raise OSError('inert failed intent publication')
            return original(path,value)
        with patch.object(self.state,'write',side_effect=write):
            with self.assertRaises(OSError):self.control.dispatch(dict(self.request,action=action))
        self.assertEqual(self.state.read('/etc/polygon/intent.json')['intent'],self.request['intent'])
        self.assertTrue(self.state.path('/etc/polygon/stopped').exists())
        self.assertFalse(self.running)

    def assert_cancelled_phases(self):
        before=len(self.calls)
        for action in ('phase','credential','seal','confirm','activate'):
            with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action=action,
                firewall={'run':self.confirmed[0],'bundle':self.confirmed[1]}))
        self.assertEqual(len(self.calls),before)

    def test_interrupted_stop_keeps_old_intent_but_refuses_every_delayed_phase(self):
        self.confirm('r-20261026t120000-abcdef','b'*64)
        original=self.state.path('/etc/polygon/identity.json').read_bytes()
        history=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes()
        self.failed_cancellation()
        self.assert_cancelled_phases()
        self.assertEqual(self.state.path('/etc/polygon/identity.json').read_bytes(),original)
        self.assertEqual(self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes(),history)
        # Re-opening the real controller models a subsequent SSH/reboot read.
        self.control=self.module.Control(self.state,self.source,verify=lambda config,network:None)
        self.assert_cancelled_phases()

    def test_new_preparation_durably_supersedes_failed_stop_before_clearing_fence(self):
        from unittest.mock import patch
        self.confirm('r-20261026t120000-abcdef','b'*64)
        self.failed_cancellation()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='prepare'))
        next_request=dict(self.request,intent='d'*32)
        original_unlink=self.module.host.unlink
        events=[]
        def unlink(path,stop):
            if path.name=='stopped':
                self.assertEqual(self.state.read('/etc/polygon/intent.json')['intent'],next_request['intent'])
                self.assertTrue(self.state.path('/etc/polygon/preparing').exists())
                self.assertFalse(self.running);events.append('new durable preparation')
            return original_unlink(path,stop)
        # Stub only native acquisition; use actual dispatcher/preparation,
        # ownership, capacity, durable publication and drain implementation.
        result={'helpers':self.control.helpers,'profile_sha256':self.module.profile_digest(self.profile)}
        with patch.object(self.install,'prepare',return_value=result),patch.object(self.module.host,'unlink',side_effect=unlink):
            self.control.dispatch(dict(next_request,action='prepare'))
        self.assertEqual(events,['new durable preparation'])
        self.assertFalse(self.state.path('/etc/polygon/stopped').exists())
        self.assert_cancelled_phases()
        self.control.dispatch(dict(next_request,action='phase'))
        self.control.dispatch(dict(next_request,action='activate',firewall={'run':self.confirmed[0],'bundle':self.confirmed[1]}))
        self.assertEqual(len(self.running),3)

    def test_manual_start_cannot_revive_cancelled_activation_after_failed_stop(self):
        self.activate();self.failed_cancellation()
        self.control.dispatch(dict(self.request,action='start'))
        self.assertEqual(len(self.running),3)
        self.assertFalse(self.state.path('/etc/polygon/stopped').exists())
        self.assert_cancelled_phases()

    def test_prepare_and_manual_start_publication_failures_keep_cancellation_authoritative(self):
        from unittest.mock import patch
        self.activate();self.failed_cancellation()
        for action in ('prepare','start','restart'):
            original=self.state.write
            def write(path,value):
                if path=='/etc/polygon/intent.json':raise OSError('inert replacement intent failure')
                return original(path,value)
            with patch.object(self.state,'write',side_effect=write):
                with self.assertRaises(OSError):self.control.dispatch(dict(self.request,action=action,intent='d'*32))
            self.assertFalse(self.running)
            self.assertTrue(self.state.path('/etc/polygon/stopped').exists())
            self.assert_cancelled_phases()

    def test_prepare_fence_failure_does_not_clear_prior_cancellation(self):
        from unittest.mock import patch
        self.activate();self.failed_cancellation()
        with patch.object(self.module.host,'fence',side_effect=OSError('inert preparation fence failure')):
            with self.assertRaises(OSError):self.control.dispatch(dict(self.request,action='prepare',intent='d'*32))
        self.assertEqual(self.state.read('/etc/polygon/intent.json')['intent'],'d'*32)
        self.assertTrue(self.state.path('/etc/polygon/stopped').exists())
        self.assertFalse(self.running)
        self.assert_cancelled_phases()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='phase',intent='d'*32))

    def test_prepare_stop_fence_removal_sync_failure_reestablishes_cancellation(self):
        from unittest.mock import patch
        self.activate();self.failed_cancellation()
        stopped=self.state.path('/etc/polygon/stopped')
        sync=self.module.host.sync_directory
        failed=[]
        def once(path):
            if not stopped.exists() and not failed:
                failed.append(True);raise OSError('inert cancellation directory sync failure')
            return sync(path)
        with patch.object(self.module.host,'sync_directory',side_effect=once):
            with self.assertRaises(OSError):self.control.dispatch(dict(self.request,action='prepare',intent='d'*32))
        self.assertEqual(failed,[True]);self.assertTrue(stopped.exists())
        self.assertTrue(self.state.path('/etc/polygon/preparing').exists())
        self.assertFalse(self.running);self.assert_cancelled_phases()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='phase',intent='d'*32))

    def test_first_stop_fence_failure_still_invalidates_and_disables_without_teardown(self):
        from unittest.mock import patch
        self.activate();self.calls.clear()
        # Fail before creating any stop fence, not merely at the later fsync.
        with patch.object(self.module.host,'fence',side_effect=OSError('inert fence creation failure')):
            with self.assertRaises(OSError):self.control.dispatch(dict(self.request,action='destroy'))
        self.assertFalse(self.running);self.assertTrue(self.policy)
        self.assertTrue(any(args[:3]==['systemctl','disable','--now'] for args in self.calls))
        self.assertNotEqual(self.state.read('/etc/polygon/intent.json')['intent'],self.request['intent'])
        self.assert_cancelled_phases()

    def test_firewall_boot_composes_actual_common_load_with_one_lock_owner(self):
        import fcntl
        from unittest.mock import patch
        common=ROOT.parent/'erpc-ops/templates/rpc-firewall.py'
        installed=self.file('/usr/local/lib/erpc/rpc-firewall.py',common.read_bytes())
        # Import the real protected installed helper via State.firewall, not a
        # factory that conceals the common controller's independent flock.
        self.state.firewall_factory=None
        calls=[];live=[False]
        def run(args,**kwargs):
            calls.append(args)
            if args[:3]==['nft','-j','list']:
                if not live[0]:raise subprocess.CalledProcessError(1,args)
                return subprocess.CompletedProcess(args,0,b'{"nftables":[]}',b'')
            if args[:2]==['nft','-f']:
                descriptor=os.open(self.state.path('/opt/erpc'),os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(descriptor)
                live[0]=True
                return subprocess.CompletedProcess(args,0,b'',b'')
            raise AssertionError('boot must not mutate accounts, services, keys or data')
        self.state.run=run
        policy=b'inert confirmed boot policy'
        self.file('/etc/erpc/polygon/firewall.nft',policy)
        self.file('/etc/erpc/polygon/confirmed.json',json.dumps({'contract':'polygon',
            'file':hashlib.sha256(policy).hexdigest(),'operation':'r-fixture','bundle':'a'*64,
            'live':hashlib.sha256(json.dumps({'nftables':[]},sort_keys=True).encode()).hexdigest()}).encode())
        def boot(expected=None):
            with patch.object(self.module,'Control',return_value=self.control),patch.object(self.module.resource,'setrlimit'), \
                    patch.object(self.module.sys,'argv',['control.py','firewall',json.dumps(expected or self.contract)]):
                self.module.main()
        boot()  # Cold boot restores the confirmed policy under the common lock.
        self.assertTrue(live[0]);self.assertEqual(sum(call[:2]==['nft','-f'] for call in calls),1)
        boot()  # A matching live policy needs no write or second acquisition.
        self.assertEqual(sum(call[:2]==['nft','-f'] for call in calls),1)
        live[0]=False;calls.clear()
        with self.state.locked():
            with self.assertRaises(BlockingIOError):boot()
        self.assertFalse(live[0]);self.assertFalse(any(call[:2]==['nft','-f'] for call in calls))
        before=list(calls)
        with self.assertRaises(ValueError):boot(dict(self.contract,owner='j'*26))
        self.assertEqual(calls,before)
        # External entrypoint validation is also preserved before interpretation.
        marker=self.root/'untrusted-interpreted'
        installed.write_text('from pathlib import Path\nPath('+repr(str(marker))+').touch()\n')
        installed.chmod(0o666)
        with self.assertRaises(ValueError):boot()
        self.assertFalse(marker.exists());self.assertEqual(calls,before)

    def test_disk_pressure_refuses_start_but_allows_stop_and_destroy(self):
        self.activate();self.free=1
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='start'))
        self.control.dispatch(dict(self.request,action='destroy'))
        self.assertFalse(self.running)

    def test_missing_runtime_guard_cannot_be_sealed(self):
        path=self.state.path('/etc/systemd/system/polygon-bor.service')
        path.write_text('\n'.join(line for line in path.read_text().splitlines() if not line.startswith('ExecStartPre=')))
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='seal'))
        self.assertFalse(self.running)

    def test_original_cipher_restore_preserves_signing_history_and_requires_stopped_fence(self):
        self.activate()
        backup=self.control.dispatch(dict(self.request,action='backup'))
        before=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='restore',backup=backup))
        self.control.dispatch(dict(self.request,action='stop'))
        for name in self.identity.FILES:self.state.path('/etc/credstore.encrypted/polygon/original/'+name).unlink()
        result=self.control.dispatch(dict(self.request,action='restore',backup=backup))
        self.assertTrue(result['stopped']);self.assertFalse(self.running)
        self.assertEqual(self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json').read_bytes(),before)
        bad=copy.deepcopy(backup);bad['files']['bor-nodekey']=base64.b64encode(b'changed key ciphertext').decode()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='restore',backup=bad))

    def test_parent_rotation_does_not_block_original_key_recovery_or_restore_old_secret(self):
        self.activate();backup=self.control.dispatch(dict(self.request,action='backup'))
        self.control.dispatch(dict(self.request,action='stop'))
        cipher=b'inert rotated parent ciphertext'
        self.state.path('/etc/credstore.encrypted/polygon/execution.json').write_bytes(cipher)
        current=self.state.read('/etc/polygon/upstream.json');current['cipher_sha256']=hashlib.sha256(cipher).hexdigest()
        self.state.write('/etc/polygon/upstream.json',current)
        self.state.path('/etc/credstore.encrypted/polygon/original/bor-nodekey').unlink()
        result=self.control.dispatch(dict(self.request,action='restore',backup=backup))
        self.assertTrue(result['restored_original_keys']);self.assertFalse(result['parent_restored'])
        self.assertEqual(self.state.path('/etc/credstore.encrypted/polygon/execution.json').read_bytes(),cipher)

    def test_missing_consensus_history_or_initialization_proof_cannot_reboot_or_restore(self):
        self.activate();backup=self.control.dispatch(dict(self.request,action='backup'))
        self.control.dispatch(dict(self.request,action='stop'))
        history=self.state.path('/var/lib/polygon/heimdall/data/priv_validator_state.json')
        history.unlink()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='start'))
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='restore',backup=backup))
        self.assertFalse(history.exists());self.assertFalse(self.running)
        history.write_bytes(b'retained history fixture')
        self.state.path('/etc/polygon/history.json').unlink()
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='restore',backup=backup))

    def test_update_does_not_downgrade_a_future_pair_before_stopping(self):
        self.activate();self.calls.clear()
        future=self.state.read('/etc/polygon/installed.json')
        old=future['profile']['releases']['bor']['tag']
        future['profile']['releases']['bor']=json.loads(json.dumps(future['profile']['releases']['bor']).replace(old,'v99.0.0'))
        self.state.write('/etc/polygon/installed.json',future)
        with self.assertRaises(ValueError):self.control.dispatch(dict(self.request,action='prepare'))
        self.assertFalse(self.calls);self.assertEqual(len(self.running),3)

if __name__=='__main__':unittest.main()
