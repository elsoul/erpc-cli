# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual RPC controller/state/unit paths with inert native/PID1/network effects."""
import hashlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixtures
import eth_state as states
import eth_accounts as accounts
import eth_namespace as namespace
import eth_units as units
import control


class Runtime(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Accounts();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.install=self.fixture.install
        self.c=dict(self.fixture.c,role='rpc',network='mainnet',kind='full')
        self.state=states.State('rpc',self.root/'rpc').reserve(self.c,'b'*64)
        self.plan=accounts.provision(self.state,'rpc');self.calls=[];self.intent='a'*32
        self.state.put('layout.json',{'contract':self.c,'binding':{'device':1,'inode':2},'children':{'reth':3,'lighthouse':4}})
        self.install(control.source_floor,'empty_data',lambda *_:True)
        for name in ['units','config','opt','helpers','firewall']:(self.root/name).mkdir()
        profiles=dict(namespace.PROFILES);profiles['rpc']={'config':self.root/'config','opt':self.root/'opt','helpers':self.root/'helpers',
                                                         'firewall':self.root/'firewall','units':units.UNITS}
        self.install(namespace,'PROFILES',profiles);self.install(namespace,'SYSTEMD',self.root/'units')
        self.install(namespace,'paths',lambda *_a,**_k:profiles['rpc']);self.install(namespace,'publish',lambda *_:'c'*64)
        self.install(control,'machine',lambda:'b'*64);self.install(control.layout,'capacity',lambda *_:{'inert':True})
        self.install(control.layout,'verify',lambda *_:None);self.install(control,'jwt',lambda *_:None)
        self.install(control,'firewall',lambda *_:None);self.install(control.processes,'quiescent',lambda *_:None)
        self.install(control.processes,'scan',lambda *_:({},False))
        def stop(plan,approved,units_stop):units_stop()
        self.install(control.processes,'stop',stop);self.install(control,'run',self.native)
        self.active=False;self.snapshot=b'inactive';self.skip=False
        pair='reth-v2.8.1--lighthouse-v8.3.2';directory=self.root/'opt'/pair;directory.mkdir()
        artifacts={}
        for client in ['reth','lighthouse']:
            raw=('inert public '+client).encode();(directory/client).write_bytes(raw);(directory/client).chmod(0o555)
            artifacts[client]={'sha256':hashlib.sha256(raw).hexdigest()}
        constant=(namespace.SOURCE/'network.yml').read_text().split('eth_checkpoint_sync_url: ')[1].strip()
        self.target={'pair':pair,'artifacts':artifacts,'rpc_bind':'127.0.0.1','metrics_bind':'127.0.0.1','checkpoint':constant}

    def native(self,argv,**_kwargs):
        self.calls.append(argv)
        if argv[1]=='show':
            if argv[-1]=='--value':
                if '--property=LoadState' in argv:return b'not-found\n'
                if '--property=MainPID' in argv:return b'0\n'
                if '--property=ActiveState' in argv:return self.snapshot
            return ('ActiveState='+('active' if self.active else 'inactive')+'\nSubState='+('running' if self.active else 'dead')+
                    '\nMainPID='+(('124' if argv[2]=='lighthouse.service' else '123') if self.active else '0')+'\nResult=success\n').encode()
        if argv[1]=='stop':self.active=False
        if argv[1] in ('start','enable') and not self.skip:self.active=True
        return b''

    def request(self,action,**extra):
        return control.dispatch(self.state,self.c,dict(action=action,contract=self.c,**extra))

    def reserve_target(self):
        source={key:self.target[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}
        source.update(reth_commit='1'*40,lighthouse_commit='2'*40,reth_archive='3'*64,lighthouse_archive='4'*64)
        self.request('reserve-deploy',intent=self.intent,target=source,operation='deploy')
        # Inert prequalified image receipt. The production-play and archive tests
        # separately exercise the actual extraction/qualification entrypoints.
        self.state.put('qualified-'+self.intent+'.json',{'source':source,'target':self.target})

    def install_target(self):
        self.reserve_target()
        self.request('begin',intent=self.intent)
        self.request('install',intent=self.intent,firewall={'run':'r-inert','bundle':'d'*64})

    def receipts(self):return {path.name:(path.stat().st_ino,path.read_bytes()) for path in self.state.directory.iterdir()}

    def stopped(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.request('stop')

    def refuses_start(self,cases):
        """Each change refuses start before any native call or receipt write; restoring it allows start."""
        for name,change,restore,error,message in cases:
            with self.subTest(name):
                before=self.receipts();change();self.calls.clear()
                try:
                    with self.assertRaisesRegex(error,message):self.request('start')
                finally:restore()
                self.assertEqual(self.calls,[]);self.assertEqual(self.receipts(),before)
        self.assertTrue(self.request('start')['started'])

    def test_indirect_shared_foreign_or_unsafe_managed_files_refuse_start(self):
        self.stopped();image=self.root/'opt'/self.target['pair']/'reth';receipt=self.state.path('active.json')
        outside=self.root/'outside';inode=fixtures.held(self,image);foreign=self.fixture.foreign
        refused='managed file is indirect, shared, foreign or has unsafe permissions'
        self.refuses_start([('foreign image',lambda:foreign.add(inode),lambda:foreign.discard(inode),ValueError,refused),
                            ('second image link',lambda:os.link(image,outside),outside.unlink,ValueError,refused),
                            ('symlinked image',lambda:(image.rename(outside),image.symlink_to(outside)),
                             lambda:(image.unlink(),outside.rename(image)),OSError,''),
                            ('group-writable image',lambda:image.chmod(0o575),lambda:image.chmod(0o555),ValueError,refused),
                            ('other-writable image',lambda:image.chmod(0o557),lambda:image.chmod(0o555),ValueError,refused),
                            ('group-readable receipt',lambda:receipt.chmod(0o640),lambda:receipt.chmod(0o600),ValueError,refused)])

    def test_foreign_writable_or_indirect_authority_directory_refuses_start(self):
        self.stopped();pair=self.root/'opt'/self.target['pair'];outside=self.root/'outside';inode=fixtures.held(self,pair)
        foreign=self.fixture.foreign;mode=pair.stat().st_mode&0o777
        refused='authority ancestor must be an original root-owned nonwritable real directory'
        self.refuses_start([('foreign directory',lambda:foreign.add(inode),lambda:foreign.discard(inode),ValueError,refused),
                            ('group-writable directory',lambda:pair.chmod(mode|0o020),lambda:pair.chmod(mode),ValueError,refused),
                            ('other-writable directory',lambda:pair.chmod(mode|0o002),lambda:pair.chmod(mode),ValueError,refused),
                            ('symlinked directory',lambda:(pair.rename(outside),pair.symlink_to(outside)),
                             lambda:(pair.unlink(),outside.rename(pair)),OSError,'')])

    def test_numeric_units_have_original_image_argv_and_sealed_external_prestart(self):
        self.install_target();record=self.state.get('installed-'+self.intent+'.json')['units']
        for name,text in record['definitions'].items():
            self.assertIn('/usr/bin/python3 -I -c',text);self.assertIn('exec(bytes.fromhex(',text)
            self.assertNotIn('/current/',text)
            if name!='erpc-eth-firewall.service':
                who=self.plan['users']['lighthouse' if name=='lighthouse.service' else 'reth']
                self.assertIn('User='+str(who['uid'])+'\nGroup='+str(who['gid']),text)
                self.assertIn('LimitCORE=0',text);self.assertIn('SendSIGKILL=no',text)
                self.assertIn('ReadWritePaths=/var/lib/ethereum/',text)
        self.assertEqual(len(record['processes']),2)
        self.assertEqual(len(next(entries for image,entries in record['processes'].items() if image.endswith('/reth'))),2)

    def test_bootstrap_requires_current_intent_and_activation_requires_private_completion(self):
        self.install_target()
        with self.assertRaises(ValueError):self.request('activate',intent=self.intent)
        self.assertEqual(self.request('bootstrap',intent=self.intent)['snapshot'],'submitted')
        self.state.put('snapshot.json',{'contract':self.c,'intent':self.intent,'target':self.target})
        self.assertEqual(self.request('bootstrap',intent=self.intent)['snapshot'],'complete')
        self.assertTrue(self.request('activate',intent=self.intent)['started'])
        self.assertFalse(self.state.exists('pending.json'));self.request('stop')
        with self.assertRaises((ValueError,FileNotFoundError)):self.request('bootstrap',intent=self.intent)

    def test_successful_systemctl_without_running_native_services_is_not_applied(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.skip=True
        with self.assertRaises(ValueError):self.request('activate',intent=self.intent)
        with self.assertRaises(ValueError):self.state.guard(self.c)
        self.assertTrue(self.state.exists('pending.json'))
        self.assertTrue(any(argv[1]=='stop' for argv in self.calls))

    def test_changed_artifact_and_original_nss_drift_refuse_before_install_or_start(self):
        self.install_target();self.calls.clear()
        image=self.root/'opt'/self.target['pair']/'reth';image.chmod(0o644);image.write_bytes(b'inert changed image');image.chmod(0o555)
        with self.assertRaises(ValueError):self.request('install',intent=self.intent,firewall={'run':'r-inert','bundle':'d'*64})
        self.assertFalse(any(argv[1]=='start' for argv in self.calls))
        self.fixture.users['reth'].pw_uid=77
        with self.assertRaises(ValueError):self.request('begin',intent=self.intent)
        with patch.object(control,'shutdown') as drain:
            self.assertTrue(self.request('stop')['stopped']);drain.assert_called_once()

    def test_foreign_contract_cannot_invoke_emergency_shutdown(self):
        with patch.object(control,'shutdown') as drain:
            with self.assertRaises(ValueError):control.dispatch(self.state,self.c,{'action':'destroy','contract':dict(self.c,owner='foreign')})
            drain.assert_not_called()

    def test_foreign_machine_cannot_even_publish_cancellation_metadata(self):
        self.install_target();before=self.state.get('halt.json');self.calls.clear()
        with patch.object(control,'machine',return_value='f'*64):
            with self.assertRaises(ValueError):self.request('stop')
        self.assertEqual(self.state.get('halt.json'),before);self.assertEqual(self.calls,[])

    def test_retained_original_plan_can_stop_after_ready_receipt_loss_but_never_recreate_identity(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.state.path('accounts.json').unlink();self.calls.clear()
        self.assertTrue(self.request('stop')['stopped'])
        with self.assertRaises((ValueError,FileNotFoundError)):self.request('start')
        before=len(self.fixture.calls)
        with self.assertRaises(ValueError):accounts.provision(self.state,'rpc')
        self.assertEqual(len(self.fixture.calls),before)

    def test_partial_consensus_stop_fences_its_real_boot_guard_without_stopping_execution(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.calls.clear();generation=self.state.halted()['generation']
        self.request('stop',layer='consensus')
        self.assertEqual(self.state.halted()['generation'],generation)
        self.assertEqual([call[-1] for call in self.calls if call[1]=='stop'],['lighthouse.service'])
        with patch.object(control,'State',return_value=self.state):
            with self.assertRaises(ValueError):control.boot('guard','lighthouse.service')
            control.boot('guard','reth.service')

    def test_start_execution_after_whole_stop_keeps_beacon_startup_paused(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.request('stop');self.calls.clear()
        self.assertTrue(self.request('start',layer='execution')['started'])
        self.assertEqual(control.paused(self.state,self.c),{'lighthouse.service'})
        starts=[call for call in self.calls if call[1]=='start']
        self.assertEqual(starts,[['/usr/bin/systemctl','start','erpc-eth-firewall.service','reth.service']])

    def test_partial_stop_first_save_failure_still_attempts_only_owned_selected_shutdown(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.calls.clear();original=self.state.put
        def failed(name,value):
            if name=='paused.json':raise OSError('inert persistent layer cancellation fault')
            original(name,value)
        with patch.object(self.state,'put',side_effect=failed):
            with self.assertRaisesRegex(ValueError,'durable layer cancellation unavailable'):self.request('stop',layer='consensus')
        self.assertEqual([call[-1] for call in self.calls if call[1]=='stop'],['lighthouse.service'])

    def test_start_keeps_already_running_exact_original_writers_instead_of_restarting_them(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        found={123:(99,self.plan['users']['reth']['uid']),124:(100,self.plan['users']['lighthouse']['uid'])}
        def prove(pid,account,approved,unit=None):
            self.assertEqual(unit,'reth.service' if pid==123 else 'lighthouse.service')
            self.assertEqual(account['uid'],found[pid][1]);self.assertTrue(approved)
            return found[pid][0]
        self.calls.clear()
        with patch.object(control.processes,'scan',return_value=(found,False)),patch.object(control.processes,'prove',side_effect=prove):
            self.assertTrue(self.request('start')['started'])
            self.assertTrue(self.request('start',layer='consensus')['started'])
        self.assertFalse(any(call[1]=='stop' for call in self.calls))

    def test_retirement_disables_owned_native_units_even_after_first_persistence_failure(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.calls.clear();original=self.state.put
        def failed(name,value):
            if name=='halt.json':raise OSError('inert cancellation persistence failure')
            original(name,value)
        with patch.object(self.state,'put',side_effect=failed):
            with self.assertRaisesRegex(ValueError,'cancellation persistence'):self.request('destroy')
        disabled={call[-1] for call in self.calls if call[1]=='disable'}
        self.assertEqual(disabled,{'reth.service','lighthouse.service'})
        self.assertFalse(self.active)
        self.assertTrue(self.state.exists('active.json'))

    def test_stopped_boot_refuses_before_expensive_capacity_and_native_checks(self):
        self.install_target();self.state.put('snapshot.json',{'contract':self.c});self.request('activate',intent=self.intent)
        self.request('stop')
        with patch.object(control,'State',return_value=self.state),patch.object(control.layout,'capacity') as capacity:
            with self.assertRaises(ValueError):control.boot('guard','reth.service')
            capacity.assert_not_called()


if __name__=='__main__':unittest.main()
