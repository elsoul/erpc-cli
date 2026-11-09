# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Host/state/identity tests: synthetic artifacts, no client/key generation run."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch
import zipfile

SOURCE=Path(__file__).parents[1]/'templates/node/control.py'
spec=importlib.util.spec_from_file_location('bsc_control',SOURCE)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
# Root metadata isolation is exercised independently by the canonical helper
# suite. This unit process imports only this checkout's benign sibling modules.
with patch.object(c,'trusted_imports',side_effect=lambda path:sys.path.append(path)):
    c.load_dependencies()
CATALOG=Path(__file__).parents[1]/'networks/catalog.json'


class ChildIsolation(unittest.TestCase):
    def test_clock_observation_requires_an_explicit_kernel_yes(self):
        for raw,expected in ((b'yes\n',True),(b'no\n',False),(b'unknown',None)):
            with patch.object(c,'run',return_value=raw):self.assertIs(c.clock_synchronized(),expected)
        with patch.object(c,'run',side_effect=c.Refused('unavailable')):self.assertIsNone(c.clock_synchronized())

    def test_time_service_selection_preserves_existing_daemons(self):
        spec=importlib.util.spec_from_file_location('bsc_clock',SOURCE.with_name('time_service.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        for service in ('chrony.service','chronyd.service','ntp.service','ntpd.service'):
            selected=module.choose({service:{'state':'running'}})
            self.assertEqual(selected,{'service':service,'install_fallback':False})
            self.assertEqual(module.choose({service:{'state':'stopped'}})['service'],service)
        self.assertEqual(module.choose({}),{'service':'systemd-timesyncd.service','install_fallback':True})

    def test_root_child_environment_excludes_inherited_credentials_and_python_settings(self):
        from types import SimpleNamespace
        with patch.dict(os.environ,{'PYTHONPATH':'untrusted-fixture','OP_SESSION_FIXTURE':'synthetic-session'}),patch.object(c.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'ok')) as run:
            self.assertEqual(c.run(['systemctl','show']),b'ok')
            self.assertEqual(run.call_args.kwargs['env'],{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        with patch.object(c,'firewall_controller') as controller:
            c.firewall({'firewall':{'run':'r-fixture','bundle':'a'*64}})
            controller.return_value.dispatch.assert_called_once_with('require-confirmed','r-fixture','a'*64)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup);self.addCleanup(patch.stopall)
        root=Path(folder.name)
        patch.object(c,'ROOT_UID',os.getuid()).start();patch.object(c,'TRUST_ANCHOR',root).start()
        patch.object(c,'ROOT',root/'state').start();patch.object(c,'CONF',root/'config').start()
        patch.object(c,'OPT',root/'opt').start();patch.object(c,'LOCK',root/'lock').start()
        patch.object(c,'UNIT_DIRECTORY',root/'units').start()
        patch.object(c,'HELPERS',root/'helpers').start();patch.object(c,'LAUNCHER',root/'launcher').start();patch.object(c,'OPERATION_ROOT',root).start();patch.object(c,'CATALOG',CATALOG).start()
        c.ROOT.mkdir();c.CONF.mkdir();c.OPT.mkdir()
        profile=c.catalog('chapel')
        self.state={'owner':'ownedhost','network':'chapel','role':'rpc','platform':'amd64','storage':'full',
                    'snapshot':profile['recommended_snapshots']['full'],'version':profile['recommended'],
                    'commit':profile['releases'][profile['recommended']]['commit'],'config_id':'c'*64,'phase':'prepared'}
        self.state.update(deploy_intent='a'*32, deploy_target=c.pin(self.state))
        c.save(self.state)
        self.running=False;self.calls=[];self.free=100_000_000_000_000;self.allocated=0
        patch.object(c.bootstrap.shutil,'disk_usage',side_effect=lambda _:type('Usage',(),{'free':self.free})()).start()
        patch.object(c,'processes',return_value=[]).start()
        def run(argv,**kwargs):
            self.calls.append(argv)
            if argv[:2]==['du','-sx']:return (str(self.allocated)+' fixture').encode()
            if argv[:2]==['systemctl','show']:return b'loaded' if 'LoadState' in argv[2] else b'0'
            if argv[:2]==['systemctl','is-active']:return b'active' if self.running else b'inactive'
            if argv[:2]==['systemctl','stop']:self.running=False
            if argv[:2]==['systemctl','start']:self.running=True
            return b''
        patch.object(c,'run',side_effect=run).start()

    def request(self,action):
        request=dict(self.state,action=action)
        if action in ('check-deploy','begin-install','install-artifacts','finish-install'):
            request['intent']='a'*32
        return request

    def test_untrusted_empty_root_and_destination_ancestors_are_never_adopted(self):
        (c.ROOT/'owner.json').unlink();c.CONF.rmdir();c.OPT.rmdir()
        for path in (c.ROOT,c.ROOT.parent):
            before=path.stat().st_mode & 0o777
            path.chmod(0o777)
            try:
                with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
                self.assertEqual(path.stat().st_mode & 0o777,0o777)
                self.assertFalse((c.ROOT/'owner.json').exists())
            finally:path.chmod(before)
        unsafe=c.ROOT.parent/'privileged';unsafe.mkdir(mode=0o777);unsafe.chmod(0o777)
        with patch.object(c,'HELPERS',unsafe/'missing'):
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
        self.assertFalse((unsafe/'missing').exists());self.assertEqual(self.calls,[])

    def test_nonroot_directory_or_owner_and_private_receipt_links_are_refused(self):
        original=Path.lstat
        for target in (c.ROOT,c.ROOT.parent,c.ROOT/'owner.json'):
            def wrong_owner(path, **kwargs):
                info=original(path,**kwargs)
                if path==target:
                    fields=list(info);fields[4]=c.ROOT_UID+1;return os.stat_result(fields)
                return info
            with self.subTest(target=target),patch.object(Path,'lstat',wrong_owner):
                with self.assertRaises(c.Refused):c.read_state()
                with self.assertRaises(c.Refused):c.save(self.state)
                with self.assertRaises(c.Refused):c.locked(self.request('stop'))
        owner=c.ROOT/'owner.json'
        raw=owner.read_bytes();owner.unlink()
        target=c.ROOT
        with patch.object(Path,'lstat',wrong_owner):
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
        self.assertFalse(owner.exists());owner.write_bytes(raw);owner.chmod(0o600)
        link=c.ROOT/'alias';os.link(owner,link)
        with self.assertRaises(c.Refused):c.read_state()
        with self.assertRaises(c.Refused):c.save(self.state)
        link.unlink();owner.chmod(0o644)
        with self.assertRaises(c.Refused):c.read_state()
        owner.chmod(0o600)
        pending=c.ROOT/'owner.new';pending.symlink_to(owner)
        with self.assertRaises(c.Refused):c.save(self.state)
        self.assertTrue(pending.is_symlink());self.assertEqual(self.calls,[])

    def test_established_permission_and_symlink_drift_refuses_before_mutation(self):
        for path in (c.ROOT,c.CONF,c.OPT,c.ROOT.parent):
            mode=path.stat().st_mode & 0o777;path.chmod(0o777)
            try:
                for action in ('prepare','authorize-deploy','begin-install','stop','destroy'):
                    with self.assertRaises(c.Refused):c.locked(self.request(action))
            finally:path.chmod(mode)
        moved=c.ROOT.with_name('moved');c.ROOT.rename(moved);c.ROOT.symlink_to(moved,target_is_directory=True)
        with self.assertRaises(c.Refused):c.read_state()
        with self.assertRaises(c.Refused):c.save(self.state)
        self.assertEqual(self.calls,[])

    def test_publication_checks_closed_release_pointer_and_carried_bytes(self):
        source=c.ROOT.parent/'source';source.mkdir()
        for name,raw in [('control.py',b'synthetic controller'),('bootstrap.py',b'synthetic bootstrap'),('validator.py',b'synthetic validator'),('catalog.json',b'{}')]:
            (source/name).write_bytes(raw)
        digest=hashlib.sha256(b''.join((source/name).read_bytes() for name in ('control.py','bootstrap.py','validator.py','catalog.json'))).hexdigest()
        release=c.HELPERS/'releases'/digest;release.mkdir(parents=True)
        for file in source.iterdir():(release/file.name).write_bytes(file.read_bytes())
        (c.HELPERS/'current').symlink_to(release,target_is_directory=True)
        (source/'launcher.py').write_bytes(b'synthetic launcher');c.LAUNCHER.write_bytes(b'synthetic launcher')
        with patch.object(c,'__file__',str(source/'control.py')):
            self.assertEqual(c.locked(self.request('verify-helpers')),{'helpers':'verified'})
            c.LAUNCHER.write_bytes(b'substitution')
            with self.assertRaises(c.Refused):c.locked(self.request('verify-helpers'))
            c.LAUNCHER.write_bytes(b'synthetic launcher')
            (release/'control.py').write_bytes(b'substitution')
            with self.assertRaises(c.Refused):c.locked(self.request('verify-helpers'))
        (release/'control.py').chmod(0o666)
        with self.assertRaises(c.Refused):c.read_state()
        (release/'control.py').chmod(0o644)
        (c.HELPERS/'current').unlink();(c.HELPERS/'current').symlink_to(source,target_is_directory=True)
        with self.assertRaises(c.Refused):c.read_state()

    def test_own_boot_units_and_dropins_cannot_be_adopted_or_drift(self):
        c.UNIT_DIRECTORY.mkdir()
        for unit in c.owned_units():
            directory=c.UNIT_DIRECTORY/(unit+'.d');directory.mkdir()
            injected=directory/'99-foreign.conf';injected.write_text('[Service]\nExecStart=/inert\n')
            for mode in (0o755,0o777):
                directory.chmod(mode)
                for action in ('prepare','begin-install','stop','destroy'):
                    with self.assertRaises(c.Refused):c.locked(self.request(action))
            directory.chmod(0o755);injected.unlink()
            guard=directory/'50-erpc-firewall-guard.conf';guard.write_bytes(b'inert guard')
            guard.chmod(0o666)
            with self.assertRaises(c.Refused):c.read_state()
            guard.chmod(0o644);self.assertEqual(c.read_state()['owner'],self.state['owner'])
            guard.unlink();directory.rmdir()
        (c.ROOT/'owner.json').unlink();c.CONF.rmdir();c.OPT.rmdir()
        dropin=c.UNIT_DIRECTORY/(c.UNIT+'.service.d');dropin.mkdir()
        with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
        self.assertFalse((c.ROOT/'owner.json').exists());self.assertEqual(self.calls,[])

    def test_checked_controller_rejects_untrusted_common_firewall_before_import(self):
        path=c.HELPERS.parent/'rpc-firewall.py';marker=c.ROOT.parent/'firewall-imported'
        path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("imported")\nclass Firewall:\n def __init__(self,family):assert family=="bsc"\n def dispatch(self,*args):assert args==("load",)\n')
        path.chmod(0o644)
        with patch.object(sys,'argv',['control','firewall-load']),patch.object(c.os,'geteuid',return_value=0):
            c.main();self.assertTrue(marker.exists());marker.unlink()
            path.chmod(0o666)
            with self.assertRaises(c.Refused):c.main()
            self.assertFalse(marker.exists())
        self.assertEqual(self.calls,[])

    def test_first_preparation_has_traversable_parent_and_private_owner_under_strict_umask(self):
        (c.ROOT/'owner.json').unlink();c.ROOT.rmdir();c.CONF.rmdir();c.OPT.rmdir()
        previous=os.umask(0o077)
        try:
            with patch.object(c,'loaded',return_value=False),patch.object(c.pwd,'getpwnam',side_effect=KeyError),patch.object(c.grp,'getgrnam',side_effect=KeyError):
                c.locked(self.request('prepare'))
        finally:os.umask(previous)
        self.assertEqual(c.ROOT.stat().st_mode & 0o777,0o755)
        self.assertEqual((c.ROOT/'owner.json').stat().st_mode & 0o777,0o600)

    def test_missing_owner_refuses_staged_identity_receipts_downloads_and_helpers(self):
        (c.ROOT/'owner.json').unlink();c.CONF.rmdir();c.OPT.rmdir()
        paths=[c.ROOT/'identity/nodekey.new',c.ROOT/'identity/nodekey',c.ROOT/'owner.json.new',
               c.ROOT/'bootstrap.json',c.ROOT/'snapshot-stage/geth/file',c.ROOT/'downloads/file',
               c.CONF/'genesis.json',c.OPT/'geth',c.HELPERS/'control.py',c.LAUNCHER]
        for path in paths:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'synthetic orphan')
                with patch.object(c,'loaded',return_value=False),patch.object(c.pwd,'getpwnam',side_effect=KeyError),patch.object(c.grp,'getgrnam',side_effect=KeyError),patch.object(c.secrets,'randbelow') as entropy:
                    with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
                    entropy.assert_not_called()
                self.assertFalse((c.ROOT/'owner.json').exists())
                self.assertEqual(path.read_bytes(),b'synthetic orphan')
                path.unlink()
                parent=path.parent
                while parent!=c.ROOT and parent!=c.ROOT.parent:
                    parent.rmdir();parent=parent.parent

    def test_failed_install_can_stop_or_retire_and_cancels_every_queued_stage(self):
        initial=copy.deepcopy(self.state)
        for action in ('stop','destroy'):
            c.save(initial)
            with patch.object(c,'stop',side_effect=c.Refused('failed stop')):
                with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))
            with patch.object(c,'stop') as stopped:
                result=c.locked(self.request(action));stopped.assert_called_once()
            self.assertTrue(result['data_preserved'])
            self.assertTrue(c.read_state()['startup_revoked'])
            self.assertIsNone(c.read_state()['deploy_intent'])
            for stale in ('check-deploy','begin-install','install-artifacts','finish-install','start'):
                request=dict(self.request(stale),intent='a'*32)
                with patch.object(c,'stop') as stop,patch.object(c,'install') as install:
                    with self.assertRaises(c.Refused):c.locked(request)
                    stop.assert_not_called();install.assert_not_called()
            with self.assertRaises(c.Refused):c.guard(c.read_state())
            fresh=dict(self.request('authorize-deploy'),intent='b'*32)
            with self.assertRaises(c.Refused):c.locked(dict(fresh,config_id='d'*64))
            c.locked(fresh)
            c.locked(dict(self.request('begin-install'),intent='b'*32))
            self.assertEqual(c.read_state()['phase'],'installing')

    def test_permanent_bootstrap_failure_can_retire_without_resuming_downloads(self):
        c.locked(self.request('begin-install'))
        with patch.object(c,'install',side_effect=c.Refused('snapshot verification failed')):
            with self.assertRaises(c.Refused):c.locked(self.request('install-artifacts'))
        with patch.object(c,'install') as install,patch.object(c,'stop') as stop:
            self.assertEqual(c.locked(self.request('destroy'))['phase'],'retired')
            stop.assert_called_once();install.assert_not_called()
        self.assertTrue(c.read_state()['startup_revoked'])
        with self.assertRaises(c.Refused):c.locked(self.request('install-artifacts'))

    def test_failed_explicit_stop_keeps_cancellation_and_restart_fence_durable(self):
        self.state.update(phase='installed',installed=c.pin(self.state));c.save(self.state)
        with patch.object(c,'stop',side_effect=c.Refused('owned writer cannot stop')):
            with self.assertRaises(c.Refused):c.locked(self.request('stop'))
        state=c.read_state();self.assertTrue(state['startup_revoked']);self.assertIsNone(state['deploy_intent'])
        with self.assertRaises(c.Refused):c.guard(state)
        with self.assertRaises(c.Refused):c.locked(dict(self.request('start'),intent='a'*32))

    def test_first_cancellation_storage_failure_still_stops_and_disables_owned_rpc(self):
        for action in ('stop','destroy'):
            c.save(self.state);self.running=True;self.calls.clear()
            with patch.object(c,'save',side_effect=OSError('inert full storage')):
                with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request(action))
            self.assertFalse(self.running)
            self.assertIn(['systemctl','stop',c.UNIT],self.calls)
            self.assertIn(['systemctl','disable',c.UNIT],self.calls)
            self.assertEqual(c.read_state()['phase'],'prepared')

    def test_transient_first_write_is_retried_after_stop_without_claiming_success(self):
        original=c.save;attempts=[];self.running=True
        def save(state):
            attempts.append(bool(self.running))
            if len(attempts)==1:raise OSError('inert transient first write')
            original(state)
        with patch.object(c,'save',side_effect=save):
            with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request('stop'))
        self.assertEqual(attempts,[True,False])
        self.assertTrue(c.read_state()['startup_revoked'])
        self.assertIsNone(c.read_state()['deploy_intent'])
        with self.assertRaises(c.Refused):c.locked(dict(self.request('start'),intent='a'*32))

    def test_shutdown_failure_still_attempts_verified_writers_and_disable_then_reports_failure(self):
        self.running=True
        def stopped(state):self.running=False
        with patch.object(c,'stop',side_effect=c.Refused('inert unit stop failure')),patch.object(c,'quiesce_writers',side_effect=stopped)as drained:
            with self.assertRaisesRegex(c.Refused,'shutdown'):c.locked(self.request('stop'))
            drained.assert_called_once()
        self.assertFalse(self.running)
        self.assertIn(['systemctl','disable',c.UNIT],self.calls)
        self.assertTrue(c.read_state()['startup_revoked'])
        self.running=True;self.calls.clear()
        with patch.object(c,'stop',side_effect=c.Refused('inert stop failure')),patch.object(c,'quiesce_writers',side_effect=c.Refused('ambiguous writer')):
            with self.assertRaisesRegex(c.Refused,'owned writer drain'):c.locked(self.request('destroy'))
        self.assertTrue(self.running)
        self.assertTrue(c.read_state()['startup_revoked'])
        self.assertIn(['systemctl','disable',c.UNIT],self.calls)

    def test_foreign_scope_never_reaches_storage_failure_shutdown_fallback(self):
        for action in ('stop','destroy'):
            for change in ({'owner':'foreign'},{'network':'mainnet'},{'role':'validator','operator':'0x'+'2'*40}):
                with patch.object(c,'save',side_effect=OSError('inert first write'))as saved,patch.object(c,'stop')as stopped,patch.object(c,'quiesce_writers')as drained:
                    with self.assertRaises(c.Refused):c.locked(dict(self.request(action),**change))
                    saved.assert_not_called();stopped.assert_not_called();drained.assert_not_called()
        self.assertFalse(self.calls)

    def test_real_first_file_or_directory_fsync_failure_still_stops_the_owned_rpc(self):
        original=c.os.fsync
        for failure in (1,2):
            for action in ('stop','destroy'):
                c.save(self.state);self.running=True;self.calls.clear();count=0
                def fsync(fd):
                    nonlocal count
                    count+=1
                    if count==failure:raise OSError('inert real fsync failure')
                    return original(fd)
                with self.subTest(failure=failure,action=action),patch.object(c.os,'fsync',side_effect=fsync):
                    with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request(action))
                self.assertFalse(self.running)
                self.assertIn(['systemctl','stop',c.UNIT],self.calls)
                self.assertIn(['systemctl','disable',c.UNIT],self.calls)
                self.assertTrue(c.read_state()['startup_revoked'])
                with self.assertRaises(c.Refused):c.locked(dict(self.request('start'),intent='a'*32))

    def test_installed_catalog_can_authorize_but_cannot_execute_a_future_carried_release(self):
        future=dict(self.request('authorize-deploy'),intent='b'*32,version='2.0.0',commit='d'*40)
        c.locked(future)
        self.assertEqual(c.read_state()['deploy_target']['version'],'2.0.0')
        with patch.object(c,'stop') as stop:
            with self.assertRaises(c.Refused):c.locked(dict(future,action='begin-install'))
            stop.assert_not_called()
        profile=copy.deepcopy(c.catalog('chapel'))
        profile['releases']['2.0.0']=copy.deepcopy(profile['releases'][self.state['version']])
        profile['releases']['2.0.0']['commit']='d'*40
        with patch.object(c,'catalog',return_value=profile),patch.object(c,'stop') as stop:
            c.locked(dict(future,action='begin-install'));stop.assert_called_once()
        self.assertEqual(c.read_state()['target']['version'],'2.0.0')

    def test_authorization_rejects_unbounded_or_malformed_target_metadata(self):
        for change in ({'version':'2.0.0;false'},{'version':'65536.0.0'},{'version':'02.0.0'},{'commit':'not-a-pin'}):
            request=dict(self.request('authorize-deploy'),intent='b'*32);request.update(change)
            with self.assertRaises(c.Refused):c.locked(request)
            self.assertEqual(c.read_state()['deploy_intent'],'a'*32)

    def test_new_authorization_supersedes_old_queue_and_binds_target(self):
        c.locked(dict(self.request('authorize-deploy'),intent='b'*32))
        with self.assertRaises(c.Refused):c.locked(self.request('check-deploy'))
        c.locked(dict(self.request('check-deploy'),intent='b'*32))
        with self.assertRaises(c.Refused):c.locked(dict(self.request('check-deploy'),intent='b'*32,config_id='d'*64))
        text=(SOURCE.parent/'firewall.yml').read_text()
        self.assertIn("{'action':'check-deploy'}",text)
        self.assertLess(text.index("{'action':'check-deploy'}"),text.index('Install nftables'))

    def test_every_mutator_checks_remote_owner_network_and_retention_first(self):
        for action in ('prepare','authorize-deploy','check-deploy','begin-install','install-artifacts','finish-install','start','stop','restart','destroy'):
            for change in ({'owner':'other'},{'role':'validator'},{'network':'mainnet'},{'storage':'pruned'},{'snapshot':'not-registered'}):
                request=self.request(action);request.update(change)
                with self.assertRaises(c.Refused):c.locked(request)
                self.assertEqual(self.calls,[])
        self.assertEqual(c.read_state()['phase'],'prepared')

    def test_failed_cross_network_init_does_not_gain_stop_or_destroy_authority(self):
        for action in ('prepare','stop','destroy'):
            request=self.request(action);request['network']='mainnet'
            with self.assertRaises(c.Refused):c.locked(request)
        self.assertEqual(self.calls,[])

    def test_capacity_failure_before_prepare_or_update_is_rechecked_on_retry(self):
        self.free=1
        for action in ('prepare','begin-install'):
            with self.assertRaises(c.Refused):c.locked(self.request(action))
        self.assertFalse(any(argv[:2]==['systemctl','stop'] for argv in self.calls))
        self.assertEqual(c.read_state()['phase'],'prepared')
        self.free=100_000_000_000_000;c.locked(self.request('begin-install'))
        self.free=1
        with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))
        self.assertEqual(c.read_state()['phase'],'installing')

    def test_partial_bootstrap_allocation_reduces_initial_floor_but_never_operating_reserve(self):
        (c.ROOT/'snapshot-stage').mkdir();self.allocated=2_000_000_000_000;self.free=300_000_000_000
        c.capacity(self.state)
        self.free=1
        with self.assertRaises(c.Refused):c.capacity(self.state)

    def test_interrupted_update_has_one_target_and_failed_stop_leaves_persistent_fence(self):
        with patch.object(c,'stop',side_effect=c.Refused('failed stop')):
            with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))
        self.assertEqual(c.read_state()['phase'],'installing')
        different=self.request('begin-install');different['config_id']='d'*64
        with self.assertRaises(c.Refused):c.locked(different)
        with self.assertRaises(c.Refused):c.locked(self.request('start'))
        c.locked(self.request('begin-install'))

    def test_retirement_never_reports_success_when_an_orphan_cannot_stop(self):
        self.state['phase']='installed';c.save(self.state)
        with patch.object(c,'stop',side_effect=c.Refused('orphan writer')):
            with self.assertRaises(c.Refused):c.locked(self.request('destroy'))
        self.assertEqual(c.read_state()['phase'],'retired')
        with self.assertRaises(c.Refused):c.guard(c.read_state())

    def test_concurrent_remote_run_refuses_mutation_without_blocking_readonly_status(self):
        fd=os.open(c.OPERATION_ROOT,os.O_RDONLY)
        try:
            c.fcntl.flock(fd,c.fcntl.LOCK_EX)
            with self.assertRaises(c.Refused):c.locked(self.request('stop'))
            self.assertFalse(c.locked(self.request('status'))['ready'])
            c.locked(self.request('begin-install'),in_play=True)
        finally:os.close(fd)

    def test_node_arguments_keep_verification_and_loopback_and_disable_signing(self):
        args=c.arguments(self.state)
        for expected in ('--chapel','--tries-verify-mode=local','--history.blocks=0','--history.transactions=0','--http.addr=127.0.0.1','--ws.addr=127.0.0.1','--mine=false','--vote=false','--rpc.allow-unprotected-txs=false'):
            self.assertIn(expected,args)
        self.assertFalse(any(arg.startswith('--unlock') for arg in args))
        pruned=dict(self.state,storage='pruned');pruned['snapshot']=c.catalog('chapel')['recommended_snapshots']['pruned']
        self.assertIn('--history.blocks=600000',c.arguments(pruned))

    def test_jenner_deadline_refuses_old_runtime_but_keeps_stop_and_upgrade_metadata_valid(self):
        main=c.catalog('mainnet');cutoff=main['network_upgrade']['activation_unix']
        old=dict(self.state,network='mainnet',version='1.7.8',commit=main['releases']['1.7.8']['commit'],
            snapshot=main['recommended_snapshots']['full'],phase='installed',startup_revoked=False)
        old['installed']=c.pin(old)
        new=dict(old,version='1.8.2',commit=main['releases']['1.8.2']['commit']);new['installed']=c.pin(new)
        self.assertTrue(c.release_supported(old,cutoff-1));self.assertFalse(c.release_supported(old,cutoff))
        self.assertTrue(c.release_supported(new,cutoff));self.assertTrue(c.release_supported(self.state,cutoff))
        with patch.object(c,'check'),patch.object(c.time,'time',return_value=cutoff),patch.object(c,'account') as account:
            with self.assertRaisesRegex(c.Refused,'Jenner'):c.guard(old)
            account.assert_not_called()
        c.validate(old);self.assertEqual(c.release(old)['commit'],main['releases']['1.7.8']['commit'])

    def test_pinned_catalog_matches_exact_bytes_and_has_separate_release_audiences(self):
        self.assertEqual(hashlib.sha256(CATALOG.read_bytes()).hexdigest(),c.CATALOG_SHA)
        self.assertEqual(c.catalog('mainnet')['recommended'],'1.8.2')
        self.assertEqual(c.catalog('chapel')['recommended'],'1.8.1')
        other=self.request('begin-install');other['version']='1.7.8'
        with self.assertRaises(c.Refused):c.locked(other)

    def test_missing_unit_orphan_is_signaled_by_pidfd_and_reused_pid_is_refused(self):
        proc=c.ROOT/'proc';entry=proc/'123';entry.mkdir(parents=True)
        (entry/'stat').write_text('123 (geth) S '+'0 '*18+'99 0')
        fdpath=c.ROOT/'pidfd-fixture';fdpath.write_text('fixture')
        writers=[(123,'99')];signals=[]
        def signal(fd,value):signals.append(value);writers.clear()
        with patch.object(c,'PROC',proc),patch.object(c,'loaded',return_value=False),patch.object(c,'processes',side_effect=lambda _:list(writers)),patch.object(c.os,'pidfd_open',side_effect=lambda _:os.open(fdpath,os.O_RDONLY),create=True),patch.object(c.signal,'pidfd_send_signal',side_effect=signal,create=True),patch('select.select',side_effect=lambda f,*_: (f,[],[])):
            c.stop(self.state)
            self.assertEqual(signals,[c.signal.SIGTERM])
            writers[:]=[(123,'old-start')]
            with self.assertRaises(c.Refused):c.stop(self.state)
            self.assertEqual(signals,[c.signal.SIGTERM])

    def test_init_retry_cannot_refresh_running_or_retired_helpers(self):
        for phase in ('installed','installing','retired'):
            state=dict(self.state,phase=phase);c.save(state)
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
            self.assertEqual(self.calls,[])

    def test_changed_or_root_service_identity_is_not_adopted_on_boot(self):
        from types import SimpleNamespace
        state=dict(self.state,service_uid=995,service_gid=995)
        for uid,gid in ((0,995),(995,0),(994,995),(995,994)):
            with patch.object(c.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=uid,pw_gid=gid)):
                with self.assertRaises(c.Refused):c.account(state)
        with patch.object(c.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=995,pw_gid=995)):
            c.account(state)

    def test_failed_final_verification_keeps_installation_phase(self):
        c.locked(self.request('begin-install'))
        request=self.request('finish-install');request['firewall']={'run':'r-fixture','bundle':'a'*64}
        with patch.object(c,'guard',side_effect=c.Refused('invalid artifact or receipt')):
            with self.assertRaises(c.Refused):c.locked(request)
        self.assertEqual(c.read_state()['phase'],'installing')

    def test_readiness_requires_owned_process_genesis_peers_sync_and_fresh_tip(self):
        profile=c.catalog('chapel');self.running=True
        state=dict(self.state,phase='installed')
        observed={'eth_chainId':hex(profile['chain_id']),'eth_syncing':False,'net_peerCount':'0x4','admin_nodeInfo':{'id':'a'*64}}
        head={'number':'0x123','timestamp':hex(10000)};genesis={'hash':profile['genesis_hash']}
        def rpc(method,params=None):
            if method=='eth_getBlockByNumber':return genesis if params[0]=='0x0' else head
            return observed[method]
        with patch.object(c,'guard'),patch.object(c,'processes',return_value=[(123,'99')]),patch.object(c,'rpc',side_effect=rpc),patch.object(c,'run',return_value=b'123'),patch.object(c,'active',return_value='active'),patch.object(c.time,'time',return_value=10001):
            self.assertTrue(c.status(state)['ready'])
            for method,bad in [('eth_chainId','0x1'),('eth_syncing',{}),('net_peerCount','0x0'),('admin_nodeInfo',{})]:
                old=observed[method];observed[method]=bad
                self.assertFalse(c.status(state)['ready']);observed[method]=old
            genesis['hash']='0x'+'b'*64;self.assertFalse(c.status(state)['ready']);genesis['hash']=profile['genesis_hash']
            head['timestamp']='0x1';self.assertFalse(c.status(state)['ready']);head['timestamp']=hex(10000)
            with patch.object(c,'run',return_value=b'456'):self.assertFalse(c.status(state)['ready'])

    def test_jenner_upgrade_preserves_original_database_identity_and_one_interrupted_target(self):
        profile=copy.deepcopy(c.catalog('mainnet'));old=profile['releases']['1.7.8'];new=profile['releases']['1.8.2']
        self.state.update(network='mainnet',version='1.7.8',commit=old['commit'],
            snapshot=profile['recommended_snapshots']['full'],phase='installed',service_uid=995,service_gid=995)
        self.state.update(installed=c.pin(self.state),deploy_intent=None,deploy_target=None)
        data=c.ROOT/'data/geth/chaindata';data.mkdir(parents=True);original=data/'original';original.write_bytes(b'inert existing database')
        identity=c.ROOT/'identity/nodekey';identity.parent.mkdir();identity.write_bytes(b'1'*64)
        self.state['identity_sha256']=hashlib.sha256(identity.read_bytes()).hexdigest();c.save(self.state)
        snapshot=profile['snapshots'][self.state['snapshot']]
        receipt={'identity':{'owner':self.state['owner'],'snapshot':snapshot['id'],'manifest':snapshot['manifest_sha256']},'phase':'complete'}
        c.bootstrap.durable_json(c.ROOT/'bootstrap.json',receipt)
        binary=c.ROOT/'new-binary';binary.write_bytes(b'inert qualified newer binary; never executed')
        genesis=b'{"config":{"chainId":56},"synthetic":true}';config=b'[Eth]\nNetworkId=56\n'
        archive=c.ROOT/'new-config.zip'
        with zipfile.ZipFile(archive,'w') as package:
            package.writestr('mainnet/genesis.json',genesis);package.writestr('mainnet/config.toml',config)
        new['binaries']['amd64']['sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        new['genesis_sha256']=hashlib.sha256(genesis).hexdigest();new['config_sha256']=hashlib.sha256(config).hexdigest()
        request=dict(self.state,version='1.8.2',commit=new['commit'],intent='b'*32)
        def stage(action):return c.locked(dict(request,action=action))
        downloads=[]
        def download(url,*args):
            downloads.append(url);self.assertIn('/v1.8.2/',url)
            return archive if url.endswith('.zip') else binary
        before=(original.read_bytes(),identity.read_bytes(),original.stat().st_ino)
        with patch.object(c,'catalog',return_value=profile),patch.object(c,'account'),patch.object(c,'firewall'), \
             patch.object(c.os,'chown'),patch.object(c.bootstrap,'download',side_effect=download), \
             patch.object(c.secrets,'randbelow',side_effect=AssertionError('must not regenerate original identity')):
            stage('authorize-deploy');stage('begin-install')
            normal_run=c.run
            def interrupted(argv,**kw):
                if 'init' in argv:raise c.Refused('inert failure after database-open attempt')
                return normal_run(argv,**kw)
            with patch.object(c,'run',side_effect=interrupted):
                with self.assertRaises(c.Refused):stage('install-artifacts')
            self.assertEqual(c.read_state()['target']['version'],'1.8.2')
            with self.assertRaises(c.Refused):c.locked(dict(self.state,action='authorize-deploy',intent='c'*32))
            stage('install-artifacts');request['firewall']={'run':'r-upgrade-fixture','bundle':'d'*64};stage('finish-install')
            current=c.read_state();self.assertEqual(current['installed']['version'],'1.8.2')
            with self.assertRaises(c.Refused):
                previous=dict(self.state,action='authorize-deploy',intent='c'*32);c.locked(previous)
                c.locked(dict(previous,action='begin-install'))
            self.assertEqual((original.read_bytes(),identity.read_bytes(),original.stat().st_ino),before)
            self.assertEqual(json.loads((c.ROOT/'bootstrap.json').read_text()),receipt)
            self.assertTrue(all('/v1.8.2/' in url for url in downloads))
            self.assertFalse(any(argv[:2]==['systemctl','start'] for argv in self.calls))

    def test_synthetic_install_recovers_identity_staging_without_generating_a_second_key(self):
        previous_umask=os.umask(0o077);self.addCleanup(os.umask,previous_umask)
        profile=copy.deepcopy(c.catalog('chapel'));selected=profile['releases'][self.state['version']]
        binary=c.ROOT/'binary-fixture';binary.write_bytes(b'non-executable synthetic artifact')
        genesis=b'{"config":{"chainId":97},"synthetic":true}'
        config=b'[Eth]\nNetworkId=97\n'
        archive=c.ROOT/'network-fixture.zip'
        with zipfile.ZipFile(archive,'w') as package:
            package.writestr('testnet/genesis.json',genesis);package.writestr('testnet/config.toml',config)
        selected['binaries']['amd64']['sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
        selected['genesis_sha256']=hashlib.sha256(genesis).hexdigest();selected['config_sha256']=hashlib.sha256(config).hexdigest()
        def download(url,*args):return archive if url.endswith('.zip') else binary
        def bootstrap(*args):
            (c.ROOT/'data/geth/chaindata').mkdir(parents=True,exist_ok=True)
        uid=995
        c.locked(self.request('begin-install'))
        request=dict(self.request('install-artifacts'),service_uid=uid,service_gid=995)
        original=c.save;interrupted=[];synced_identity_directory=[]
        real_fsync=os.fsync
        def fsync(fd):
            path=c.ROOT/'identity'
            if path.exists() and os.fstat(fd).st_ino==path.stat().st_ino:
                synced_identity_directory.append(True)
            real_fsync(fd)
        def save(state):
            if 'identity_sha256' in state and not interrupted:
                self.assertTrue(synced_identity_directory, 'staged directory must be durable before its identity receipt')
                interrupted.append(True);raise RuntimeError('power loss before identity intent persisted')
            original(state)
        with patch.object(c,'catalog',return_value=profile),patch.object(c.bootstrap,'download',side_effect=download),patch.object(c.bootstrap,'bootstrap',side_effect=bootstrap),patch.object(c.os,'chown'),patch.object(c.secrets,'randbelow',return_value=0) as random:
            with patch.object(c,'save',side_effect=save),patch.object(c.os,'fsync',side_effect=fsync):
                with self.assertRaises(RuntimeError):c.locked(request)
            self.assertTrue((c.ROOT/'identity/nodekey.new').is_file())
            c.locked(request)
            self.assertEqual(random.call_count,1,'retry must preserve the staged synthetic identity')
            self.assertEqual((c.OPT/self.state['version']).stat().st_mode & 0o777,0o755)
            self.assertEqual(c.binary(self.state).parent.stat().st_mode & 0o777,0o755)
            self.assertEqual(c.read_state()['identity_sha256'],hashlib.sha256((c.ROOT/'identity/nodekey').read_bytes()).hexdigest())
            (c.ROOT/'identity/nodekey').unlink()
            with self.assertRaises(c.Refused):c.locked(request)
            self.assertEqual(random.call_count,1,'a previously published identity cannot regenerate')
        self.assertFalse(any(argv[0]==str(c.binary(self.state)) for argv in self.calls),'all process execution is mocked')


class ValidatorActivation(unittest.TestCase):
    setUp = Lifecycle.setUp
    request = Lifecycle.request
    # Keep the existing RPC cases on their original role; these methods create
    # validator fixtures explicitly so no inherited test relaxes an RPC boundary.
    def signer(self):
        self.state.update(role='validator',operator='0x'+'2'*40,phase='installed',installed=c.pin(self.state),backup_confirmed=True,startup_revoked=False)
        c.save(self.state);(c.ROOT/'bootstrap.json').write_text('{"phase":"complete"}')
        for name in ('account','capacity','artifacts','firewall'):patch.object(c,name).start()
        patch.object(c.validator,'guard').start()
        patch.object(c,'clock_synchronized',return_value=True).start()

    def test_timer_and_custody_refuse_untrusted_owner_launcher_or_unit_before_authority(self):
        self.signer();c.UNIT_DIRECTORY.mkdir()
        timer=c.UNIT_DIRECTORY/(c.UNIT+'-activation.timer')
        for target in (c.ROOT/'owner.json',c.LAUNCHER,timer):
            if not target.exists():target.write_bytes(b'inert fixture')
            mode=target.stat().st_mode & 0o777;target.chmod(0o666)
            try:
                for action in ('stop','destroy','activate','export-custody','restore-custody','confirm-backup'):
                    with patch.object(c,'stop') as stop,patch.object(c,'rpc') as rpc,patch.object(c.validator,'export_backup') as export:
                        with self.assertRaises(c.Refused):c.locked(self.request(action))
                        stop.assert_not_called();rpc.assert_not_called();export.assert_not_called()
                with patch.object(sys,'argv',['bsc-control','activate']),patch.object(c.os,'geteuid',return_value=0):
                    with self.assertRaises(c.Refused):c.main()
            finally:target.chmod(mode)
        self.assertEqual(self.calls,[])

    def test_expired_release_fences_the_whole_validator_without_new_miner_requests(self):
        self.signer();self.running=True
        with patch.object(c,'release_supported',return_value=False),patch.object(c,'signer_peer') as peer, \
             patch.object(c,'quiesce_writers',side_effect=lambda state:setattr(self,'running',False)) as drained:
            with self.assertRaises(c.Refused):c.activate(c.read_state())
            peer.assert_not_called();drained.assert_called_once()
        self.assertFalse(self.running);self.assertTrue(c.read_state()['startup_revoked'])

    def expired_original(self):
        self.signer();profile=c.catalog('mainnet')
        self.state.update(network='mainnet',version='1.7.8',commit=profile['releases']['1.7.8']['commit'],
                          snapshot=profile['recommended_snapshots']['full'])
        self.state.update(installed=c.pin(self.state),deploy_target=c.pin(self.state))
        c.save(self.state);self.running=True
        patch.object(c.time,'time',return_value=profile['network_upgrade']['activation_unix']+1).start()
        patch.object(c.os,'geteuid',return_value=0).start()
        self.original_files=[]
        for name in ('data/original-db','identity/original-peer','signer/original-vote-history'):
            path=c.ROOT/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'inert original '+name.encode())
            self.original_files.append((path,path.read_bytes(),path.stat().st_ino))
        return profile

    def timer(self):
        with patch.object(sys,'argv',['bsc-control','activate']):c.main()

    def assert_original_files(self):
        for path,raw,inode in self.original_files:
            self.assertEqual(path.read_bytes(),raw);self.assertEqual(path.stat().st_ino,inode)

    def test_actual_timer_drains_expired_original_despite_shared_run_lock_and_revokes_queued_intent(self):
        profile=self.expired_original();fd=os.open(c.OPERATION_ROOT,os.O_RDONLY)
        self.addCleanup(os.close,fd);c.fcntl.flock(fd,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
        def drain(state):
            self.assertEqual(c.contract(state),c.contract(self.state));self.running=False
        with patch.object(c,'quiesce_writers',side_effect=drain) as drained,patch.object(c,'rpc') as rpc:
            with self.assertRaises(c.Refused):self.timer()
            drained.assert_called_once();rpc.assert_not_called()
        self.assertFalse(self.running);self.assertTrue(c.read_state()['startup_revoked'])
        c.fcntl.flock(fd,c.fcntl.LOCK_UN)
        with self.assertRaises(c.Refused):c.locked(self.request('check-deploy'))
        self.assert_original_files()
        # A new explicit qualified update can recover the retained owner.
        fresh=dict(self.request('authorize-deploy'),version='1.8.2',commit=profile['releases']['1.8.2']['commit'],intent='b'*32)
        c.locked(fresh);c.locked(dict(fresh,action='begin-install'))
        c.locked(dict(fresh,action='finish-install',firewall={'run':'r-recovery','bundle':'c'*64}))
        self.assertEqual(c.read_state()['installed']['version'],'1.8.2')
        self.assertFalse(c.read_state()['startup_revoked']);self.assert_original_files()

    def test_actual_timer_retries_failed_drain_for_installed_and_installing_originals(self):
        profile=self.expired_original()
        for installing in (False,True):
            with self.subTest(installing=installing):
                state=dict(self.state,startup_revoked=False)
                if installing:
                    state.update(phase='installing',startup_revoked=True,
                                 target={'version':'1.8.2','commit':profile['releases']['1.8.2']['commit'],'config_id':state['config_id']})
                c.save(state);self.running=True
                with patch.object(c,'quiesce_writers',side_effect=c.Refused('inert writer still alive')) as drained:
                    with self.assertRaises(c.Refused):self.timer()
                    drained.assert_called_once()
                self.assertTrue(self.running);self.assertTrue(c.read_state()['startup_revoked'])
                with patch.object(c,'quiesce_writers',side_effect=lambda _:setattr(self,'running',False)) as drained,patch.object(c,'rpc') as rpc:
                    with self.assertRaises(c.Refused):self.timer()
                    drained.assert_called_once();rpc.assert_not_called()
                self.assertFalse(self.running)
                if installing:self.assertEqual(c.read_state()['target'],state['target'])
                with self.assertRaises(c.Refused):c.locked(self.request('check-deploy'))
                self.assert_original_files()

    def test_actual_timer_attempts_drain_after_fence_storage_failure_and_retries_after_repair(self):
        self.expired_original();fd=os.open(c.OPERATION_ROOT,os.O_RDONLY);self.addCleanup(os.close,fd)
        c.fcntl.flock(fd,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
        with patch.object(c,'save',side_effect=OSError('inert unavailable owner storage')), \
             patch.object(c,'quiesce_writers',side_effect=c.Refused('inert first drain failure')) as drained:
            with self.assertRaises(c.Refused):self.timer()
            drained.assert_called_once()
        self.assertIn(['systemctl','stop','--no-block','erpc-bsc-activation.timer',c.UNIT],self.calls)
        self.running=True
        with patch.object(c,'quiesce_writers',side_effect=lambda _:setattr(self,'running',False)) as drained:
            with self.assertRaises(c.Refused):self.timer()
            drained.assert_called_once()
        self.assertFalse(self.running);self.assertTrue(c.read_state()['startup_revoked']);self.assert_original_files()

    def test_contended_timer_never_activates_or_stops_a_supported_or_replaced_original(self):
        profile=self.expired_original();fd=os.open(c.OPERATION_ROOT,os.O_RDONLY);self.addCleanup(os.close,fd)
        c.fcntl.flock(fd,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
        upgraded=dict(self.state,version='1.8.2',commit=profile['releases']['1.8.2']['commit'])
        upgraded['installed']=c.pin(upgraded)
        for replace_after_first_read in (False,True):
            c.save(self.state if replace_after_first_read else upgraded)
            actual=c.read_state;reads=[]
            def read_state():
                value=actual();reads.append(True)
                if replace_after_first_read and len(reads)==1:c.save(upgraded)
                return value
            with patch.object(c,'read_state',side_effect=read_state),patch.object(c,'quiesce_writers') as drained,patch.object(c,'rpc') as rpc:
                with self.assertRaisesRegex(c.Refused,'another node operation'):self.timer()
                drained.assert_not_called();rpc.assert_not_called()
            self.assertFalse(c.read_state()['startup_revoked']);self.assertTrue(self.running)
        self.assert_original_files()

    def test_expiry_fence_file_and_directory_barrier_failures_still_drain_and_allow_repair(self):
        self.expired_original();real_fsync=os.fsync
        for point in (1,2):
            c.save(self.state);self.running=True;count=[]
            def fail_one(fd):
                count.append(True)
                if len(count)==point:raise OSError('inert owner publication barrier')
                return real_fsync(fd)
            with patch.object(os,'fsync',side_effect=fail_one), \
                 patch.object(c,'quiesce_writers',side_effect=lambda _:setattr(self,'running',False)) as drained:
                with self.assertRaisesRegex(c.Refused,'cannot persist validator fence'):self.timer()
                drained.assert_called_once()
            self.assertFalse(self.running)
            with self.assertRaises(c.Refused):c.locked(self.request('start'))
            with patch.object(c,'quiesce_writers') as drained:
                with self.assertRaises(c.Refused):self.timer()
                drained.assert_called_once()
            self.assertTrue(c.read_state()['startup_revoked'])
            with self.assertRaises(c.Refused):c.locked(self.request('check-deploy'))
            self.assert_original_files()

    def test_activation_uses_only_owned_private_miner_api_after_all_admission_checks(self):
        self.signer()
        good={'clock_synchronized':True,'node_ready':True,'registration':{'registered':True,'jailed':False}}
        cases=[(good,True,'miner_start'),(good,False,'miner_stop'),
               ({'node_ready':False,'registration':good['registration']},True,'miner_stop'),
               ({'node_ready':True,'registration':{'registered':False,'jailed':False}},True,'miner_stop'),
               ({'node_ready':True,'registration':{'registered':True,'jailed':True}},True,'miner_stop'),
               ({'inspection_error':'unavailable'},True,'miner_stop'),
               (dict(good,clock_synchronized=False),True,'miner_stop'),(dict(good,clock_synchronized=None),True,'miner_stop')]
        for observed,backup,method in cases:
            self.state['backup_confirmed']=backup;c.save(self.state)
            with patch.object(c,'signer_peer',return_value=(123,'99',995)),patch.object(c,'status',return_value=observed),patch.object(c,'rpc',return_value=False) as rpc:
                c.locked(self.request('activate'))
                self.assertEqual(rpc.call_args_list[0].args,(method,))
                self.assertTrue(all(call.kwargs=={'expected':(123,'99',995)} for call in rpc.call_args_list))

    def test_already_mining_signer_stops_when_signing_guard_fails(self):
        self.signer()
        mining=[True]
        def command(method,*,expected):
            self.assertEqual(expected,(123,'99',995))
            if method=='miner_stop':mining[0]=False;return None
            self.assertEqual(method,'eth_mining');return mining[0]
        for failing in ('capacity','firewall','artifacts'):
            mining[0]=True
            with self.subTest(failing=failing),patch.object(c,'signer_peer',return_value=(123,'99',995)),patch.object(c,failing,side_effect=c.Refused('unavailable')),patch.object(c,'rpc',side_effect=command) as rpc:
                self.assertEqual(c.locked(self.request('activate')),{'eligible':False})
                self.assertEqual([call.args[0] for call in rpc.call_args_list],['miner_stop','eth_mining'])
                self.assertFalse(mining[0])
        with patch.object(c,'signer_peer',return_value=(123,'99',995)),patch.object(c.validator,'guard',side_effect=c.Refused('missing signer or credential')),patch.object(c,'rpc',return_value=False) as rpc:
            self.assertEqual(c.locked(self.request('activate')),{'eligible':False})
            self.assertEqual([call.args[0] for call in rpc.call_args_list],['miner_stop','eth_mining'])

    def test_failed_miner_stop_or_identity_inspection_durably_fences_before_quiesce(self):
        self.signer()
        def quiesce(state):
            persisted=c.read_state()
            self.assertTrue(persisted['startup_revoked'])
            self.assertIsNone(persisted['deploy_intent']);self.assertIsNone(persisted['deploy_target'])
            raise c.Refused('owned writer refuses graceful stop')
        for failure in ('command','still-mining','ownership'):
            self.state.update(startup_revoked=False,deploy_intent='a'*32,deploy_target=c.pin(self.state));c.save(self.state)
            with self.subTest(failure=failure),patch.object(c,'signer_peer',side_effect=c.Refused('unknown owner') if failure=='ownership' else None,return_value=(123,'99',995)),patch.object(c,'guard',side_effect=c.Refused('ineligible')),patch.object(c,'rpc',side_effect=c.Refused('IPC failed') if failure=='command' else None,return_value=True) as rpc,patch.object(c,'quiesce_writers',side_effect=quiesce) as stopped:
                with self.assertRaises(c.Refused):c.locked(self.request('activate'))
                stopped.assert_called_once()
                if failure=='ownership':rpc.assert_not_called()
                self.assertTrue(c.read_state()['startup_revoked'])

    def test_failed_fence_write_still_attempts_owned_shutdown_and_cancels_timer(self):
        self.signer()
        with patch.object(c,'signer_peer',side_effect=c.Refused('unavailable')),patch.object(c,'save',side_effect=OSError('read-only storage')),patch.object(c,'run') as run,patch.object(c,'quiesce_writers') as stopped:
            with self.assertRaisesRegex(c.Refused,'cannot persist validator fence'):c.locked(self.request('activate'))
            run.assert_called_once_with(['systemctl','stop','--no-block','erpc-bsc-activation.timer',c.UNIT])
            stopped.assert_called_once()
        with patch.object(c,'signer_peer',side_effect=c.Refused('unavailable')),patch.object(c,'save',side_effect=OSError('no space')),patch.object(c,'run',side_effect=c.Refused('systemd unavailable')),patch.object(c,'quiesce_writers') as stopped:
            with self.assertRaises(c.Refused):c.locked(self.request('activate'))
            stopped.assert_called_once()

    def test_explicit_validator_stop_attempts_shutdown_when_first_and_checkpoint_writes_fail(self):
        self.signer();self.state['journal_bound']=True;c.save(self.state)
        original=c.save
        history=c.ROOT/'data/inert-history';history.parent.mkdir();history.write_bytes(b'original history')
        material=c.ROOT/'signer/inert-custody';material.parent.mkdir();material.write_bytes(b'original encrypted fixture')
        for failure_at in (1,2,'all'):
            c.save(self.state);self.running=True;self.calls.clear();attempts=[]
            def save(state):
                attempts.append(len(attempts)+1)
                if failure_at=='all' or len(attempts)==failure_at:raise OSError('inert custody checkpoint write failure')
                original(state)
            with patch.object(c,'save',side_effect=save),patch.object(c.validator,'journal',return_value=512):
                with self.assertRaises(c.Refused):c.locked(self.request('stop'))
            self.assertFalse(self.running)
            for unit in ('erpc-bsc-activation.timer','erpc-bsc-activation.service',c.UNIT):
                self.assertIn(['systemctl','stop',unit],self.calls)
            self.assertIn(['systemctl','disable','erpc-bsc-activation.timer'],self.calls)
            self.assertIn(['systemctl','disable',c.UNIT],self.calls)
            self.assertEqual(history.read_bytes(),b'original history')
            self.assertEqual(material.read_bytes(),b'original encrypted fixture')
            self.assertFalse(any('teardown' in call for call in self.calls))
            if failure_at!='all':
                saved=c.read_state();self.assertTrue(saved['startup_revoked'])
                self.assertIsNone(saved['deploy_intent']);self.assertEqual(saved['journal_checkpoint'],512)

    def test_foreign_validator_scope_never_enters_storage_error_recovery(self):
        self.signer();self.calls.clear()
        for action in ('stop','destroy'):
            for change in ({'owner':'foreign'},{'network':'mainnet'},{'operator':'0x'+'3'*40},{'role':'rpc'}):
                with patch.object(c,'save',side_effect=OSError('inert storage fault'))as saved,patch.object(c,'stop')as stopped,patch.object(c,'quiesce_writers')as drained:
                    with self.assertRaises(c.Refused):c.locked(dict(self.request(action),**change))
                    saved.assert_not_called();stopped.assert_not_called();drained.assert_not_called()
        self.assertFalse(self.calls)

    def test_observer_sandbox_permits_atomic_fence_but_not_signer_or_database_writes(self):
        import configparser
        unit=configparser.ConfigParser(interpolation=None)
        unit.read(SOURCE.with_name('erpc-bsc-activation.service'))
        self.assertEqual(unit['Service']['ProtectSystem'],'strict')
        writable=unit['Service']['ReadWritePaths'].split()
        readonly=unit['Service']['ReadOnlyPaths'].split()
        owner_root=Path('/var/lib/erpc-bsc')
        self.assertIn(str(owner_root),writable)
        for leaf in ('data','identity','signer'):self.assertIn('-'+str(owner_root/leaf),readonly)
        self.assertNotIn(str(owner_root),readonly)
        self.assertGreaterEqual(int(unit['Service']['TimeoutStartSec']),1800+120)

    def test_signer_authority_uses_reviewed_process_and_network_bound_ipc(self):
        self.signer();self.state['service_uid']=995
        profile=c.catalog('chapel')
        def rpc(method,params=None,*,expected=None):
            self.assertEqual(expected,(123,'99',995))
            return '0x61' if method=='eth_chainId' else {'hash':profile['genesis_hash']}
        with patch.object(c,'processes',return_value=[(123,'99')]),patch.object(c,'run',return_value=b'123'),patch.object(c,'rpc',side_effect=rpc):
            self.assertEqual(c.signer_peer(self.state),(123,'99',995))
        for writers,pid in (([],b'0'),([(123,'99'),(124,'88')],b'123'),([(123,'99')],b'456')):
            with patch.object(c,'processes',return_value=writers),patch.object(c,'run',return_value=pid),patch.object(c,'rpc')as rpc:
                with self.assertRaises(c.Refused):c.signer_peer(self.state)
                rpc.assert_not_called()
        with patch.object(c,'processes',return_value=[(123,'99')]),patch.object(c,'run',return_value=b'123'),patch.object(c,'rpc',return_value='0x38'):
            with self.assertRaises(c.Refused):c.signer_peer(self.state)

    def test_delayed_observer_cannot_revive_a_stopped_or_failed_installation(self):
        self.signer();old=self.request('activate')
        with patch.object(c,'stop'):c.locked(self.request('stop'))
        with patch.object(c,'rpc') as rpc:
            with self.assertRaises(c.Refused):c.locked(old)
            rpc.assert_not_called()
        state=c.read_state();state.update(phase='installing',startup_revoked=False);c.save(state)
        with patch.object(c,'rpc') as rpc:
            with self.assertRaises(c.Refused):c.locked(old)
            rpc.assert_not_called()

    def test_epoch_snapshot_is_hash_bound_and_unknown_observation_is_never_ready(self):
        self.signer();self.state['custody']={'consensus':'0x'+'3'*40,'vote':'4'*96,'proof':'0x'+'5'*192};c.save(self.state)
        profile=c.catalog('chapel');head={'number':'0x10','timestamp':hex(10000),'hash':'0x'+'b'*64}
        snapshot={'number':16,'hash':head['hash'],'validators':{'0x'+'3'*40:{'vote_address':[0x44]*48}}}
        word=lambda n:n.to_bytes(32,'big')
        answers={'059ddd22':bytes(12)+bytes.fromhex('3'*40),'6f8e2fa4':word(32)+word(48)+bytes.fromhex('4'*96)+bytes(16),'cbb04d9d':word(100)+word(0)+word(0)}
        def rpc(method,params=None):
            if method=='eth_getBlockByNumber':return {'hash':profile['genesis_hash']} if params[0]=='0x0' else head
            if method=='parlia_getSnapshotAtHash':self.assertEqual(params,[head['hash']]);return snapshot
            if method=='eth_call':
                self.assertEqual(params[1],{'blockHash':head['hash'],'requireCanonical':True})
                return '0x'+answers[params[0]['data'][2:10]].hex()
            return {'eth_chainId':'0x61','eth_syncing':False,'net_peerCount':'0x4','eth_mining':True,'admin_nodeInfo':{'id':'a'*64}}[method]
        with patch.object(c,'processes',return_value=[(123,'99')]),patch.object(c,'rpc',side_effect=rpc),patch.object(c,'run',return_value=b'123'),patch.object(c,'active',return_value='active'),patch.object(c.time,'time',return_value=10001):
            self.assertTrue(c.status(self.state)['ready'])
            snapshot['hash']='0x'+'c'*64
            self.assertFalse(c.status(self.state)['ready'])
            snapshot['hash']=head['hash'];snapshot['validators']={'0x'+'6'*40:{'vote_address':[0x66]*48}}
            result=c.status(self.state)
            self.assertTrue(result['node_ready']);self.assertTrue(result['validator_eligible']);self.assertFalse(result['ready'])
            snapshot['validators']={'0x'+'3'*40:{'vote_address':[]}}
            self.assertFalse(c.status(self.state)['ready'])

    def test_rpc_inventory_cannot_gain_authority_after_failed_validator_host_init(self):
        self.signer()
        for action in ('prepare','start','stop','destroy','begin-install'):
            request=dict(self.request(action),role='rpc')
            with patch.object(c,'stop') as stopped:
                with self.assertRaises(c.Refused):c.locked(request)
                stopped.assert_not_called()

    def test_foreign_operator_cannot_quiesce_or_restore_the_signer(self):
        self.signer()
        for action in ('stop','destroy','activate','export-custody','restore-custody','confirm-backup'):
            request=dict(self.request(action),operator='0x'+'9'*40)
            with patch.object(c,'stop') as stopped,patch.object(c,'quiesce_writers') as writers,patch.object(c,'rpc') as rpc:
                with self.assertRaises(c.Refused):c.locked(request)
                stopped.assert_not_called()
                writers.assert_not_called();rpc.assert_not_called()



class ProcessOwnership(unittest.TestCase):
    def test_private_ipc_rejects_replaced_peer_uid_pid_or_start_time_before_sending(self):
        from unittest.mock import MagicMock
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'data';data.mkdir();(data/'geth.ipc').touch()
            proc=root/'proc';(proc/'123').mkdir(parents=True)
            stat=proc/'123/stat';stat.write_text('123 (geth) '+' '.join(['0']*19+['99']))
            with patch.object(c,'ROOT',root),patch.object(c,'PROC',proc),patch.object(c.socket,'SO_PEERCRED',17,create=True):
                for pid,uid,start in ((123,995,'99'),(456,995,'99'),(123,996,'99'),(123,995,'100')):
                    connection=MagicMock();connection.getsockopt.return_value=c.struct.pack('3i',pid,uid,995)
                    connection.recv.return_value=b'{"jsonrpc":"2.0","id":1,"result":false}\n'
                    manager=MagicMock();manager.__enter__.return_value=connection
                    stat.write_text('123 (geth) '+' '.join(['0']*19+[start]))
                    with patch.object(c.socket,'socket',return_value=manager):
                        if (pid,uid,start)==(123,995,'99'):
                            self.assertIs(c.rpc('miner_stop',expected=(123,'99',995)),False)
                            connection.sendall.assert_called_once()
                        else:
                            with self.assertRaises(c.Refused):c.rpc('miner_stop',expected=(123,'99',995))
                            connection.sendall.assert_not_called()
                    connection.getsockopt.assert_called_once_with(c.socket.SOL_SOCKET,17,12)

    def test_scanner_requires_the_exact_data_identity_uid_and_reviewed_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);data=root/'state';opt=root/'opt';proc=root/'proc';entry=proc/'123'
            entry.mkdir(parents=True)
            profile=json.loads(CATALOG.read_text())['chapel']
            selected=profile['releases'][profile['recommended']]
            binary=opt/profile['recommended']/'amd64/geth';binary.parent.mkdir(parents=True);binary.write_bytes(b'synthetic executable bytes; never run')
            selected['binaries']['amd64']['sha256']=hashlib.sha256(binary.read_bytes()).hexdigest()
            state={'owner':'owned','network':'chapel','role':'rpc','platform':'amd64','storage':'full','snapshot':profile['recommended_snapshots']['full'],'version':profile['recommended'],'commit':selected['commit'],'config_id':'a'*64,'service_uid':os.getuid()}
            (entry/'exe').symlink_to(binary)
            (entry/'stat').write_text('123 (geth) S '+'0 '*18+'99 0')
            with patch.object(c,'ROOT',data),patch.object(c,'OPT',opt),patch.object(c,'PROC',proc),patch.object(c,'catalog',return_value=profile):
                for args in [[str(binary),'--datadir='+str(data/'data')],[str(binary),'--datadir',str(data/'data')]]:
                    (entry/'cmdline').write_bytes(b'\0'.join(v.encode() for v in args))
                    self.assertEqual(c.processes(state),[(123,'99')])
                with self.assertRaises(c.Refused):c.processes(dict(state,service_uid=os.getuid()+1))
                binary.write_bytes(b'tampered executable')
                with self.assertRaises(c.Refused):c.processes(state)
                (entry/'cmdline').write_bytes(b'other-program\0--datadir=/unrelated')
                self.assertEqual(c.processes(state),[])


if __name__=='__main__':unittest.main()
