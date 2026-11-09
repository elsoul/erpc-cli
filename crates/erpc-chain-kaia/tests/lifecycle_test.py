# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Real lifecycle functions with inert process/artifact fixtures, no node execution."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
SOURCE=Path(__file__).parents[1]/'templates/node/control.py'
spec=importlib.util.spec_from_file_location('kaia_control',SOURCE)
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
with patch.object(c,'trusted_imports',side_effect=lambda directory:sys.path.append(str(directory))):c.load_dependencies()


class Lifecycle(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup);self.addCleanup(patch.stopall)
        root=Path(folder.name)
        patch.object(c,'TRUST_ANCHOR',root).start()
        mounts=root/'mountinfo';mounts.write_text('1 0 0:0 / / rw - ext4 /dev/fixture rw\n')
        patch.object(c,'MOUNTINFO',mounts).start()
        for name,path in (('ROOT',root/'data-root'),('CONF',root/'config'),('HELPERS',root/'helpers'),('LAUNCHER',root/'launcher'),('UNIT_DIRECTORY',root/'units'),('PROC',root/'proc'),('LOCK',root/'lock'),('OPERATION_ROOT',root/'operation')):
            patch.object(c,name,path).start()
        c.PROC.mkdir();c.OPERATION_ROOT.mkdir()
        # A Docker engine on the machine running the tests is not this fixture's.
        patch.object(c,'DOCKER',[str(root/'docker'),'--host=unix:///var/run/docker.sock']).start()
        for name in ('DOCKER_SOCKET','DOCKER_CONTAINERS','DOCKER_CONFIG','DOCKER_OVERRIDES'):
            patch.object(c,name,root/name.lower()).start()
        patch.object(c,'ROOT_UID',os.getuid()).start()
        patch.object(c,'account').start()
        patch.object(c.os,'chown').start()
        patch.object(c.pwd,'getpwnam',side_effect=KeyError).start()
        patch.object(c.grp,'getgrnam',side_effect=KeyError).start()
        self.free=20_000_000_000_000;self.allocated=0;self.active=False;self.loaded=False;self.container=None;self.calls=[];self.docker_root=b''
        patch.object(c.shutil,'disk_usage',side_effect=lambda _:SimpleNamespace(free=self.free)).start()
        patch.object(c,'check_container',side_effect=lambda _:copy.deepcopy(self.container)).start()
        patch.object(c,'run',side_effect=self.command).start()
        patch.object(c,'verify_image').start();patch.object(c,'firewall').start()
        self.state={'owner':'fixture','network':'kairos','role':'rpc','platform':'amd64','storage':'full','snapshot':'genesis','image':c.CATALOG['image'],'genesis':c.CATALOG['networks']['kairos']['genesis'],'version':c.CATALOG['version'],'commit':c.CATALOG['commit'],'config_id':'a'*64}
        c.prepare(self.request('prepare'));self.state=c.state_read()

    def request(self,action):
        return dict(self.state,action=action,intent='b'*32,service_uid=995,service_gid=995)

    def command(self,args,**kwargs):
        self.calls.append(args)
        if args[:2]==['systemctl','show']:return b'loaded' if self.loaded and 'LoadState' in args[2] else b'not-found' if 'LoadState' in args[2] else b'0'
        if args[:2]==['systemctl','is-active']:return b'active' if self.active else b'inactive'
        if args[:2]==['systemctl','stop']:self.active=False
        if args[:2]==['systemctl','start']:self.active=True
        if args[:2]==['/usr/bin/du','-sx']:return str(self.allocated).encode()+b' fixture'
        if args==[*c.DOCKER,'info','--format','{{.DockerRootDir}}']:return self.docker_root
        if args[:3]==[*c.DOCKER,'container'] and 'kill' in args:
            self.container['State'].update(Running=False,Pid=0)
        if args[:3]==[*c.DOCKER,'container'] and 'rm' in args:self.container=None
        return b''

    def begin(self):
        c.locked(self.request('authorize-deploy'));c.locked(self.request('begin-install'))
        self.state=c.state_read()

    def test_fresh_helper_ancestor_refuses_writable_or_indirect_paths_before_reservation(self):
        (c.ROOT/'owner.json').unlink();c.ROOT.rmdir();self.calls.clear()
        parent=c.TRUST_ANCHOR/'lib';parent.mkdir();parent.chmod(0o777)
        with patch.object(c,'HELPERS',parent/'missing'):
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
            self.assertFalse(c.ROOT.exists());self.assertEqual(parent.stat().st_mode&0o777,0o777)
            parent.chmod(0o755);parent.rmdir()
            outside=c.TRUST_ANCHOR/'outside';outside.mkdir();parent.symlink_to(outside,target_is_directory=True)
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
            self.assertFalse(c.ROOT.exists());self.assertFalse(any(outside.iterdir()))
        self.assertEqual(self.calls,[])

    def test_owner_receipts_reject_links_and_permission_drift_without_overwrite(self):
        owner=c.ROOT/'owner.json';before=owner.read_bytes();self.calls.clear()
        alias=c.ROOT/'alias';os.link(owner,alias)
        for operation in (lambda:c.state_read(),lambda:c.save(self.state)):
            with self.assertRaises(c.Refused):operation()
        alias.unlink();owner.chmod(0o644)
        with self.assertRaises(c.Refused):c.state_read()
        owner.chmod(0o600);pending=c.ROOT/'owner.new';pending.symlink_to(owner)
        with self.assertRaises(c.Refused):c.save(self.state)
        self.assertTrue(pending.is_symlink());self.assertEqual(owner.read_bytes(),before)
        self.assertEqual(self.calls,[])

    def test_unit_and_dropin_drift_is_refused_before_every_mutator(self):
        self.calls.clear();c.UNIT_DIRECTORY.mkdir()
        for unit in c.owned_units():
            directory=c.UNIT_DIRECTORY/(unit+'.d');directory.mkdir()
            foreign=directory/'99-foreign.conf';foreign.write_text('[Service]\nExecStartPre=\n');foreign.chmod(0o644)
            for action in ('prepare','authorize-deploy','begin-install','stop','destroy'):
                with self.assertRaises(c.Refused):c.locked(self.request(action))
            foreign.unlink();pending=directory/'50-erpc-firewall-guard.conf.new';pending.write_text('inert pending guard')
            self.assertEqual(c.state_read()['owner'],self.state['owner'])
            pending.chmod(0o666)
            with self.assertRaises(c.Refused):c.state_read()
            pending.unlink();directory.rmdir()
        c.LAUNCHER.write_text('inert launcher');c.LAUNCHER.chmod(0o666)
        with self.assertRaises(c.Refused):c.state_read()
        self.assertEqual(self.calls,[])

    def test_publication_matches_both_complete_revision_and_legacy_launcher(self):
        import hashlib
        source=c.TRUST_ANCHOR/'source';source.mkdir()
        for name,raw in (('control.py',b'inert controller'),('bootstrap.py',b'inert bootstrap'),('custody.py',b'inert custody'),('corecell.py',b'inert corecell'),('coreaccount.py',b'inert account'),('catalog.json',b'{}')):
            (source/name).write_bytes(raw)
        digest=hashlib.sha256(b''.join((source/name).read_bytes() for name in c.HELPER_PROFILE)).hexdigest()
        target=c.HELPERS/'releases'/digest;target.mkdir(parents=True)
        for file in source.iterdir():(target/file.name).write_bytes(file.read_bytes())
        (source/'launcher.py').write_text('inert launcher');c.LAUNCHER.write_text('inert launcher')
        (c.HELPERS/'current').symlink_to(target,target_is_directory=True)
        with patch.object(c,'__file__',str(source/'control.py')):
            self.assertEqual(c.locked(self.request('verify-helpers')),{'helpers':'verified'})
            c.LAUNCHER.write_text('substituted launcher')
            with self.assertRaises(c.Refused):c.locked(self.request('verify-helpers'))
            c.LAUNCHER.write_text('inert launcher');(target/'control.py').write_text('substituted controller')
            with self.assertRaises(c.Refused):c.locked(self.request('verify-helpers'))

    def test_checked_controller_refuses_writable_common_helper_before_import(self):
        path=c.HELPERS.parent/'rpc-firewall.py';marker=c.TRUST_ANCHOR/'firewall-imported'
        path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("imported")\nclass Firewall:\n def __init__(self,family):assert family=="kaia"\n def dispatch(self,*args):assert args==("load",)\n')
        path.chmod(0o644)
        with patch.object(sys,'argv',['control','firewall-load']),patch.object(c.os,'geteuid',return_value=0):
            c.main();self.assertTrue(marker.exists());marker.unlink()
            path.chmod(0o666)
            with self.assertRaises(c.Refused):c.main()
            self.assertFalse(marker.exists())

    def test_firewall_boot_leaves_lock_ownership_to_actual_common_load(self):
        import hashlib,subprocess,fcntl
        source=SOURCE.parents[3]/'erpc-ops/templates/rpc-firewall.py'
        spec=importlib.util.spec_from_file_location('kaia_boot_common',source)
        common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
        operation=c.TRUST_ANCHOR/'opt/erpc';operation.mkdir(parents=True)
        calls=[];live=[False]
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[:3]==['nft','-j','list']:
                if not live[0]:raise subprocess.CalledProcessError(1,argv)
                return subprocess.CompletedProcess(argv,0,b'{"nftables":[]}',b'')
            if argv[:2]==['nft','-f']:
                descriptor=os.open(operation,os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(descriptor)
                live[0]=True
            return subprocess.CompletedProcess(argv,0,b'',b'')
        fw=common.Firewall('kaia',c.TRUST_ANCHOR,run);fw.directory.mkdir(parents=True)
        policy=b'inert policy';(fw.directory/'firewall.nft').write_bytes(policy)
        (fw.directory/'confirmed.json').write_text(json.dumps({'contract':'kaia','file':hashlib.sha256(policy).hexdigest(),
            'live':fw.digest(json.dumps({'nftables':[]},sort_keys=True).encode())}))
        with patch.object(c,'firewall_controller',return_value=fw),patch.object(c.os,'geteuid',return_value=0),patch.object(sys,'argv',['control','firewall-load']):
            c.main();c.main();self.assertTrue(live[0]);self.assertEqual(sum(x[:2]==['nft','-f'] for x in calls),1)
            live[0]=False;descriptor=os.open(operation,os.O_RDONLY)
            try:
                fcntl.flock(descriptor,fcntl.LOCK_EX)
                with self.assertRaises(BlockingIOError):c.main()
            finally:os.close(descriptor)
            self.assertFalse(live[0])

    def test_storage_and_unit_stop_failure_still_drains_owned_container_and_disables(self):
        for action in ('stop','destroy'):
            self.loaded=True;self.active=True;self.container={'Id':'d'*64,'State':{'Running':True,'Pid':123}};self.calls.clear()
            original=self.command
            def failed_unit(args,**kwargs):
                if args[:2]==['systemctl','stop']:
                    self.calls.append(args);raise c.Refused('inert unit stop failure')
                return original(args,**kwargs)
            with patch.object(c,'run',side_effect=failed_unit),patch.object(c,'save',side_effect=OSError('inert full storage')):
                with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request(action))
            self.assertIsNone(self.container)
            self.assertIn([*c.DOCKER,'container','kill','--signal=SIGTERM','d'*64],self.calls)
            self.assertIn(['systemctl','disable',c.UNIT],self.calls)
        self.loaded=True;self.calls.clear()
        with patch.object(c,'save',side_effect=OSError('inert storage')),patch.object(c,'stop',side_effect=c.Refused('inert service failure')),patch.object(c,'stop_container',side_effect=c.Refused('ambiguous owner')):
            with self.assertRaisesRegex(c.Refused,'owned container drain'):c.locked(self.request('stop'))
        self.assertIn(['systemctl','disable',c.UNIT],self.calls)
        self.assertFalse(any('kill' in args for args in self.calls))

    def test_transient_real_fsync_failures_retry_after_shutdown_without_success_claim(self):
        original=c.os.fsync
        for failure in (1,2):
            for action in ('stop','destroy'):
                c.save(self.state);self.loaded=True;self.active=True;self.calls.clear();count=0
                def fsync(fd):
                    nonlocal count
                    count+=1
                    if count==failure:raise OSError('inert fsync failure')
                    return original(fd)
                with self.subTest(failure=failure,action=action),patch.object(c.os,'fsync',side_effect=fsync):
                    with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request(action))
                self.assertFalse(self.active);self.assertIn(['systemctl','disable',c.UNIT],self.calls)
                self.assertTrue(c.state_read()['startup_revoked']);self.assertIsNone(c.state_read()['deploy_intent'])

    def test_foreign_scope_never_reaches_failed_write_container_fallback(self):
        self.calls.clear()
        for action in ('stop','destroy'):
            with patch.object(c,'save',side_effect=OSError('inert storage'))as saved,patch.object(c,'stop')as stopped,patch.object(c,'stop_container')as drained:
                with self.assertRaises(c.Refused):c.locked(dict(self.request(action),owner='foreign'))
                saved.assert_not_called();stopped.assert_not_called();drained.assert_not_called()
        self.assertEqual(self.calls,[])

    def test_foreign_owner_network_genesis_role_or_storage_never_stops_an_owned_node(self):
        for change in ({'owner':'other'},{'network':'mainnet'},{'genesis':'0x'+'f'*64},{'role':'validator'},{'storage':'pruned'},{'platform':'arm64'}):
            for action in ('stop','destroy','begin-install','install-artifacts','start'):
                with self.subTest(change=change,action=action),patch.object(c,'stop')as stopped:
                    with self.assertRaises(c.Refused):c.locked(dict(self.request(action),**change))
                    stopped.assert_not_called()

    def test_orphan_container_is_gracefully_stopped_by_immutable_id_without_force_kill(self):
        self.container={'Id':'d'*64,'State':{'Running':True,'Pid':123}}
        self.begin()
        signals=[a for a in self.calls if 'kill'in a]
        self.assertEqual(signals,[[*c.DOCKER,'container','kill','--signal=SIGTERM','d'*64]])
        self.assertIsNone(self.container);self.assertTrue(c.state_read()['startup_revoked'])

    def test_untracked_dedicated_account_writer_blocks_artifact_mutation(self):
        self.begin();self.state['service_uid']=os.getuid();self.state['service_gid']=995;c.save(self.state)
        (c.PROC/'123').mkdir()
        with self.assertRaises(c.Refused):c.stop_container(self.state)
        self.assertFalse(any('pull'in a for a in self.calls))

    def test_failed_install_stop_still_allows_explicit_shutdown_and_cancels_queued_stages(self):
        c.locked(self.request('authorize-deploy'))
        with patch.object(c,'stop',side_effect=c.Refused('inert failed stop')):
            with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))
        self.assertEqual(c.state_read()['phase'],'installing')
        c.locked(self.request('stop'))
        for action in ('begin-install','install-artifacts','finish-install'):
            with self.assertRaises(c.Refused):c.locked(self.request(action))
        c.locked(self.request('destroy'));self.assertEqual(c.state_read()['phase'],'retired')

    def test_full_genesis_and_peer_identity_survive_install_retries_without_new_entropy(self):
        self.begin()
        with patch.object(c.secrets,'token_bytes',return_value=bytes([1])*32)as entropy:
            c.locked(self.request('install-artifacts'));self.assertEqual(entropy.call_count,1)
            c.locked(self.request('install-artifacts'));self.assertEqual(entropy.call_count,1)
        self.state=c.state_read();peer=(c.ROOT/'identity/nodekey').read_bytes()
        history=c.ROOT/'data/klay/chaindata/native-fixture';history.write_text('advanced native database')
        with patch.object(c.secrets,'token_bytes',side_effect=AssertionError('replacement key forbidden')):
            c.locked(self.request('install-artifacts'))
        self.assertEqual(history.read_text(),'advanced native database');self.assertEqual((c.ROOT/'identity/nodekey').read_bytes(),peer)
        (c.ROOT/'identity/nodekey').unlink()
        with self.assertRaises(c.Refused):c.locked(self.request('install-artifacts'))

    def test_capacity_failure_does_not_disable_recovery_stop_or_retirement(self):
        self.begin();self.free=1
        with self.assertRaises(c.Refused):c.locked(self.request('install-artifacts'))
        c.locked(self.request('stop'));c.locked(self.request('destroy'))
        self.assertEqual(c.state_read()['phase'],'retired')

    def test_failed_fence_storage_still_attempts_owned_stop_without_success_claim(self):
        self.begin()
        with patch.object(c,'save',side_effect=OSError('inert full storage')),patch.object(c,'stop')as stopped:
            with self.assertRaisesRegex(c.Refused,'cancellation storage'):c.locked(self.request('stop'))
            stopped.assert_called_once()
        with patch.object(c,'check_container',side_effect=c.Refused('foreign or uninspectable container')):
            with self.assertRaises(c.Refused):c.locked(self.request('stop'))
        self.assertTrue(c.state_read()['startup_revoked'])

    def test_docker_filesystem_headroom_is_separate_from_the_data_budget(self):
        def usage(path):
            data = c.ROOT == path or c.ROOT in Path(path).parents
            return SimpleNamespace(free=20_000_000_000_000 if data else 3*1024**3)
        with patch.object(c.shutil,'disk_usage',side_effect=usage):
            c.capacity(self.state)
            with self.assertRaises(c.Refused):c.capacity(self.state,installation=True)

    def docker(self):
        """The fixture's own Docker binary and socket; `docker info` answers self.docker_root."""
        Path(c.DOCKER[0]).touch();c.DOCKER_SOCKET.touch()

    def test_docker_root_dir_answer_is_where_engine_headroom_is_required(self):
        engine=c.TRUST_ANCHOR/'engine';engine.mkdir();self.docker();self.docker_root=str(engine).encode()+b'\n'
        def usage(path):return SimpleNamespace(free=3*1024**3 if Path(path)==engine else 20_000_000_000_000)
        with patch.object(c.shutil,'disk_usage',side_effect=usage):
            c.capacity(self.state)
            with self.assertRaisesRegex(c.Refused,'insufficient Docker/OS artifact headroom'):c.capacity(self.state,installation=True)
        self.assertIn([*c.DOCKER,'info','--format','{{.DockerRootDir}}'],self.calls)

    def test_empty_relative_or_unnormalized_docker_root_dir_is_refused(self):
        self.docker()
        for answer in (b'\n',b'var/lib/docker\n',b'/var/lib/../lib/docker\n',b'/var//lib/docker\n',b'/var/lib/docker/\n'):
            with self.subTest(answer=answer):
                self.docker_root=answer
                with self.assertRaisesRegex(c.Refused,'Docker storage location is unavailable or ambiguous'):c.capacity(self.state)

    def test_prepare_records_a_fresh_docker_installation_only_without_a_binary(self):
        self.assertIs(self.state['docker_fresh_install'],True)
        (c.ROOT/'owner.json').unlink();c.ROOT.rmdir();Path(c.DOCKER[0]).touch()
        c.prepare(self.request('prepare'))
        self.assertIs(c.state_read()['docker_fresh_install'],False)

    def test_ready_requires_owned_stable_process_and_qualified_fresh_chain(self):
        self.active=True
        self.container={'Id':'d'*64,'State':{'Running':True,'Pid':123,'StartedAt':'fixture-generation'}}
        replies={'eth_chainId':hex(c.network(self.state)['chain_id']),
                 'eth_syncing':False,'net_peerCount':'0x3'}
        def rpc(method,params=None):
            if method=='eth_getBlockByNumber':
                return {'hash':c.network(self.state)['genesis']} if params[0]=='0x0' else {'number':'0x123','timestamp':hex(int(c.time.time()))}
            return replies[method]
        with patch.object(c,'guard'),patch.object(c,'owned_ports',return_value=True),patch.object(c,'rpc',side_effect=rpc):
            self.assertTrue(c.status(self.state)['ready'])
            replies['eth_chainId']='0x1';self.assertFalse(c.status(self.state)['ready'])
            replies['eth_chainId']=hex(c.network(self.state)['chain_id'])
            with patch.object(c,'owned_ports',return_value=False):self.assertFalse(c.status(self.state)['ready'])
            changed=copy.deepcopy(self.container);changed['State']['StartedAt']='replacement-generation'
            with patch.object(c,'check_container',side_effect=[self.container,changed]):
                self.assertFalse(c.status(self.state)['ready'])
            self.active=False;self.assertFalse(c.status(self.state)['ready'])

    def test_untrusted_empty_root_and_ancestor_cannot_create_owner_or_adopt_state(self):
        (c.ROOT/'owner.json').unlink()
        for path in (c.ROOT,c.TRUST_ANCHOR):
            original=path.stat().st_mode & 0o777;path.chmod(0o777)
            try:
                with self.assertRaises(c.Refused):c.prepare(self.request('prepare'))
                self.assertFalse((c.ROOT/'owner.json').exists())
                self.assertEqual(path.stat().st_mode & 0o777,0o777)
            finally:path.chmod(original)
        original_stat=Path.lstat
        def foreign_root(path,*args,**kwargs):
            result=original_stat(path,*args,**kwargs)
            if path==c.ROOT:
                fields=list(result);fields[4]+=1;return os.stat_result(fields)
            return result
        with patch.object(Path,'lstat',foreign_root):
            with self.assertRaises(c.Refused):c.prepare(self.request('prepare'))
        self.assertFalse((c.ROOT/'owner.json').exists())

    def test_owner_directory_permission_drift_refuses_every_privileged_lifecycle(self):
        for path in (c.ROOT,c.TRUST_ANCHOR):
            original=path.stat().st_mode & 0o777;path.chmod(0o777)
            try:
                for action in ('authorize-deploy','begin-install','start','stop','destroy'):
                    with self.assertRaises(c.Refused):c.locked(self.request(action))
                with self.assertRaises(c.Refused):c.save(self.state)
            finally:path.chmod(original)
        with patch.object(c,'ROOT_UID',os.getuid()+1):
            with self.assertRaises(c.Refused):c.state_read()
        alias=c.TRUST_ANCHOR/'alias';alias.symlink_to(c.TRUST_ANCHOR,target_is_directory=True)
        with patch.object(c,'ROOT',alias/c.ROOT.name):
            with self.assertRaises(c.Refused):c.state_read()
        self.assertFalse(any('kill' in argv or 'stop' in argv for argv in self.calls))

    def test_nested_native_database_filesystem_cannot_borrow_parent_free_space(self):
        data=c.ROOT/'data/klay/chaindata';data.mkdir(parents=True)
        original=Path.stat
        def different_device(path,*args,**kwargs):
            value=original(path,*args,**kwargs)
            if path==data:
                fields=list(value);fields[2]+=1;return os.stat_result(fields)
            return value
        c.locked(self.request('authorize-deploy'))
        with patch.object(Path,'stat',different_device):
            with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))
            installed=dict(self.state,phase='installed',installed=c.pin(self.state),startup_revoked=False)
            with self.assertRaises(c.Refused):c.guard(installed)
            for installing in (False,True):
                with self.assertRaises(c.Refused):c.capacity(self.state,installation=installing)
            c.locked(self.request('stop'))
            c.locked(self.request('destroy'))
        self.assertEqual(c.state_read()['phase'],'retired')

    def test_same_device_bind_mounts_and_nested_bootstrap_mounts_are_rejected(self):
        for relative in ('data','data/klay/chaindata','data/klay/chaindata/subtree',
                         'snapshot-stage/klay/chaindata','snapshot-downloads/cache'):
            path=c.ROOT/relative;path.mkdir(parents=True,exist_ok=True)
            c.MOUNTINFO.write_text('1 0 0:0 / / rw - ext4 /dev/fixture rw\n2 1 0:0 / '+str(path)+' rw - ext4 /dev/fixture rw\n')
            with self.assertRaises(c.Refused):c.capacity(self.state)
            with self.assertRaises(c.Refused):c.capacity(self.state,installation=True)
        # A mount at the managed root itself is a supported dedicated disk.
        c.MOUNTINFO.write_text('1 0 0:0 / / rw - ext4 /dev/fixture rw\n2 1 0:0 / '+str(c.ROOT)+' rw - ext4 /dev/fixture rw\n')
        c.capacity(self.state)
        c.MOUNTINFO.write_text('unreadable topology')
        with self.assertRaises(c.Refused):c.capacity(self.state)
        c.locked(self.request('stop'))

    def test_missing_owner_cannot_adopt_staged_identity_or_retained_data(self):
        (c.ROOT/'owner.json').unlink();(c.ROOT/'identity').mkdir();(c.ROOT/'identity/nodekey.new').write_bytes(b'inert orphan')
        with self.assertRaises(c.Refused):c.prepare(self.request('prepare'))
        self.assertFalse((c.ROOT/'owner.json').exists())

    def test_client_arguments_use_builtin_network_and_full_database_without_public_admin(self):
        for network in ('mainnet','kairos'):
            for storage in ('pruned','full'):
                args=c.arguments(dict(self.state,network=network,storage=storage))
                self.assertIn('--'+network,args)
                # Pinned nodeflags.go does not register NodeTypeFlag; ken main sets EN internally.
                self.assertFalse(any(value.startswith('--nodetype') for value in args))
                self.assertIn('--auction.disable',args)
                self.assertNotIn('--gasless.disable',args)  # CN-only flag is not accepted by ken.
                self.assertIn('--state.live-pruning='+str(storage=='pruned').lower(),args)
                self.assertFalse(any('networkid' in a or 'unlock' in a or 'admin' in a or 'personal' in a for a in args))
                self.assertIn('--rpcaddr=127.0.0.1',args);self.assertIn('--wsaddr=127.0.0.1',args)

    def test_future_catalog_authorization_is_bounded_but_only_new_carried_code_executes_it(self):
        future=dict(self.request('authorize-deploy'),version='3.0.0',commit='e'*40,image='docker.io/kaiachain/kaia@sha256:'+'f'*64)
        c.locked(future)
        with patch.object(c,'stop')as stop:
            with self.assertRaises(c.Refused):c.locked(dict(future,action='begin-install'))
            stop.assert_not_called()
        catalog=copy.deepcopy(c.CATALOG);catalog.update(version=future['version'],commit=future['commit'],image=future['image'])
        with patch.object(c,'CATALOG',catalog):
            c.locked(dict(future,action='begin-install'))
        self.assertEqual(c.state_read()['target']['version'],'3.0.0')
        c.locked(self.request('stop'))
        self.assertTrue(c.state_read()['startup_revoked'])


class ContainerOwnership(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(folder.name);binary=self.root/'docker';binary.touch()
        patch.object(c,'DOCKER',[str(binary),'--host=unix:///var/run/docker.sock']).start()
        for name in ('DOCKER_SOCKET','DOCKER_CONTAINERS','DOCKER_CONFIG','DOCKER_OVERRIDES'):
            patch.object(c,name,self.root/name.lower()).start()
        self.state={'owner':'fixture','network':'kairos','role':'rpc','phase':'installed'}
        self.inspect={'Id':'d'*64,'Config':{'Labels':{'erpc.owner':'fixture','erpc.network':'kairos','erpc.role':'rpc'}},'State':{'Running':True,'Pid':123}}
        self.calls=[]
        def command(args,**_):
            self.calls.append(args)
            return b'erpc-kaia\n' if 'ls'in args else json.dumps([self.inspect]).encode()
        patch.object(c,'run',side_effect=command).start()

    def test_foreign_container_labels_are_never_stop_or_remove_authority(self):
        self.assertEqual(c.check_container(self.state)['Id'],'d'*64)
        for key in ('owner','network','role'):
            old=self.inspect['Config']['Labels']['erpc.'+key]
            self.inspect['Config']['Labels']['erpc.'+key]='another'
            with self.assertRaises(c.Refused):c.check_container(self.state)
            self.inspect['Config']['Labels']['erpc.'+key]=old
        self.assertFalse(any('kill'in args or 'rm'in args for args in self.calls))

    def test_absent_docker_binary_refuses_retained_container_state_without_inspection(self):
        Path(c.DOCKER[0]).unlink();self.assertIsNone(c.check_container(self.state))
        c.DOCKER_CONTAINERS.mkdir()
        with self.assertRaisesRegex(c.Refused,'uninspected Docker state requires operator recovery'):c.check_container(self.state)
        self.assertEqual(self.calls,[])

    def test_interrupted_fresh_docker_package_can_resume_but_existing_state_cannot_hide(self):
        fresh=dict(self.state,phase='prepared',docker_fresh_install=True)
        self.assertIsNone(c.check_container(fresh));self.assertFalse(self.calls)
        c.DOCKER_CONTAINERS.mkdir();(c.DOCKER_CONTAINERS/'orphan').mkdir()
        with self.assertRaises(c.Refused):c.check_container(fresh)
        (c.DOCKER_CONTAINERS/'orphan').rmdir();c.DOCKER_CONFIG.write_text('{}')
        with self.assertRaises(c.Refused):c.check_container(fresh)
        c.DOCKER_CONFIG.unlink()
        with patch.object(c,'run',side_effect=c.Refused('daemon unavailable')):
            with self.assertRaises(c.Refused):c.check_container(self.state)


class LocalObserver(unittest.TestCase):
    def test_actual_http_redirect_is_refused_before_following_another_local_resource(self):
        import http.server
        import threading
        seen=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.path);self.send_response(302)
                self.send_header('Location','/unexpected');self.end_headers()
            def do_GET(self):
                seen.append(self.path);self.send_response(200);self.end_headers()
            def log_message(self,*args):pass
        server=http.server.HTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            with self.assertRaises(c.Refused):c.rpc('eth_chainId',port=server.server_port)
            self.assertEqual(seen,['/'])
        finally:server.shutdown();thread.join();server.server_close()


if __name__=='__main__':unittest.main()
