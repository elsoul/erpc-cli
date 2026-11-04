# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Offline Nitro control failures; no container, node, provider or key is run."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).parents[1] / 'templates/node/control.py'
spec = importlib.util.spec_from_file_location('nitro_control', SOURCE)
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class Lifecycle(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.addCleanup(patch.stopall)
        root = Path(folder.name)
        patch.object(c, 'ROOT', root / 'state').start()
        patch.object(c, 'CONF', root / 'config').start()
        patch.object(c, 'LOCK', root / 'lock').start()
        patch.object(c, 'OPERATION_ROOT', root).start()
        c.ROOT.mkdir();c.CONF.mkdir();(c.ROOT / 'data').mkdir()
        self.state = {'owner':'ownedhost','family':'arbitrum','network':'sepolia','platform':'amd64',
                      'version':c.VERSION,'commit':c.COMMIT,'config_id':'a'*64,'phase':'installed',
                      'service_uid':995,'service_gid':996,'firewall':{'run':'r-fixture','bundle':'b'*64}}
        self.state['installed'] = c.pin(self.state)
        c.save(self.state)
        (c.ROOT / 'data/chain-fixture').write_text('retained chain state')
        (c.CONF / 'l1-upstreams.cred').write_bytes(b'encrypted fixture')
        self.calls = []
        self.running = True
        self.free = 10_000_000_000_000
        patch.object(c.shutil, 'disk_usage', side_effect=lambda _: type('Usage',(),{'free':self.free})()).start()
        patch.object(c, 'check_container', return_value=None).start()
        patch.object(c, 'artifacts').start()
        patch.object(c, 'rpc', side_effect=c.Refused('fixture RPC unavailable')).start()
        def run(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if argv[:2] == ['du','-sx']: return b'0 data'
            if argv[:2] == ['systemctl','show']:
                return b'loaded' if 'LoadState' in argv[2] else b'0'
            if argv[:2] == ['systemctl','is-active']: return b'active' if self.running else b'inactive'
            if argv[:2] == ['systemctl','stop']: self.running = False
            if argv[:2] == ['systemctl','start']: self.running = True
            if argv[:len(c.DOCKER)] == c.DOCKER and argv[len(c.DOCKER):len(c.DOCKER)+2] == ['image','inspect']:
                return json.dumps([{'Architecture':'amd64','Os':'linux','RepoDigests':[c.image(self.state)]}]).encode()
            return b''
        patch.object(c, 'run', side_effect=run).start()

    def request(self, action):
        result=copy.deepcopy(self.state);result['action']=action;return result

    def test_every_mutator_rejects_other_owners_networks_and_families_before_commands(self):
        for action in ('prepare','begin-install','pull-image','finish-install','start','stop','restart','destroy','install-upstreams'):
            for change in ({'owner':'foreign'}, {'network':'mainnet'}, {'family':'robinhood','network':'testnet'}):
                request=self.request(action);request.update(change)
                with self.assertRaises(c.Refused): c.locked(request)
                self.assertEqual(self.calls,[])
        self.assertTrue(self.running)
        self.assertEqual((c.ROOT/'data/chain-fixture').read_text(),'retained chain state')

    def test_failed_cross_network_init_cannot_gain_stop_or_retire_authority(self):
        request=self.request('prepare');request.update(owner='wronginventory',family='robinhood',network='mainnet')
        with self.assertRaises(c.Refused): c.locked(request)
        for action in ('stop','restart','destroy'):
            request['action']=action
            with self.assertRaises(c.Refused): c.locked(request)
        self.assertEqual(c.state_read()['network'],'sepolia')
        self.assertEqual(self.calls,[])

    def test_init_retry_cannot_replace_helpers_of_an_existing_installation(self):
        for phase in ('installed', 'installing', 'retired'):
            state=copy.deepcopy(self.state);state['phase']=phase;c.save(state)
            with self.assertRaises(c.Refused):c.locked(self.request('prepare'))
            self.assertEqual(self.calls,[])
        state=copy.deepcopy(self.state);state['phase']='prepared';c.save(state)
        self.assertEqual(c.locked(self.request('prepare'))['phase'],'prepared')
        wrong=self.request('prepare');wrong['config_id']='d'*64
        with self.assertRaises(c.Refused):c.locked(wrong)

    def test_interrupted_update_binds_the_desired_configuration_and_retains_data(self):
        request=self.request('begin-install');request['config_id']='c'*64
        c.locked(request)
        self.assertEqual(c.state_read()['phase'],'installing')
        with self.assertRaises(c.Refused): c.guard(c.state_read())
        c.locked(request)
        different=self.request('begin-install');different['config_id']='d'*64
        with self.assertRaises(c.Refused): c.locked(different)
        with self.assertRaises(c.Refused): c.locked(self.request('start'))
        self.assertEqual(c.state_read()['target']['config_id'],'c'*64)
        self.assertEqual((c.ROOT/'data/chain-fixture').read_text(),'retained chain state')

    def test_upgrade_intent_remains_observable_by_the_previous_helper_and_resumable(self):
        # Synthetic catalog entry models a later reviewed CLI without pulling any image.
        requested=self.request('begin-install');requested.update(version='4.0.0',commit='d'*40,config_id='e'*64)
        future={'commit':'d'*40,'images':c.IMAGES}
        with patch.dict(c.RELEASES,{'4.0.0':future}):
            c.locked(requested)
        old_helper=dict(requested,action='status')
        observed=c.locked(old_helper)
        self.assertEqual(observed['phase'],'installing')
        self.assertEqual(observed['target']['version'],'4.0.0')
        with self.assertRaises(c.Refused):c.locked(dict(requested,action='start'))
        with patch.dict(c.RELEASES,{'4.0.0':future}):
            c.locked(requested)  # carried newer helper resumes its exact target
            completed=dict(requested,action='finish-install',service_uid=995,service_gid=996,firewall=self.state['firewall'])
            c.locked(completed)
            self.assertEqual(c.state_read()['version'],'4.0.0')
            with self.assertRaises(c.Refused):c.locked(self.request('begin-install'))

    def test_failed_stop_keeps_persistent_install_fence(self):
        with patch.object(c,'stop',side_effect=c.Refused('stop fixture')):
            with self.assertRaises(c.Refused): c.locked(self.request('begin-install'))
        self.assertEqual(c.state_read()['phase'],'installing')
        with self.assertRaises(c.Refused): c.guard(c.state_read())

    def test_missing_or_inactive_unit_cannot_leave_an_owned_container_writing(self):
        identity='f'*64
        running={'Id':identity,'State':{'Running':True,'Pid':123}}
        stopped={'Id':identity,'State':{'Running':False,'Pid':0}}
        for loaded in (False,True):
            for action in ('stop','destroy','begin-install'):
                c.save(self.state);self.calls.clear();self.running=False
                with patch.object(c,'loaded',return_value=loaded),patch.object(c,'check_container',side_effect=[running,running,stopped]):
                    result=c.locked(self.request(action))
                stops=[argv for argv,_ in self.calls if argv[:len(c.DOCKER)]==c.DOCKER]
                self.assertEqual(stops,[[*c.DOCKER,'container','stop','--time=1800',identity]])
                self.assertEqual(result['phase'], 'retired' if action=='destroy' else 'installing' if action=='begin-install' else 'installed')

    def test_orphan_stop_failure_or_replacement_preserves_install_retirement_fence(self):
        identity='f'*64
        running={'Id':identity,'State':{'Running':True,'Pid':123}}
        replacement={'Id':'e'*64,'State':{'Running':False,'Pid':0}}
        for action in ('destroy','begin-install'):
            for remaining in (running,replacement,{'Id':identity,'State':{'Running':False,'Pid':123}}):
                c.save(self.state)
                with patch.object(c,'loaded',return_value=False),patch.object(c,'check_container',side_effect=[running,running,remaining]):
                    with self.assertRaises(c.Refused):c.locked(self.request(action))
                self.assertEqual(c.state_read()['phase'],'retired' if action=='destroy' else 'installing')
            c.save(self.state)
            original=c.run
            def fail_stop(argv,**kwargs):
                if argv[:len(c.DOCKER)]==c.DOCKER:raise c.Refused('fixture failed Docker stop')
                return original(argv,**kwargs)
            with patch.object(c,'loaded',return_value=False),patch.object(c,'check_container',return_value=running),patch.object(c,'run',side_effect=fail_stop):
                with self.assertRaises(c.Refused):c.locked(self.request(action))
            self.assertEqual(c.state_read()['phase'],'retired' if action=='destroy' else 'installing')
            self.assertEqual((c.ROOT/'data/chain-fixture').read_text(),'retained chain state')

    def test_foreign_container_refuses_stop_before_retirement_or_install_mutation(self):
        for action in ('stop','destroy','begin-install'):
            with patch.object(c,'check_container',side_effect=c.Refused('foreign labels')):
                with self.assertRaises(c.Refused):c.locked(self.request(action))
            self.assertEqual(self.calls,[])
            self.assertEqual(c.state_read()['phase'],'installed')

    def test_active_remote_play_blocks_standalone_mutations_without_deadlock(self):
        import os
        fd=os.open(c.OPERATION_ROOT,os.O_RDONLY)
        try:
            c.fcntl.flock(fd,c.fcntl.LOCK_EX)
            with self.assertRaises(c.Refused): c.locked(self.request('stop'))
            c.locked(self.request('status'))
            c.locked(self.request('begin-install'),in_play=True)
        finally:os.close(fd)
        self.assertEqual(c.state_read()['phase'],'installing')

    def test_changed_configuration_cannot_start_the_previous_installation(self):
        request=self.request('start');request['config_id']='d'*64
        with self.assertRaises(c.Refused):c.locked(request)
        self.assertEqual(self.calls,[])

    def test_unreviewed_images_and_nonnumeric_identity_fail_closed(self):
        request=self.request('begin-install');request['version']='3.11.4'
        with self.assertRaises(c.Refused):c.locked(request)
        self.assertEqual(self.calls,[])
        c.locked(self.request('begin-install'))
        request=self.request('finish-install');request['service_uid']=True
        with self.assertRaises(c.Refused):c.locked(request)
        self.assertEqual(c.state_read()['phase'],'installing')

    def test_capacity_failure_precedes_stopping_and_cannot_be_bypassed_by_resume(self):
        self.free=1
        for action in ('prepare','begin-install','start','restart'):
            with self.assertRaises(c.Refused):c.locked(self.request(action))
        self.assertTrue(self.running)
        self.assertFalse(any(argv[:2]==['systemctl','stop'] for argv,_ in self.calls))
        c.locked(self.request('stop'))
        self.assertFalse(self.running)

    def test_missing_or_revoked_firewall_prevents_boot_and_start(self):
        state=c.state_read();state.pop('firewall');c.save(state)
        with self.assertRaises(c.Refused):c.guard(state)
        c.save(self.state)
        with patch.object(c,'firewall',side_effect=c.Refused('revoked')):
            with self.assertRaises(c.Refused):c.locked(self.request('start'))
        self.assertFalse(any(argv[:2]==['systemctl','start'] for argv,_ in self.calls))

    def test_retirement_keeps_database_credentials_and_owner(self):
        c.locked(self.request('destroy'))
        state=c.state_read()
        self.assertEqual(state['phase'],'retired')
        self.assertEqual(state['owner'],'ownedhost')
        self.assertTrue((c.CONF/'l1-upstreams.cred').exists())
        self.assertTrue((c.ROOT/'data/chain-fixture').exists())
        with self.assertRaises(c.Refused):c.guard(state)

    def test_readiness_requires_owned_listeners_current_parent_and_confirmed_filter(self):
        def rpc(method, params=None, port=8547):
            if method=='eth_chainId':return hex(c.network(self.state)[0]) if port==8547 else '0xaa36a7'
            if method=='eth_syncing':return False
            return {'number':'0x10','timestamp':hex(1_000 if port==8547 else self.parent_time)}
        self.parent_time=999
        with patch.object(c,'rpc',side_effect=rpc),patch.object(c,'check_container',return_value={'State':{'Running':True,'Pid':123}}),patch.object(c,'owned_ports',return_value=True),patch.object(c,'upstream_pid',return_value=456),patch.object(c.time,'time',return_value=1001):
            self.assertTrue(c.status(self.state)['ready'])
            self.parent_time=1
            self.assertFalse(c.status(self.state)['ready'])
            self.parent_time=999
            with patch.object(c,'firewall',side_effect=c.Refused('revoked')):
                self.assertFalse(c.status(self.state)['ready'])
            with patch.object(c,'owned_ports',return_value=False):
                self.assertFalse(c.status(self.state)['ready'])

    def test_unready_proxy_cannot_be_replaced_by_a_different_local_listener_on_boot(self):
        with patch.object(c,'upstream_pid',return_value=456),patch.object(c,'owned_ports',return_value=False),patch.object(c.time,'monotonic',side_effect=[0,0,121]),patch.object(c.time,'sleep'):
            with self.assertRaises(c.Refused):c.wait_upstreams(self.state)
        with patch.object(c,'upstream_pid',return_value=456),patch.object(c,'owned_ports',return_value=True),patch.object(c,'rpc',return_value='0x1'):
            with self.assertRaises(c.Refused):c.wait_upstreams(self.state)
        with patch.object(c,'upstream_pid',return_value=456),patch.object(c,'owned_ports',return_value=True),patch.object(c,'rpc',return_value='0xaa36a7'):
            c.wait_upstreams(self.state)

    def test_client_arguments_are_network_qualified_private_and_non_signing(self):
        for family,network in c.NETWORKS:
            state=dict(self.state,family=family,network=network)
            args=c.arguments(state)
            self.assertIn('--chain.id='+str(c.NETWORKS[(family,network)][0]),args)
            for option in ('--http.addr=127.0.0.1','--ws.addr=127.0.0.1','--node.staker.enable=false','--execution.caching.state-scheme=path','--init.validate-checksum=true','--init.force=false'):
                self.assertIn(option,args)
            self.assertEqual('--init.genesis-json-file=/config/genesis.json' in args,(family,network)==('robinhood','mainnet'))
            self.assertEqual('--init.latest=pruned' in args,family=='arbitrum')
            self.assertFalse(any('private-key' in arg or 'password' in arg for arg in args))

    def test_credential_validation_precedes_encryption_and_failure_keeps_old_ciphertext(self):
        import importlib.abc
        checked=[]
        class Loader(importlib.abc.Loader):
            def create_module(self,spec): return None
            def exec_module(self,module):
                module.strict_json=json.loads
                class Upstreams:
                    def __init__(self,config,network):
                        self.config=config;checked.append(network)
                    def verify(self):
                        if self.config.get('fail'): raise RuntimeError('context-free provider refusal')
                module.Upstreams=Upstreams
        spec=importlib.util.spec_from_loader('fixture_proxy',Loader())
        request=self.request('validate-upstreams');request['secret']=json.dumps({'fixture':'concealed fixture'})
        with patch.object(importlib.util,'spec_from_file_location',return_value=spec):
            c.locked(request)
            self.assertEqual(checked,['sepolia'])
            self.assertFalse(any(argv[0]=='systemd-creds' for argv,_ in self.calls))
            c.locked(self.request('begin-install'))
            request['action']='install-upstreams';request['secret']=json.dumps({'fail':True})
            with self.assertRaises(RuntimeError):c.locked(request)
            self.assertEqual((c.CONF/'l1-upstreams.cred').read_bytes(),b'encrypted fixture')
            request['secret']=json.dumps({'fixture':'concealed fixture'})
            original=c.run
            def encrypt(argv,**kwargs):
                if argv[0]=='systemd-creds':
                    self.assertNotIn('concealed fixture',' '.join(argv))
                    self.assertIn(b'concealed fixture',kwargs['input'])
                    Path(argv[-1]).write_bytes(b'new encrypted fixture')
                return original(argv,**kwargs)
            with patch.object(c,'run',side_effect=encrypt):c.locked(request)
        self.assertEqual((c.CONF/'l1-upstreams.cred').read_bytes(),b'new encrypted fixture')
        self.assertEqual((c.CONF/'l1-upstreams.cred').stat().st_mode & 0o777,0o600)
        self.assertFalse((c.CONF/'l1-upstreams.new').exists())



class ContainerAndArtifactTests(unittest.TestCase):
    def test_host_catalog_matches_official_manifest_and_carried_metadata_pins(self):
        root=SOURCE.parents[2]
        index=json.loads((root/'tests/fixtures/image-index.json').read_text())
        for platform,digest in c.IMAGES.items():
            descriptor=next(value for value in index['manifests'] if value['platform']['architecture']==platform)
            self.assertEqual(descriptor['digest'],digest)
            self.assertEqual(descriptor['platform']['os'],'linux')
        documents=json.loads((root/'networks/documents.json').read_text())
        self.assertEqual(documents['arbitrum']['sha256'],c.INFO_HASH['arbitrum'])
        self.assertEqual(documents['robinhood-mainnet']['sha256'],c.INFO_HASH['mainnet'])
        self.assertEqual(documents['robinhood-testnet']['sha256'],c.INFO_HASH['testnet'])
        self.assertEqual(documents['robinhood-genesis']['sha256'],c.GENESIS_HASH)

    def test_foreign_container_name_is_not_adopted_or_stopped(self):
        state={'family':'arbitrum','network':'sepolia','owner':'ownedhost'}
        with patch.object(Path,'is_file',return_value=True),patch.object(c,'run',side_effect=[b'erpc-arbitrum-nitro\n',json.dumps([{'Config':{'Labels':{'erpc.owner':'foreign'}}}]).encode()]) as run:
            with self.assertRaises(c.Refused):c.check_container(state)
            self.assertEqual(run.call_count,2)
            self.assertFalse(any('stop' in args.args[0] for args in run.call_args_list))

    def test_docker_daemon_selection_cannot_inherit_operator_context(self):
        self.assertIn('--host=unix:///var/run/docker.sock', c.DOCKER)
        with patch.dict(c.os.environ, {'DOCKER_HOST':'fixture-remote','DOCKER_CONTEXT':'fixture-remote','DOCKER_TLS_VERIFY':'1','NITRO_TEST_MARKER':'retained'}):
            environment=c.docker_environment()
            self.assertFalse(any(key.startswith('DOCKER_') for key in environment))
            self.assertEqual(environment['NITRO_TEST_MARKER'],'retained')

    def test_socket_ownership_checks_real_numeric_ss_field_shape(self):
        output=b'LISTEN 0 128 127.0.0.1:18545 0.0.0.0:* users:(("python3",pid=456,fd=3))\nLISTEN 0 128 127.0.0.1:15052 0.0.0.0:* users:(("python3",pid=456,fd=4))\n'
        with patch.object(c,'run',return_value=output):
            self.assertTrue(c.owned_ports(456,(18545,15052)))
            self.assertFalse(c.owned_ports(45,(18545,15052)))
            self.assertFalse(c.owned_ports(456,(8547,8548)))
        with patch.object(c,'run',return_value=output.replace(b'127.0.0.1:18545',b'0.0.0.0:18545')):
            self.assertFalse(c.owned_ports(456,(18545,15052)))

    def test_genesis_artifact_tampering_or_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'genesis';path.write_text('public fixture')
            digest=hashlib.sha256(path.read_bytes()).hexdigest();c.file_hash(path,digest)
            path.write_text('changed')
            with self.assertRaises(c.Refused):c.file_hash(path,digest)
            alias=path.with_name('alias');alias.symlink_to(path)
            with self.assertRaises(c.Refused):c.file_hash(alias,hashlib.sha256(path.read_bytes()).hexdigest())

    def test_reboot_units_require_filtering_and_do_not_put_credentials_in_arguments(self):
        root=SOURCE.parent
        for name in ('nitro','upstreams'):
            unit=(root/(name+'.service.j2')).read_text()
            self.assertIn('Requires=erpc-{{ nitro_family }}-firewall.service',unit)
            self.assertIn('nitro-control guard',unit)
            self.assertIn('LimitCORE=0',unit)
        upstream=(root/'upstreams.service.j2').read_text()
        self.assertIn('LoadCredentialEncrypted=l1-upstreams:',upstream)
        self.assertIn('User=erpc-nitro-upstreams',upstream)
        self.assertIn('nitro-upstreams.py {{ nitro_parent }}',upstream)
        self.assertNotIn('Environment=',upstream)


if __name__=='__main__':unittest.main()
