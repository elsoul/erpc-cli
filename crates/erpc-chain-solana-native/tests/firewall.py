# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compose the actual native policy wrapper and common firewall with inert nft/systemd."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_files as files
import native_firewall as firewall
import native_state as lifecycle
from mounts import owner

COMMON = Path(__file__).resolve().parents[2] / 'erpc-ops/templates/rpc-firewall.py'


class NativeFirewall(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup); self.addCleanup(patch.stopall)
        self.root = Path(folder.name)
        self.state_path = self.root / 'state'; self.state_path.mkdir()
        patch.object(lifecycle, 'read', lambda p, size: files.read(p, size, os.getuid())).start()
        patch.object(firewall, 'read', lambda p, size=1048576: files.read(p, size, os.getuid())).start()
        patch.object(firewall, 'sync_file', lambda p: files.sync_file(p, os.getuid())).start()
        def directory(path, create=False, mode=0o755):
            if create: path.mkdir(parents=True, exist_ok=True, mode=mode)
            if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o022:
                raise ValueError('unsafe fixture directory')
        patch.object(firewall, 'root_directory', directory).start()
        for name, relative in [('HELPER','usr/local/lib/erpc/rpc-firewall.py'),
                               ('UNIT','etc/systemd/system/erpc-solana-native-firewall.service')]:
            path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True)
            patch.object(firewall, name, path).start()
        patch.object(firewall, 'DIRECTORY', self.root / 'etc/erpc/solana-native').start()
        self.operation = 'r-20261027t120000-fixture'
        self.run_path = self.root / 'opt/erpc/runs' / self.operation
        self.source = self.run_path / 'bundle'; self.source.mkdir(parents=True)
        self.source.joinpath('rpc-firewall.py').write_bytes(COMMON.read_bytes())
        self.archive = b'inert submitted bundle'
        self.run_path.joinpath('bundle.tar.gz').write_bytes(self.archive)
        patch.object(firewall, 'SOURCE', self.source).start()
        patch.object(firewall.helpers, 'verify', return_value=self.source).start()
        self.contract = owner(); self.contract.update(profile='agave-native-rpc',vote_account=None,authority_account=None)
        self.intent = 'a'*32
        self.state = lifecycle.State(self.state_path); self.state.reserve(self.contract)
        self.state.authorize(self.contract,self.intent,{'helper_revision':'b'*64},'deploy')
        self.request = {'action':'firewall-prepare','contract':self.contract,'intent':self.intent,
            'source_sha256':hashlib.sha256(COMMON.read_bytes()).hexdigest(),
            'access':{'controller':'192.0.2.9','ssh_port':2222,'management':['2001:db8:1::/64'],'rpc':['198.51.100.7/32']}}
        self.live = None; self.calls = []
        spec = importlib.util.spec_from_file_location('inert_common_firewall',COMMON)
        self.common = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.common)
        self.common.ROOT_UID = os.getuid()
        patch.object(firewall.runpy, 'run_path', return_value={
            'Firewall':lambda family:self.common.Firewall(family,self.root,self.command)}).start()

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        output, code = b'', 0
        if argv[:2] == ['systemctl','show']:output=b'loaded'
        elif argv[:3] == ['nft','-j','list']:
            if self.live is None:raise subprocess.CalledProcessError(1,argv)
            output=json.dumps({'nftables':[{'policy':self.live}]}).encode()
        elif argv[:2] == ['nft','list']:
            output,code=(self.live.encode(),0) if self.live else (b'',1)
        elif argv[:2] == ['nft','-f']:self.live=Path(argv[2]).read_text()
        elif argv[:2] == ['nft','delete']:self.live=None
        return subprocess.CompletedProcess(argv,code,output,b'')

    def host_command(self,args,**kwargs):
        if args[:2]==['/usr/bin/systemctl','show']:
            return 'not-found\n'
        return self.command(args,**kwargs).stdout.decode()

    def prepare(self):return firewall.prepare(self.state,self.contract,self.request,self.host_command)

    def test_actual_apply_then_fresh_confirmation_is_required_by_runtime(self):
        result=self.prepare()
        manager=firewall.installed(self.state,self.contract)
        with self.assertRaises((ValueError,FileNotFoundError)):
            manager.require_confirmed(result['run'],result['bundle'])
        request={'action':'firewall-confirm','contract':self.contract,'intent':self.intent,
                 'run':result['run'],'bundle':result['bundle']}
        self.assertTrue(firewall.confirm(self.state,self.contract,request)['firewall_confirmed'])
        manager.require_confirmed(result['run'],result['bundle'])
        self.assertIn('tcp dport { 8899, 8900 } drop',self.live)
        self.assertIn('ip saddr 198.51.100.7/32 tcp dport { 7211, 7212 } accept',self.live)
        self.assertIn('tcp dport 2222 drop',self.live)
        self.assertIn('firewall-load',firewall.UNIT.read_text())
        self.assertNotIn('flush ruleset',self.live)

    def test_original_policy_cannot_be_changed_by_retry_or_stale_confirmation(self):
        self.prepare(); original=copy.deepcopy(self.request)
        self.request['access']['rpc']=['203.0.113.0/24']
        with self.assertRaisesRegex(ValueError,'original firewall policy'):self.prepare()
        self.request=original; result=self.prepare()
        self.state.stop(self.contract,lambda:None)
        with self.assertRaises(ValueError):firewall.confirm(self.state,self.contract,{
            'action':'firewall-confirm','contract':self.contract,'intent':self.intent,
            'run':result['run'],'bundle':result['bundle']})

    def test_unconfirmed_rollback_stops_listeners_before_removing_policy(self):
        result=self.prepare(); manager=firewall.installed(self.state,self.contract)
        manager.dispatch('rollback',result['run'],result['bundle'])
        stop=next(i for i,args in enumerate(self.calls) if args[:3]==['systemctl','disable','--now'])
        delete=next(i for i,args in enumerate(self.calls) if args[:2]==['nft','delete'])
        self.assertLess(stop,delete);self.assertIsNone(self.live)

    def test_receipt_before_unit_publication_resumes_without_accepting_unknown_unit(self):
        firewall.UNIT.write_bytes(b'unowned root unit')
        with self.assertRaisesRegex(ValueError,'unknown native firewall'):self.prepare()
        self.assertEqual(self.calls,[]);firewall.UNIT.unlink()
        real=firewall.atomic
        def fail(path,raw,*args):
            if path==firewall.UNIT:raise OSError('inert interrupted unit write')
            return real(path,raw,*args)
        with patch.object(firewall,'atomic',fail),self.assertRaises(OSError):self.prepare()
        self.assertEqual(self.calls,[])
        self.prepare(); firewall.installed(self.state,self.contract)

    def test_private_state_links_extra_files_and_changed_helper_refuse(self):
        self.prepare(); before=len(self.calls)
        path=firewall.DIRECTORY/'pending.json'; raw=path.read_bytes();path.unlink()
        other=self.root/'foreign';other.write_bytes(raw);other.chmod(0o600);path.symlink_to(other)
        with self.assertRaises(ValueError):self.prepare()
        self.assertEqual(len(self.calls),before);path.unlink();path.write_bytes(raw);path.chmod(0o600)
        firewall.HELPER.write_bytes(b'changed protected helper')
        with self.assertRaisesRegex(ValueError,'installation changed'):firewall.installed(self.state,self.contract)

    def test_acl_injection_wildcards_conflicting_ports_and_validator_ingress_refuse(self):
        for field,value in [('controller','192.0.2.1;flush ruleset'),('rpc',['0.0.0.0/0']),
            ('rpc',['192.0.2.1/24']),('rpc',['::ffff:c000:200/120']),('management',['::/0']),('ssh_port',8899),('ssh_port',8001),('ssh_port',True)]:
            data=copy.deepcopy(self.request['access']);data[field]=value
            with self.assertRaises(ValueError):firewall.policy(data,True)
        with self.assertRaises(ValueError):firewall.policy(self.request['access'],False)
        self.assertEqual(self.calls,[])

    def test_unknown_node_or_gateway_is_not_given_a_rollback_guard(self):
        for name in ('erpc-solana.service','erpc-solana-gateway.service'):
            path=firewall.UNIT.parent/name;path.write_bytes(b'unowned listener service')
            with self.assertRaisesRegex(ValueError,'unknown listener'):self.prepare()
            self.assertEqual(path.read_bytes(),b'unowned listener service')
            self.assertFalse((firewall.UNIT.parent/(name+'.d')).exists())
            self.assertEqual(self.calls,[]);path.unlink()


if __name__=='__main__':unittest.main()
