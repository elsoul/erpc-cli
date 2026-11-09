# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual controller/host phase routing and durable receipts; native boundaries are inert."""
import contextlib
import copy
import io
import importlib.util
import os
from pathlib import Path
import resource
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parents[1] / 'templates/node'))
import control
import erpc_hl_common as common
import erpc_hl_host as host
import erpc_hl_state as lifecycle


class Phases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name).resolve()
        self.root = self.directory/'state'
        self.root.mkdir()
        self.calls, self.patches = [], []
        def install(obj, name, value):
            item = patch.object(obj, name, value, create=True)
            item.start(); self.patches.append(item)
        def read(path): return common.read(path, owner=os.getuid())
        install(lifecycle, 'read', read)
        install(host, 'read', read)
        install(host, 'ROOT', self.root)
        install(common, 'ROOT', self.root)
        install(control, 'trusted_imports', lambda _: None)  # Entrypoint trust has its own subprocess suite.
        install(resource, 'setrlimit', lambda *_: None)
        install(control.os, 'geteuid', lambda: 0)
        install(host, 'protected_paths', lambda **_: None)
        self.identities = {host.setup.NATIVE: {'uid': 995, 'gid': 995}, host.setup.GATEWAY: {'uid': 996, 'gid': 996}}
        install(host, 'recorded_accounts', lambda: self.identities)
        install(host.setup, 'storage_mounts', lambda: None)
        install(host.setup, 'capacity', lambda *_,**__: None)
        install(host.setup, 'native_directories', lambda *_: None)
        install(host.artifact, 'install', lambda *_: self.directory/'release')
        install(host.artifact, 'check', lambda *_: None)
        install(host, 'publish_helpers', lambda *_: None)
        install(host.setup, 'install_configuration', lambda *_,**__: {'inert-public-config': 'a'*64})
        install(host.setup, 'public_gnupg', lambda *_: {})
        install(host, 'public_receipt', lambda *_: None)
        install(host.public, 'root_peers', lambda *_: None)
        install(host, 'stop_owned', lambda **_: self.calls.append('owned-stop'))
        def execute(argv, **kwargs):
            self.calls.append(tuple(argv))
            if 'show' in argv:
                uid=996 if 'erpc-hyperliquid-rpc.service' in argv else 995
                return SimpleNamespace(returncode=0,stdout=('LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=123\nUser='+str(uid)+'\nGroup='+str(uid)+'\nResult=success\n').encode())
            return SimpleNamespace(returncode=0, stdout=b'')
        install(host, 'execute', execute)
        install(common, 'execute', execute)
        self.confirmed = None
        def firewall(receipt):
            host.firewall_token(receipt)
            common.require(receipt == self.confirmed, 'unconfirmed fixture policy')
        install(host, 'firewall', firewall)
        controller = SimpleNamespace(apply=lambda run,bundle: self.calls.append(('filter-apply',run,bundle)),
            confirm=lambda run,bundle: setattr(self, 'confirmed', {'run':run,'bundle':bundle}))
        install(host, 'common_firewall', lambda: controller)
        self.contract = {'owner':'a'*32,'network':'testnet','role':'rpc','public_ip':'8.8.8.8'}
        self.state = lifecycle.State(self.root)
        self.state.put('owner.json', {'contract':self.contract})
        pin = common.unique_json(read(host.SOURCE/'catalog.json'))['networks']['testnet']['supervisor']
        self.policy = {'rpc_allow': [], 'management_allow': ['192.0.2.1/32']}
        self.target = {key:pin[key] for key in ('id','sha256','signed_at')}
        self.target.update(helper_sha=host.helper_digest(),config_id=common.digest(common.json_bytes(self.policy)))
        self.intent, self.receipt = 'b'*32, {'run':'inert-run','bundle':'c'*64}
        (self.root/'retained-native-data').write_bytes(b'never delete')

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temporary.cleanup()

    def invoke(self, action, **fields):
        request = dict(action=action,contract=self.contract,**fields)
        source = SimpleNamespace(buffer=io.BytesIO(common.json_bytes(request)))
        output = io.StringIO()
        with patch.object(sys,'argv',['control.py','play']),patch.object(sys,'stdin',source),contextlib.redirect_stdout(output):
            control.main()
        return common.unique_json(output.getvalue())

    def authorize(self):
        return self.invoke('authorize',intent=self.intent,target=self.target,policy=self.policy)

    def prepare(self):
        return self.invoke('prepare',intent=self.intent,target=self.target,policy=self.policy)

    def activate(self):
        return self.invoke('activate',intent=self.intent,firewall=self.receipt)

    def install(self):
        self.authorize(); self.prepare()
        self.invoke('firewall-apply',intent=self.intent,firewall=self.receipt)
        self.invoke('firewall-confirm',intent=self.intent,firewall=self.receipt)
        return self.activate()

    def test_preparation_never_starts_before_exact_fresh_confirmation_and_consumes_authority(self):
        self.authorize(); self.prepare()
        self.assertFalse(any(isinstance(call,tuple) and 'start' in call for call in self.calls))
        with self.assertRaisesRegex(ValueError,'unconfirmed'): self.activate()
        self.assertTrue((self.root/'installing.json').exists())
        self.invoke('firewall-confirm',intent=self.intent,firewall=self.receipt)
        self.assertTrue(self.activate()['started'])
        self.assertIsNone(self.state.get('operation.json')['intent'])
        with self.assertRaises(ValueError): self.activate()
        self.assertEqual((self.root/'retained-native-data').read_bytes(),b'never delete')

    def test_stop_between_prepare_and_activation_blocks_all_old_continuations(self):
        self.authorize(); self.prepare(); self.invoke('stop')
        for action in ('check-deploy','firewall-apply','firewall-confirm','activate'):
            with self.subTest(action=action),self.assertRaises(ValueError):
                self.invoke(action,intent=self.intent,target=self.target,policy=self.policy,firewall=self.receipt)
        self.assertTrue((self.root/'stopped').exists())
        self.assertFalse(any(isinstance(call,tuple) and 'start' in call for call in self.calls))

    def test_activation_start_failure_cancels_and_drains_even_after_installed_receipt(self):
        self.authorize(); self.prepare(); self.confirmed=self.receipt
        def failed(argv, **kwargs):
            self.calls.append(tuple(argv))
            if 'start' in argv: raise OSError('inert partial service start failure')
        with patch.object(common,'execute',failed),self.assertRaises(OSError): self.activate()
        self.assertIn('owned-stop',self.calls)
        self.assertTrue((self.root/'installed.json').exists())
        self.assertTrue((self.root/'stopped').exists())
        with self.assertRaises(ValueError): host.ready(self.contract)

    def test_owned_stop_runs_on_storage_failure_but_foreign_contract_never_stops(self):
        self.install(); self.calls.clear()
        with patch.object(lifecycle.State,'put',side_effect=OSError('inert storage failure')), \
             patch.object(lifecycle.State,'marker',side_effect=OSError('inert marker failure')):
            with self.assertRaisesRegex(ValueError,'not persisted'): self.invoke('stop')
        self.assertEqual(self.calls,['owned-stop'])
        self.calls.clear(); self.contract=dict(self.contract,network='mainnet')
        with self.assertRaisesRegex(ValueError,'immutable'): self.invoke('retire')
        self.assertEqual(self.calls,[])

    def test_preparation_failure_retains_target_and_explicit_recovery_revokes_stale_play(self):
        self.authorize()
        with patch.object(host.artifact,'install',side_effect=OSError('inert acquisition failure')),self.assertRaises(OSError): self.prepare()
        self.assertTrue((self.root/'installing.json').exists())
        self.assertTrue(self.invoke('recover-preparation')['data_preserved'])
        with self.assertRaises(ValueError): self.prepare()
        self.intent='d'*32
        self.assertTrue(self.install()['started'])
        self.assertTrue((self.root/('abandoned-'+'b'*32+'.json')).exists())
        self.assertEqual((self.root/'retained-native-data').read_bytes(),b'never delete')

    def test_skipped_failed_pending_or_redirected_service_never_consumes_activation(self):
        healthy=host.execute
        for field,value in [('Result','exec-condition'),('Result','exit-code'),('ActiveState','activating'),
                            ('SubState','auto-restart'),('MainPID','0'),('User','997')]:
            with self.subTest(field=field,value=value):
                self.intent=('%032x' % (len(self.calls)+1))
                self.authorize();self.prepare();self.confirmed=self.receipt;self.calls.clear()
                def changed(argv,**kwargs):
                    result=healthy(argv,**kwargs)
                    if 'show' in argv:
                        rows=dict(line.split('=',1) for line in result.stdout.decode().splitlines())
                        rows[field]=value
                        result.stdout=''.join(key+'='+entry+'\n' for key,entry in rows.items()).encode()
                    return result
                with patch.object(host,'execute',changed),self.assertRaisesRegex(ValueError,'startup'):
                    self.activate()
                self.assertIn('owned-stop',self.calls)
                self.assertTrue((self.root/'stopped').exists())
                self.assertIsNone(self.state.get('operation.json')['intent'])
                self.assertEqual((self.root/'retained-native-data').read_bytes(),b'never delete')

    def test_manual_start_and_restart_partial_failure_cancels_and_stops(self):
        self.install()
        for action in ('start','restart'):
            self.invoke('stop');self.calls.clear()
            with patch.object(host,'started',side_effect=ValueError('inert partial startup')), \
                 self.assertRaisesRegex(ValueError,'partial startup'):
                self.invoke(action)
            self.assertTrue((self.root/'stopped').exists())
            self.assertTrue((self.root/'activation-revoked').exists())
            self.assertIn('owned-stop',self.calls)
            self.assertIsNone(self.state.get('operation.json')['intent'])

    def test_actual_common_firewall_confirmation_is_not_replaced_by_stale_installed_policy(self):
        path=Path(__file__).resolve().parents[2]/'erpc-ops/tests/firewall.py'
        spec=importlib.util.spec_from_file_location('hl_common_firewall_fixture',path)
        fixtures=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixtures)
        fixture=fixtures.HyperliquidFirewallTests();fixture.setUp()
        try:
            def candidate(suffix,rules):
                run='r-20261027t120000-'+suffix
                directory=fixture.control.path('/opt/erpc/runs/'+run)
                (directory/'bundle').mkdir(parents=True)
                payload=('inert original archive '+suffix).encode()
                (directory/'bundle.tar.gz').write_bytes(payload)
                (directory/'bundle/firewall-candidate.nft').write_text(rules)
                return {'run':run,'bundle':fixture.control.digest(payload)}
            with patch.object(host,'common_firewall',return_value=fixture.control), \
                 patch.object(host,'firewall',lambda receipt:fixture.control.require_confirmed(receipt['run'],receipt['bundle'])):
                self.authorize();self.prepare();self.receipt=candidate('aaaaaa','old-policy')
                self.invoke('firewall-apply',intent=self.intent,firewall=self.receipt)
                self.invoke('firewall-confirm',intent=self.intent,firewall=self.receipt)
                self.activate()
                self.intent='d'*32;self.authorize();self.prepare();self.receipt=candidate('bbbbbb','narrowed-policy')
                self.invoke('firewall-apply',intent=self.intent,firewall=self.receipt)
                fixture.control.rollback(self.receipt['run'],self.receipt['bundle'])
                self.assertEqual(fixture.live,'old-policy')
                with self.assertRaises(Exception):self.invoke('firewall-confirm',intent=self.intent,firewall=self.receipt)
                with self.assertRaises(Exception):self.activate()
                self.assertTrue((self.root/'installing.json').exists())
                self.assertEqual((self.root/'retained-native-data').read_bytes(),b'never delete')
        finally:fixture.doCleanups()


if __name__ == '__main__': unittest.main()
