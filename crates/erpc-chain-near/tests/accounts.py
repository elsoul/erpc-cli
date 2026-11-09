# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original NSS authority with inert account tools and temporary-file publication."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('control', ROOT / 'templates/node/control.py')
c = importlib.util.module_from_spec(spec); sys.modules['control'] = c; spec.loader.exec_module(c)
c.ROOT_UID = os.getuid()
spec = importlib.util.spec_from_file_location('near_account_setup', ROOT / 'templates/node/setup.py')
setup = importlib.util.module_from_spec(spec); spec.loader.exec_module(setup)


class Accounts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.users = []; self.groups = []; self.extra = []
        self.calls = []; self.running = True
        self.expected = {'owner': 'fixture', 'network': 'testnet', 'role': 'rpc', 'genesis_hash': c.PINS['testnet']['genesis_hash']}
        self.control = c.Control(self.root, self.host_run)
        self.control.path('/opt/erpc').mkdir(parents=True)
        self.control.account_snapshot = lambda: (self.users, self.groups)
        def lookup(kind, value):
            values = self.users if kind.startswith('user') else self.groups
            field = {'user_name':'pw_name', 'user_id':'pw_uid', 'group_name':'gr_name', 'group_id':'gr_gid'}[kind]
            return next((entry for entry in values if getattr(entry, field) == value), None)
        self.control.account_lookup = lookup
        self.members = patch.object(c.os, 'getgrouplist', side_effect=lambda name, gid: [gid, *self.extra]); self.members.start(); self.addCleanup(self.members.stop)

    def host_run(self, argv, **kwargs):
        self.calls.append(argv); output = b''
        if argv[0] in ('/usr/sbin/groupadd', '/usr/sbin/useradd'):
            record = self.control.read('accounts-intent.json')
            self.assertTrue((self.control.directory / 'accounts-reserved').exists())
            if argv[0].endswith('groupadd'):
                self.groups.append(SimpleNamespace(gr_name='near', gr_gid=record['gid'], gr_mem=[]))
            else:
                self.users.append(SimpleNamespace(pw_name='near', pw_uid=record['uid'], pw_gid=record['gid'], pw_dir=record['home'], pw_shell=record['shell']))
        if argv[:2] == ['systemctl', 'show']: output = b'not-found'
        if argv[-3:] == ['container', 'inspect', c.CONTAINER]:
            output = json.dumps([{'Id': 'a' * 64, 'Config': {'Labels': {'erpc.owner': self.expected['owner'], 'erpc.network': 'testnet', 'erpc.role': 'rpc'}}, 'State': {'Running': self.running}}]).encode()
        if argv[-4:] == ['stop', '--time', '180', 'a' * 64]: self.running = False
        return subprocess.CompletedProcess(argv, 0, output, b'')

    def establish(self):
        self.control.reserve(self.expected); self.control.accounts(self.expected)
        self.control.home.mkdir(parents=True, exist_ok=True); self.control.home.chmod(0o700)
        original = Path.lstat
        record = self.control.read('accounts-intent.json')
        def metadata(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.control.home:
                fields = list(info); fields[4] = record['uid']; fields[5] = record['gid']; return os.stat_result(fields)
            return info
        model = patch.object(Path, 'lstat', metadata); model.start(); self.addCleanup(model.stop)
        return record

    def test_fresh_unknown_user_or_group_is_refused_before_owner_and_mutation(self):
        for kind in ('user', 'group'):
            self.users = [SimpleNamespace(pw_name='near', pw_uid=20001, pw_gid=20001)] if kind == 'user' else []
            self.groups = [SimpleNamespace(gr_name='near', gr_gid=20001, gr_mem=[])] if kind == 'group' else []
            with self.assertRaises(c.Refused): self.control.reserve(self.expected)
            self.assertFalse((self.control.directory / 'contract.json').exists()); self.assertFalse(self.calls)

    def test_reservation_records_original_ids_before_nss_and_is_idempotent(self):
        self.users = [SimpleNamespace(pw_name='unrelated', pw_uid=20000, pw_gid=20000)]
        self.groups = [SimpleNamespace(gr_name='unrelated', gr_gid=20001, gr_mem=[])]
        record = self.control.reserve(self.expected)
        self.assertEqual(record['uid'], 20002); self.assertEqual(record['gid'], 20002); self.assertFalse(self.calls)
        self.assertEqual(self.control.accounts(self.expected), {'uid': 20002, 'gid': 20002})
        before = len(self.calls); self.control.accounts(self.expected); self.assertEqual(len(self.calls), before)

    def test_unenumerated_nss_names_and_occupied_primary_gid_do_not_gain_authority(self):
        hidden = SimpleNamespace(pw_name='near', pw_uid=22000, pw_gid=22000)
        original = self.control.account_lookup
        with patch.object(self.control, 'account_lookup', side_effect=lambda kind, value: hidden if kind == 'user_name' else original(kind, value)):
            with self.assertRaises(c.Refused): self.control.reserve(self.expected)
        self.assertFalse(self.control.directory.exists()); self.assertFalse(self.calls)
        self.users = [SimpleNamespace(pw_name='other', pw_uid=40000, pw_gid=20000)]
        record = self.control.reserve(self.expected)
        self.assertEqual(record['uid'], 20001)

    def test_direct_nss_resolution_must_match_original_enumerated_identity(self):
        record = self.establish(); original = self.control.account_lookup
        for kind in ('user_name', 'user_id', 'group_name', 'group_id'):
            with self.subTest(kind=kind), patch.object(self.control, 'account_lookup', side_effect=lambda lookup, value: None if lookup == kind else original(lookup, value)):
                with self.assertRaises(c.Refused): self.control.account(self.expected)
        # Exercise the actual resolver against inert NSS functions as well.
        with patch.object(c.pwd, 'getpwuid', return_value=self.users[0]) as lookup:
            self.assertEqual(c.Control.account_lookup(self.control, 'user_id', record['uid']), self.users[0])
            lookup.assert_called_once_with(record['uid'])

    def test_group_or_user_response_loss_resumes_only_original_numeric_ids(self):
        for kind in ('groupadd', 'useradd'):
            self.users = []; self.groups = []
            if (self.control.directory / 'accounts.json').exists(): self.control.remove('accounts.json')
            self.control.reserve(self.expected); original = self.control.command; failed = []
            def command(*argv, **kwargs):
                result = original(*argv, **kwargs)
                if argv[0] == '/usr/sbin/' + kind and not failed:
                    failed.append(True); raise OSError('inert lost NSS response')
                return result
            with patch.object(self.control, 'command', side_effect=command):
                with self.assertRaises(OSError): self.control.accounts(self.expected)
            before = self.control.read('accounts-intent.json')
            self.control.accounts(self.expected)
            self.assertEqual(self.control.read('accounts.json'), before)

    def test_failed_receipt_or_ancestor_sync_cannot_mutate_nss(self):
        self.control.reserve(self.expected)
        with patch.object(self.control, 'write', side_effect=OSError('inert receipt storage failure')):
            with self.assertRaises(OSError): self.control.accounts(self.expected)
        self.assertFalse(self.calls)
        real = self.control.sync_directory
        def sync(path):
            if path == self.control.directory.parent: raise OSError('inert ancestor sync failure')
            return real(path)
        with patch.object(self.control, 'sync_directory', side_effect=sync):
            with self.assertRaises(OSError): self.control.accounts(self.expected)
        self.assertFalse(self.calls)
        self.control.accounts(self.expected)

    def test_original_nss_fields_aliases_and_all_membership_are_required(self):
        self.establish(); users = copy.deepcopy(self.users); groups = copy.deepcopy(self.groups)
        for kind in ('uid', 'gid', 'home', 'shell', 'supplementary', 'group-members', 'uid-alias', 'gid-alias', 'primary-sharing', 'missing-user', 'missing-group'):
            self.users = copy.deepcopy(users); self.groups = copy.deepcopy(groups); self.extra = []
            if kind == 'uid': self.users[0].pw_uid += 1
            elif kind == 'gid': self.users[0].pw_gid += 1
            elif kind == 'home': self.users[0].pw_dir = '/home/previous'
            elif kind == 'shell': self.users[0].pw_shell = '/bin/bash'
            elif kind == 'supplementary': self.extra = [998]
            elif kind == 'group-members': self.groups[0].gr_mem = ['another']
            elif kind == 'uid-alias': self.users.append(SimpleNamespace(**dict(vars(self.users[0]), pw_name='another')))
            elif kind == 'gid-alias': self.groups.append(SimpleNamespace(gr_name='another', gr_gid=self.groups[0].gr_gid, gr_mem=[]))
            elif kind == 'primary-sharing': self.users.append(SimpleNamespace(pw_name='another', pw_uid=50000, pw_gid=self.groups[0].gr_gid))
            elif kind == 'missing-user': self.users = []
            elif kind == 'missing-group': self.groups = []
            with self.subTest(kind=kind), self.assertRaises(c.Refused): self.control.account(self.expected)

    def test_original_home_must_be_real_correctly_owned_and_private(self):
        self.establish(); self.assertEqual(self.control.account(self.expected), (20000, 20000))
        self.control.home.chmod(0o755)
        with self.assertRaises(c.Refused): self.control.account(self.expected)
        self.control.home.chmod(0o700); old = self.control.home.with_name('retained'); self.control.home.rename(old)
        self.control.home.symlink_to(old)
        with self.assertRaises(c.Refused): self.control.account(self.expected)

    def test_unreceipted_legacy_cannot_provision_or_start_but_owned_stop_remains(self):
        self.control.directory_guard(self.control.directory, create=True, mode=0o700)
        self.control.write('contract.json', self.expected)
        for operation in (self.control.reserve, self.control.accounts, self.control.account, self.control.guard):
            with self.assertRaises(c.Refused): operation(self.expected)
        self.control.service(self.expected, 'stop')
        self.assertFalse(self.running)

    def test_receipt_loss_never_replaces_original_uid_even_after_nss_loss(self):
        self.establish(); self.control.remove('accounts-intent.json'); self.users = []; self.groups = []
        before = len(self.calls)
        with self.assertRaises(c.Refused): self.control.accounts(self.expected)
        self.control.remove('accounts.json')
        with self.assertRaises(c.Refused): self.control.accounts(self.expected)
        self.assertEqual(len(self.calls), before)
        self.control.service(self.expected, 'stop'); self.assertFalse(self.running)

    def test_owned_container_shutdown_does_not_depend_on_live_nss(self):
        self.establish()
        with patch.object(self.control, 'account_snapshot', side_effect=AssertionError('stop must not consult NSS')):
            self.control.service(self.expected, 'stop')
        self.assertFalse(self.running)
        self.assertTrue(any(call[-4:] == ['stop', '--time', '180', 'a' * 64] for call in self.calls))

    def test_guard_prepare_and_key_stage_refuse_drift_before_native_or_secret_access(self):
        self.establish(); self.extra = [998]
        target = {key: c.PINS['testnet'][key] for key in ('version', 'commit', 'image')}
        target.update({key: 'b' * 64 for key in ('config_sha256', 'genesis_sha256', 'policy_sha256')})
        for operation in (lambda: self.control.guard(self.expected), lambda: self.control.begin_install(self.expected, target, 'c' * 32),
                          lambda: self.control.stage_runtime_key(self.expected), lambda: setup.prepare(self.control, self.expected, {}),
                          lambda: setup.peer_identity(self.control, self.expected, {}, Path('unused'), 'unused')):
            before = len(self.calls)
            with self.assertRaises(c.Refused): operation()
            self.assertEqual(len(self.calls), before)
        result = self.control.status(self.expected)
        self.assertFalse(result['ready']); self.assertIn('inspection_error', result)

    def test_foreign_owner_still_cannot_stop_under_account_drift(self):
        self.establish(); self.extra = [998]; before = len(self.calls)
        with self.assertRaises(c.Refused): self.control.service(dict(self.expected, owner='other'), 'stop')
        self.assertEqual(len(self.calls), before); self.assertTrue(self.running)

    def test_firewall_loader_unwraps_scope_without_requiring_current_nss(self):
        self.establish()
        helper = self.control.path('/usr/local/lib/erpc/rpc-firewall.py')
        helper.parent.mkdir(parents=True); helper.write_text('# inert fixture')
        calls = []
        class Firewall:
            def __init__(self, family): calls.append(family)
            def dispatch(self, *args): calls.append(args); return 'loaded'
        with patch('runpy.run_path', return_value={'Firewall': Firewall}), patch.object(self.control, 'account_snapshot', side_effect=AssertionError('filter restoration must not require NSS')):
            self.assertEqual(self.control.firewall_action('load'), 'loaded')
        self.assertEqual(calls, ['near', ('load', None, None)])

    def test_full_scope_wrapper_is_generic_and_old_exact_contract_shape_refuses(self):
        self.control.reserve(self.expected)
        record = self.control.read('contract.json')
        self.assertEqual(record, {'format': 2, 'contract': self.expected}); self.assertNotEqual(record, self.expected)
        self.assertEqual(self.control.public_contract(), self.expected)
        extended = dict(self.expected, validator_account='fixture.testnet')
        self.control.write('contract.json', {'format': 2, 'contract': extended})
        with patch.object(self.control, 'expected', side_effect=lambda value: value):
            self.assertEqual(self.control.public_contract(), extended)
            self.assertTrue(self.control.contract(extended))


try:
    import shutil
    import yaml
    ANSIBLE = shutil.which('ansible-playbook')
except ImportError:
    ANSIBLE = None


@unittest.skipUnless(ANSIBLE, 'optional pinned Ansible publication integration')
class Publication(unittest.TestCase):
    def test_actual_initialization_orders_reservation_nss_then_numeric_home(self):
        for kind in ('new', 'unknown-nss', 'unsafe-home', 'sync-failure'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); operation = root / 'operation'; operation.mkdir()
                nss = root / 'inert-nss.json'
                nss.write_text(json.dumps({'users': [{'pw_name': 'near', 'pw_uid': 22000, 'pw_gid': 22000}] if kind == 'unknown-nss' else [], 'groups': [], 'calls': []}))
                source = (ROOT / 'templates/node/control.py').read_text()
                source = source.replace("root=Path('/')", 'root=Path(' + repr(str(root)) + ')')
                source = source.replace('ROOT_UID = 0', 'ROOT_UID = ' + str(os.getuid()))
                # Model NSS and UID ownership only. Execute the actual controller
                # reservation/provisioning and actual Ansible file module; never
                # invoke account tools or use a different real filesystem UID.
                fixture = """
from types import SimpleNamespace
_NSS = Path(%r)
def _snapshot(self):
    value = json.loads(_NSS.read_text())
    return ([SimpleNamespace(**row) for row in value['users']], [SimpleNamespace(**row) for row in value['groups']])
def _command(self, *argv, **kwargs):
    value = json.loads(_NSS.read_text()); record = self.read('accounts-intent.json')
    assert (self.directory / 'accounts-reserved').exists()
    value['calls'].append(list(argv))
    if argv[0] == '/usr/sbin/groupadd': value['groups'].append({'gr_name':'near','gr_gid':record['gid'],'gr_mem':[]})
    elif argv[0] == '/usr/sbin/useradd': value['users'].append({'pw_name':'near','pw_uid':record['uid'],'pw_gid':record['gid'],'pw_dir':record['home'],'pw_shell':record['shell']})
    else: raise AssertionError('unexpected system tool')
    _NSS.write_text(json.dumps(value))
    return subprocess.CompletedProcess(argv,0,b'',b'')
def _lookup(self, kind, value):
    users, groups = _snapshot(self)
    values = users if kind.startswith('user') else groups
    field = {'user_name':'pw_name','user_id':'pw_uid','group_name':'gr_name','group_id':'gr_gid'}[kind]
    return next((entry for entry in values if getattr(entry, field) == value), None)
Control.account_lookup = _lookup
Control.account_snapshot = _snapshot
Control.command = _command
os.getgrouplist = lambda name, gid: [gid]
_real_accounts = Control.accounts
def _accounts(self, expected):
    _real_accounts(self, expected)
    return {'uid':os.getuid(),'gid':os.getgid()}
Control.accounts = _accounts
trusted_imports = lambda path: None
""" % str(nss)
                if kind == 'sync-failure': fixture += "Control.sync_directory = lambda self, path: (_ for _ in ()).throw(OSError('inert sync failure'))\n"
                source = source.replace("if __name__ == '__main__':", fixture + "\nif __name__ == '__main__':")
                (operation / 'control.py').write_text(source)
                home = root / 'var/lib/near'
                if kind == 'unsafe-home':
                    home.parent.mkdir(parents=True); outside = root / 'outside'; outside.mkdir(); home.symlink_to(outside)
                play = yaml.safe_load((ROOT / 'templates/node/init.yml').read_text())
                self.assertFalse(any('ansible.builtin.user' in task for task in play[0]['tasks']))
                play[0]['become'] = False
                play[0]['tasks'] = [task for task in play[0]['tasks'] if
                    'play-reserve' in task.get('ansible.builtin.command', {}).get('argv', []) or
                    'play-accounts' in task.get('ansible.builtin.command', {}).get('argv', []) or
                    task.get('ansible.builtin.file', {}).get('path') == '/var/lib/near']
                play[0]['tasks'][-1]['ansible.builtin.file']['path'] = str(home)
                script = operation / 'play.yml'; script.write_text(yaml.safe_dump(play))
                import base64
                contract = {'owner': 'fixture', 'network': 'testnet', 'role': 'rpc', 'genesis_hash': c.PINS['testnet']['genesis_hash']}
                variables = operation / 'vars.json'; variables.write_text(json.dumps({'near_contract':base64.b64encode(json.dumps(contract).encode()).decode()}))
                result = subprocess.run([ANSIBLE, '-i', 'localhost,', '-c', 'local', str(script), '-e', '@' + str(variables)], capture_output=True, text=True, timeout=90)
                observed = json.loads(nss.read_text())
                if kind == 'new':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(len(observed['calls']), 2)
                    self.assertEqual(observed['users'][0]['pw_uid'], observed['groups'][0]['gr_gid'])
                    self.assertEqual((home.stat().st_uid, home.stat().st_gid, home.stat().st_mode & 0o777), (os.getuid(), os.getgid(), 0o700))
                else:
                    self.assertNotEqual(result.returncode, 0); self.assertFalse(observed['calls'])
                    if kind == 'unsafe-home': self.assertTrue(home.is_symlink()); self.assertFalse(any(outside.iterdir()))
                    else: self.assertFalse(home.exists())


if __name__ == '__main__': unittest.main()
