# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Public config and openat fixtures; no account or systemd mutation occurs."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.dont_write_bytecode = True
folder = Path(__file__).parents[1] / 'templates/node'
sys.path.insert(0, str(folder))
spec = importlib.util.spec_from_file_location('hyperliquid_setup_fixture', folder / 'erpc_hl_setup.py')
s = importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
import erpc_hl_common as common


class Setup(unittest.TestCase):
    def test_chain_configuration_cannot_reuse_other_network_or_unqualified_peers(self):
        c = {'network': 'mainnet', 'public_ip': '8.8.8.8'}
        peers = {'chain': 'Mainnet', 'root_node_ips': [{'Ip': '1.1.1.1'}]}
        result = s.configuration(c, {'chain': 'Mainnet'}, [], peers)
        self.assertEqual(result['visor.json'], b'{"chain": "Mainnet"}\n')
        self.assertIn(b'"allow": []', result['gateway.json'])
        with self.assertRaises(ValueError):s.configuration(c, {'chain': 'Testnet'}, [], peers)
        with self.assertRaises(ValueError):s.configuration(c, {'chain': 'Mainnet'}, [], None)
        with self.assertRaises(ValueError):s.configuration(c, {'chain': 'Mainnet'}, [], {'chain': 'Mainnet', 'root_node_ips': [{'Ip': '127.0.0.1'}]})
        testnet = dict(c, network='testnet')
        self.assertNotIn('gossip.json', s.configuration(testnet, {'chain': 'Testnet'}, ['192.0.2.1'], None))

    def test_numeric_account_reservation_survives_interruption_without_adopting_unknown_users(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); users = {}; groups = {}; writes = []; calls = []
            values = {}
            def get(mapping, selector, value):
                for item in mapping.values():
                    if getattr(item, selector) == value:return item
                raise KeyError(value)
            def put(name, value):
                values[name] = value;writes.append(name);(root/name).write_bytes(b'public numeric reservation')
            state = SimpleNamespace(directory=root, put=put, get=lambda name:values[name])
            fail = [True]
            def execute(argv):
                self.assertIn('account-reservation.json', writes)
                calls.append(argv)
                name = argv[-1]
                if 'groupadd' in argv[0]:
                    groups[name] = SimpleNamespace(gr_name=name, gr_gid=int(argv[argv.index('--gid')+1]), gr_mem=[])
                else:
                    users[name] = SimpleNamespace(pw_name=name, pw_uid=int(argv[argv.index('--uid')+1]),
                        pw_gid=int(argv[argv.index('--gid')+1]), pw_dir=argv[argv.index('--home-dir')+1], pw_shell='/usr/sbin/nologin')
                    if fail[0]:fail[0] = False;raise OSError('interrupted after account publication')
            with patch.object(s.pwd,'getpwnam',side_effect=lambda v:get(users,'pw_name',v)), \
                 patch.object(s.pwd,'getpwuid',side_effect=lambda v:get(users,'pw_uid',v)), \
                 patch.object(s.pwd,'getpwall',side_effect=lambda:list(users.values())), \
                 patch.object(s.grp,'getgrnam',side_effect=lambda v:get(groups,'gr_name',v)), \
                 patch.object(s.grp,'getgrgid',side_effect=lambda v:get(groups,'gr_gid',v)), \
                 patch.object(s.grp,'getgrall',side_effect=lambda:list(groups.values())), \
                 patch.object(s.os,'getgrouplist',side_effect=lambda name,gid:[gid],create=True),patch.object(s,'execute',execute):
                with self.assertRaises(OSError):s.provision_accounts(state)
                planned = values['account-reservation.json'].copy()
                self.assertNotIn('accounts.json', values)
                result = s.provision_accounts(state)
                self.assertEqual(result, planned)
                self.assertEqual(len(calls),4)
                self.assertEqual(s.provision_accounts(state),result)
                self.assertEqual(len(calls),4)
                users[s.NATIVE].pw_dir = '/unexpected'
                with self.assertRaises(ValueError):s.provision_accounts(state)
                del values['accounts.json'];(root/'accounts.json').unlink()
                del values['account-reservation.json'];(root/'account-reservation.json').unlink()
                with self.assertRaisesRegex(ValueError,'unknown dedicated account'):s.provision_accounts(state)
                self.assertEqual(len(calls),4)

    def test_native_directory_publication_does_not_follow_a_user_owned_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);outside = root / 'unrelated';outside.mkdir()
            identity = {'uid': os.getuid(), 'gid': os.getgid()}
            mounts = root / 'mountinfo';mounts.write_text('1 0 0:1 / / rw - fixture none rw\n')
            with patch.object(s, 'ROOT', root), patch.object(s, 'MOUNTINFO', mounts):
                (root / 'home').symlink_to(outside)
                with self.assertRaises(OSError):s.native_directories(identity)
                self.assertEqual(list(outside.iterdir()), [])
                (root / 'home').unlink()
                s.native_directories(identity)
                for name in ('home', 'home/hl', 'home/hl/data'):
                    self.assertEqual((root / name).stat().st_mode & 0o777, 0o700)

    def test_nested_native_and_same_device_bind_mounts_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'root';root.mkdir()
            mounts = Path(temporary) / 'mountinfo'
            with patch.object(s, 'ROOT', root), patch.object(s, 'MOUNTINFO', mounts):
                for path in [root, Path('/unrelated')]:
                    mounts.write_text('1 0 0:1 / '+str(path)+' rw - fixture none rw\n')
                    s.storage_mounts()
                for path in [root/'home', root/'home/hl/data', root/'home/hl/data/hyperliquid_data']:
                    mounts.write_text('1 0 0:1 / '+str(path)+' rw - fixture none rw\n')
                    with self.assertRaises(ValueError):s.storage_mounts()
                mounts.write_text('ambiguous kernel metadata')
                with self.assertRaises(ValueError):s.storage_mounts()

    def test_capacity_uses_opened_native_device_and_rejects_indirect_or_changed_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'home';data=home/'hl/data';data.mkdir(parents=True)
            for path in (home,home/'hl',data):path.chmod(0o700)
            identity={'uid':os.getuid(),'gid':os.getgid()};seen=[]
            def usage(fd):
                seen.append(os.fstat(fd).st_ino)
                return SimpleNamespace(f_blocks=1_000_000_000,f_bavail=600_000_000,f_frsize=1024)
            with patch.object(s,'ROOT',root),patch.object(s,'HOME',home),patch.object(s,'ROOT_UID',os.getuid()), \
                 patch.object(s,'storage_mounts'),patch.object(s.os,'fstatvfs',side_effect=usage), \
                 patch.object(s,'execute',return_value=SimpleNamespace(stdout=b'100000000000 native')):
                self.assertEqual(s.capacity(identity)['required'],350_000_000_000)
                self.assertEqual(seen,[data.stat().st_ino])
                # Same real opened native filesystem, but the larger validator
                # initial-sync floor cannot be replaced with RPC headroom.
                with self.assertRaises(ValueError):s.capacity(identity,validator=True)
                with patch.object(s.os,'fstatvfs',return_value=SimpleNamespace(f_blocks=1_000_000_000,
                                  f_bavail=900_000_000,f_frsize=1024)):
                    self.assertEqual(s.capacity(identity,validator=True)['required'],800_000_000_000)
                with patch.object(s.os,'fstatvfs',return_value=SimpleNamespace(f_blocks=500_000_000,
                                  f_bavail=500_000_000,f_frsize=1024)):
                    with self.assertRaises(ValueError):s.capacity(identity,validator=True)
                (home/'hl').chmod(0o750)
                with self.assertRaisesRegex(ValueError,'privacy changed'):s.capacity(identity)
                (home/'hl').chmod(0o700);(home/'hl').rename(home/'retained')
                (home/'hl').symlink_to(home/'retained')
                with self.assertRaises(OSError):s.capacity(identity)
                self.assertTrue((home/'retained/data').is_dir())

    def test_capacity_refuses_a_child_device_even_when_the_mount_table_was_stale(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'home';data=home/'hl/data';data.mkdir(parents=True)
            for path in (home,home/'hl',data):path.chmod(0o700)
            inode=(home/'hl').stat().st_ino;original=os.fstat
            def moved(fd):
                info=original(fd)
                if info.st_ino==inode:
                    fields=list(info);fields[2]+=1;return os.stat_result(fields)
                return info
            with patch.object(s,'ROOT',root),patch.object(s,'HOME',home),patch.object(s,'ROOT_UID',os.getuid()), \
                 patch.object(s,'storage_mounts'),patch.object(s.os,'fstat',side_effect=moved),patch.object(s,'execute') as execute:
                with self.assertRaisesRegex(ValueError,'device'):s.capacity({'uid':os.getuid(),'gid':os.getgid()})
                execute.assert_not_called()

    def test_public_keyring_publication_recovers_after_rename_failure_without_accepting_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);config = root/'config';config.mkdir();release = root/'release';release.mkdir()
            (release/'publisher.asc').write_bytes(b'inert public verification fixture')
            calls = []
            def execute(argv):
                calls.append(argv)
                if '--import' in argv:
                    stage = config/'.gnupg-stage'
                    (stage/'pubring.kbx').write_bytes(b'inert public keyring')
                    (stage/'trustdb.gpg').write_bytes(b'inert public trust database')
                return SimpleNamespace(returncode=0, stdout=b'')
            with patch.object(s,'CONFIG',config),patch.object(s,'ROOT_UID',os.getuid()),\
                 patch.object(s,'read',lambda p:common.read(p,owner=os.getuid())),patch.object(s,'execute',execute):
                with patch.object(s.os,'rename',side_effect=OSError('inert rename failure')):
                    with self.assertRaises(OSError):s.public_gnupg(release)
                self.assertTrue((config/'public-keyring.json').exists())
                self.assertFalse((config/'gnupg').exists())
                receipt = s.public_gnupg(release)
                with patch.object(s,'execute',side_effect=AssertionError('completed public keyring must not import again')):
                    self.assertEqual(s.public_gnupg(release),receipt)
                for path in receipt:self.assertEqual(Path(path).stat().st_mode&0o777,0o444)
                target = config/'gnupg/pubring.kbx';target.chmod(0o600)
                with self.assertRaises(ValueError):s.public_gnupg(release)
                target.chmod(0o644);target.write_bytes(b'changed trust input');target.chmod(0o444)
                with self.assertRaises(ValueError):s.public_gnupg(release)


if __name__ == '__main__':unittest.main()
