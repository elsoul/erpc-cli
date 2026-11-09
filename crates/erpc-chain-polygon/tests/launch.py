# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual native argv/environment construction; exec and account lookup are inert."""
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/scripts'))
import launch


class Launch(unittest.TestCase):
    def setUp(self):
        self.binaries={name:{'directory':'/opt/polygon/releases/'+name+'-'+tag+'-x86_64'}
            for name,tag in [('bor','v2.10.3'),('heimdall','v0.12.2')]}
    def metadata(self,phase=None):
        expected={'network':'amoy','role':'fullnode' if phase is None else 'validator'}
        return launch.metadata(expected,{} if phase is None else {'validator':{'phase':phase}},self.binaries)
    def test_observer_and_rpc_cannot_enable_bridge_and_active_uses_only_private_app_path(self):
        for phase in (None,'observing','active'):
            metadata=self.metadata(phase);args=launch.arguments('heimdall',metadata)
            self.assertIn('--bridge='+str(phase=='active').lower(),args)
            self.assertEqual('--all' in args,phase=='active')
            self.assertEqual('--app' in args,phase is not None)
            if phase is not None:self.assertEqual(args[-1],'/run/credentials/polygon-heimdall.service/native-app.toml')
            self.assertFalse(any('https://' in arg or 'amqps://' in arg for arg in args))
        for invalid in ('','unknown',True):
            with self.assertRaises(ValueError):self.metadata(invalid)
        with self.assertRaises(ValueError):launch.arguments('heimdall',dict(self.metadata(),role='validator'))
    def test_actual_launcher_keeps_credentials_out_of_argv_and_environment(self):
        authority=SimpleNamespace(runtime=Mock())
        empty=SimpleNamespace(lstat=lambda:SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0),iterdir=lambda:iter(()))
        empty.__str__=lambda:'/etc/polygon/empty-ca'
        class Empty:
            lstat=staticmethod(empty.lstat);iterdir=staticmethod(empty.iterdir)
            def __str__(self):return '/etc/polygon/empty-ca'
        for phase in ('observing','active'):
            value=self.metadata(phase)
            def path(name):
                if str(name)=='/etc/polygon/launch.json':return SimpleNamespace(read_text=lambda:json.dumps(value))
                if str(name)=='/etc/polygon/empty-ca':return Empty()
                return Path(name)
            spec=SimpleNamespace(loader=SimpleNamespace(exec_module=Mock()))
            with patch.object(launch.sys,'argv',['launch.py','heimdall']),patch.object(launch,'Path',side_effect=path), \
                    patch.object(launch.importlib.util,'spec_from_file_location',return_value=spec), \
                    patch.object(launch.importlib.util,'module_from_spec',return_value=authority),patch.object(launch.os,'execve') as execute:
                launch.main()
            executable,args,environment=execute.call_args.args
            self.assertEqual(executable,args[0]);self.assertEqual(args,launch.arguments('heimdall',value))
            self.assertEqual(environment['SSL_CERT_FILE'],'/etc/polygon/local-ca.pem')
            self.assertEqual(environment['SSL_CERT_DIR'],'/etc/polygon/empty-ca')
            self.assertEqual(set(environment),{'PATH','LANG','HOME','TMPDIR','SSL_CERT_FILE','SSL_CERT_DIR'})
        authority.runtime.assert_called_with('heimdall','amoy')
    def test_unknown_ambient_issuer_directory_refuses_launch(self):
        for info,entries in ((SimpleNamespace(st_mode=stat.S_IFLNK|0o777,st_uid=0),[]),
                (SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0),[]),
                (SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=1000),[]),
                (SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0),['foreign-ca.pem'])):
            with patch.object(launch,'Path',return_value=SimpleNamespace(lstat=lambda:info,iterdir=lambda:iter(entries))):
                with self.assertRaises(ValueError):launch.environment('heimdall',self.metadata('active'))


if __name__=='__main__':unittest.main()
