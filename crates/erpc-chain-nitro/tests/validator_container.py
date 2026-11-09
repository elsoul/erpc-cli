#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Inert Docker inspection fixtures exercise the actual process-proof caller."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/validator/node'))
import container
import protocol


class Container(unittest.TestCase):
    def setUp(self):
        self.contract = {'owner': 'a'*26, 'family': 'arbitrum', 'network': 'mainnet', 'platform': 'amd64',
                         'role': 'assertion-validator', 'wallet': '0x'+'1'*40, 'creation': 'b'*32,
                         'host_binding': 'c'*64, 'data_uuid': '00000000-0000-0000-0000-000000000001'}
        self.generation = 'd'*32; self.identity = 'e'*64
        self.target = {'phase': 'active', 'version': protocol.VERSION, 'commit': protocol.COMMIT,
                       'image': protocol.IMAGE, 'image_id': protocol.IMAGE_ID, 'helpers_sha256': 'a'*64, 'config_id': 'b'*64}
        self.account = {'uid': 20000, 'gid': 20000}
        self.image = {'Config': {'Env': ['PATH=/usr/local/bin:/usr/bin:/bin']}}
        self.value = {'Id': self.identity, 'Name': '/erpc-arbitrum-validator', 'Image': protocol.IMAGE_ID,
            'Config': {'Image': protocol.IMAGE, 'User': '20000:20000', 'Entrypoint': ['/usr/local/bin/nitro'],
                'Cmd': ['--conf.file=/config/node.json,/run/wallet.json'], 'WorkingDir': '/data',
                'OpenStdin': False, 'Tty': False, 'Env': ['PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/data','SSL_CERT_FILE=/config/parent-ca.pem','SSL_CERT_DIR=/etc/ssl/certs'],
                'Labels': container.labels(self.contract, self.generation, self.target)},
            'HostConfig': {'NetworkMode': 'host', 'UsernsMode': 'host', 'ReadonlyRootfs': True,
                'IpcMode':'private','CgroupnsMode':'private','Init':False,'LogConfig':{'Type':'local','Config':{'max-size':'20m','max-file':'5'}},
                'Privileged': False, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'],
                'RestartPolicy': {'Name': 'no'}, 'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=2147483648,mode=1777'}},
            'State': {'Running': True, 'Pid': 1234, 'Paused': False, 'Restarting': False, 'Dead': False},
            'Mounts': [{'Type': 'bind', 'Propagation': 'rprivate', 'Source': '/var/lib/erpc-nitro/data', 'Destination': '/data', 'RW': True},
                       {'Type': 'bind', 'Propagation': 'rprivate', 'Source': '/etc/erpc/arbitrum-validator/public', 'Destination': '/config', 'RW': False},
                       {'Type': 'bind', 'Propagation': 'rprivate', 'Source': '/run/erpc-arbitrum-validator/wallet/wallet.json', 'Destination': '/run/wallet.json', 'RW': False}]}
        self.record = {'contract': self.contract, 'generation': self.generation, 'target': self.target,
                       'account': self.account, 'container_id': self.identity}

    def qualify(self, value):
        return container.qualify(value, self.contract, self.generation, self.target, self.account, self.image, running=True)

    def test_exact_native_profile_and_original_numeric_user(self):
        self.assertEqual(self.qualify(self.value), self.identity)
        args = container.create_args(self.contract, self.generation, self.target, self.account)
        self.assertIn('--user=20000:20000', args); self.assertIn('--pull=never', args)
        self.assertIn('--read-only', args); self.assertIn('--userns=host', args)
        self.assertIn('--env=SSL_CERT_FILE=/config/parent-ca.pem',args)
        self.assertIn('--env=SSL_CERT_DIR=/etc/ssl/certs',args)
        self.assertFalse(any('private-key' in value for value in args))

    def test_same_name_reply_never_substitutes_for_content_or_privilege_proof(self):
        cases = [('Image', None, 'sha256:'+'f'*64), ('Config', 'User', 'root'),
                 ('Config', 'Cmd', ['--dangerous']), ('Config', 'Env', ['LD_PRELOAD=/data/evil']),
                 ('HostConfig', 'Privileged', True), ('HostConfig', 'GroupAdd', ['docker']),
                 ('HostConfig', 'UsernsMode', ''), ('HostConfig', 'PidMode', 'host'), ('HostConfig','IpcMode','host'),
                 ('HostConfig','ExtraHosts',['inert:127.0.0.2']),
                 ('HostConfig', 'Binds', ['/run/docker.sock:/run/docker.sock']),
                 ('HostConfig', 'Devices', [{'PathOnHost': '/dev/sda'}]),
                 ('State', 'Running', False), ('State', 'Pid', 0)]
        for section, key, value in cases:
            with self.subTest(section=section, key=key):
                bad = deepcopy(self.value)
                if key is None: bad[section] = value
                else: bad[section][key] = value
                with self.assertRaises(ValueError): self.qualify(bad)
        bad = deepcopy(self.value); bad['Mounts'][2]['RW'] = True
        with self.assertRaises(ValueError): self.qualify(bad)
        bad = deepcopy(self.value); bad['Config']['Labels'][container.LABEL+'generation'] = 'f'*32
        with self.assertRaises(ValueError): self.qualify(bad)

    def test_composed_runtime_rechecks_container_and_pid_after_socket_proof(self):
        proof = {'pid': 1234, 'start_time': 789, 'cgroup': '/system.slice/docker-'+self.identity+'.scope'}
        with patch.object(container, 'image', return_value=self.image), \
             patch.object(container, 'observe', return_value=self.value) as observe, \
             patch.object(container.processes, 'snapshot', return_value=proof) as snapshot, \
             patch.object(container.processes, 'container_members') as members, \
             patch.object(container.processes, 'listeners') as listeners, \
             patch.object(container.processes, 'identity', return_value={'start_time': 789}):
            self.assertEqual(container.prove(self.record)['container_id'], self.identity)
            self.assertEqual(observe.call_count, 2); self.assertEqual(snapshot.call_count, 1)
            members.assert_called_once_with(self.account, 1234, proof['cgroup'])
            listeners.assert_called_once_with(1234, 20000, (8547, 8548, 8549, 6070))
            replacement = deepcopy(self.value); replacement['State']['Pid'] = 999
            observe.side_effect = [self.value, replacement]
            with self.assertRaisesRegex(ValueError, 'changed'): container.prove(self.record)
            observe.side_effect = None; observe.return_value = deepcopy(self.value)
            observe.return_value['Config']['User'] = '2001:2001'; snapshot.reset_mock()
            with self.assertRaises(ValueError): container.prove(self.record)
            snapshot.assert_not_called()

    def test_same_process_validation_socket_loss_or_rebind_refuses_the_actual_container_proof(self):
        import validator_processes
        fixture = validator_processes.Processes(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.argv = [container.BINARY, *container.arguments('active')]
        fixture.group = '/system.slice/docker-' + self.identity + '.scope'
        path = fixture.process(pid=1234)
        for port in (8547, 8548, 8549, 6070):
            fixture.listen(path, port=port, inode=port)
        with patch.object(container, 'image', return_value=self.image), \
             patch.object(container, 'observe', return_value=self.value):
            self.assertEqual(container.prove(self.record)['container_id'], self.identity)
            # Another process could bind an auth endpoint that answers RPC;
            # absence from the original PID's FD table still refuses it.
            (path/'fd/8549').unlink()
            with self.assertRaises(ValueError): container.prove(self.record)
            (path/'fd/8549').symlink_to('socket:[8549]')
            (path/'net/tcp').write_text('header\n')
            for port in (8547, 8548, 6070):
                fixture.listen(path, port=port, inode=port, descriptor=False)
            with self.assertRaises(ValueError): container.prove(self.record)


if __name__ == '__main__': unittest.main()
