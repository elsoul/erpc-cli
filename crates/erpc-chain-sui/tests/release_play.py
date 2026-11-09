# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled production bundles and migration routing; optional pinned Ansible composition."""
import contextlib
import importlib.machinery
import importlib.util
import io
import copy
import shutil
import json
import sys
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode = True
documents = json.load(sys.stdin)
try:
    from ansible import release
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar
except ImportError:
    Templar = None
else:
    assert release.__version__ == '2.18.19'
sys.path.insert(0, str(Path(__file__).parent))
from release_test import Fixture

for document in documents:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(bytes(document['bundle'])), mode='r:gz') as archive:
            for member in archive.getmembers():
                target = root / member.name
                assert member.isfile() and target.resolve().is_relative_to(root.resolve())
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.extractfile(member).read())
        inventory = json.loads((root / 'inventory.yml').read_text())['all']['hosts']['fixture']
        assert inventory['sui_source_history'] == document['history']
        assert inventory['sui_phase'] == document['operation']
        assert inventory['sui_release_pin']['version'] == ('testnet-v1.83.1' if document['network'] == 'testnet' else 'mainnet-v1.82.3')
        assert (root / 'jinja/erpc-sui-release.py.j2').is_file()
        for name in ('control', 'release', 'account'):
            relative = 'jinja/erpc-sui-' + name + '.py.j2'
            assert (root / relative).read_bytes() == (Path(__file__).parents[1] / 'templates' / relative).read_bytes(), 'compiled helper is stale'
        deploy = (root / 'ansible/sui-node/deploy.yml').read_text()
        assert deploy.index('check-source') < deploy.index('begin-intent') < deploy.index('qualify-release') < deploy.index('Select the reviewed release')
        for name in ('sui-node.service', 'sui-bootstrap.service'):
            assert (' open-bootstrap ' if name.startswith('sui-bootstrap') else ' open-release ') in (root / ('jinja/' + name + '.j2')).read_text()
        if Templar is None:
            continue
        loader = DataLoader()
        inventory['sui_jinja'] = str(root / 'jinja')
        original_evidence = copy.deepcopy(document['history'] or document['origin'])
        migration = loader.load((root / 'ansible/sui-node/migrate-source-history.yml').read_text())[0]
        assert len(migration['tasks']) == 1
        migration_vars = dict(inventory, sui_source_history=original_evidence)
        rendered = Templar(loader=loader, variables=migration_vars).template(migration['tasks'][0]['ansible.builtin.command'])
        assert rendered['argv'][3:] == ['migrate-source-history', document['network'], document['role'], original_evidence['contract']['genesis']]
        assert json.loads(rendered['stdin']) == original_evidence
        with Fixture(source=root / 'jinja') as fixture:
            # Only artifacts/NSS/PID1/nft effects are inert. Use the extracted
            # compiled controller for real state, archive and quarantine work.
            fixture.expected = original_evidence['contract']
            fixture.record['contract'] = fixture.expected
            fixture.c.write('/etc/sui/original-account.json', fixture.record)
            fixture.c.write('/etc/sui/contract.json', dict(fixture.expected, original_account=fixture.record, authority_protocol=2))
            fixture.c.path(fixture.r.HISTORY + '/scope.json').unlink()
            fixture.c.path(fixture.r.HISTORY).rmdir()
            if document['operation'] == 'recover-update': fixture.bootstrap_only()
            if document['role'] == 'validator': fixture.validator_receipt()
            original = fixture.artifact(original_evidence['highest_opened']['version']); fixture.select(original)
            original_evidence['highest_opened'] = original
            def dispatch(command):
                payload = command.get('stdin', '')
                supplied = type('Input', (), {'buffer': io.BytesIO(payload.encode())})()
                argv = command['argv']
                assert argv[:2] == ['/usr/bin/python3', '-I'] and Path(argv[2]) == root / 'jinja/erpc-sui-control.py.j2'
                assert argv[4:7] == [fixture.expected['network'], fixture.expected['role'], fixture.expected['genesis']]
                with patch.object(sys, 'stdin', supplied), contextlib.redirect_stdout(io.StringIO()):
                    fixture.c.dispatch(argv[3], fixture.expected, argv[7] if len(argv) == 8 else None)
            rendered['stdin'] = json.dumps(original_evidence)
            dispatch(rendered)
            assert fixture.stopped.call_count > 0
            assert json.loads(fixture.c.path('/etc/sui/contract.json').read_text())['authority_protocol'] == 3
            assert fixture.c.path('/etc/sui/stopped').exists()
            assert fixture.r.claims(fixture.c, fixture.expected) == [original]
            if document['operation'] == 'recover-update':
                candidate = fixture.artifact(inventory['sui_release_pin']['version'])
                variables = dict(inventory, sui_release_pin=candidate)
                play = loader.load((root / 'ansible/sui-node/deploy.yml').read_text())[0]
                actions = []
                with patch.object(fixture.module.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(10**13, 0, 10**13)):
                    for task in play['tasks']:
                        value = task.get('ansible.builtin.command')
                        if not isinstance(value, dict) or 'argv' not in value: continue
                        command = Templar(loader=loader, variables=variables).template(value)
                        action = command['argv'][3] if len(command['argv']) > 3 else None
                        if action in ('check-source', 'recover-owned', 'begin-intent', 'qualify-release'):
                            dispatch(command); actions.append(action)
                assert actions == ['check-source', 'recover-owned', 'begin-intent', 'qualify-release']
                retained = list(fixture.c.path('/var/lib/sui').glob('db.quarantine.*/live/original'))
                assert len(retained) == 1 and (retained[0].read_bytes(), retained[0].stat().st_ino) == fixture.original[:2]
                fixture.confirm_generation(candidate, inventory['sui_confirmation_id'], already_begun=True)
                fixture.c.dispatch('open-bootstrap', fixture.expected)
                assert not fixture.r.native_used(fixture.c)
                assert {value['version'] for value in fixture.r.claims(fixture.c, fixture.expected)} == {original['version'], candidate['version']}
                for path, raw, inode in fixture.retained:
                    assert (path.read_bytes(), path.stat().st_ino) == (raw, inode)
            assert fixture.cipher.read_bytes() == fixture.original[2]
print('eight compiled migration/recovery bundles and source-opening routes passed' + (' with pinned Ansible actual-controller composition' if Templar else '; pinned Ansible composition requires its qualified runtime'))
