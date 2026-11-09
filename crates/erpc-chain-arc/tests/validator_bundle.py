#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled caller bundle -> generated external entries, with inert file effects.

The root-UID projection adapts the reviewed Arc70 entrypoint fixture. Only owner
metadata and virtual paths are modeled; real modes, links, hashes, and loaded
bytes drive refusal. No node, secret, NSS mutation or systemd operation runs.
"""
import hashlib
import io
import json
import os
import pathlib
import runpy
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
from unittest import mock

sys.dont_write_bytecode = True
DOCUMENT = json.load(sys.stdin)
SETUP = r'''import os
from pathlib import Path
from types import SimpleNamespace
original_lstat=os.lstat
fixture_root=Path(ROOT)
fixture_target=Path(TARGET)
fixture_uid=os.getuid()
def metadata(path,*args,**kwargs):
    value=original_lstat(path,*args,**kwargs);fields=list(value);candidate=Path(path)
    if candidate==fixture_root or fixture_root in candidate.parents:
        if fields[4]==fixture_uid:fields[4]=0
        if SCENARIO=='owner' and candidate==fixture_target:fields[4]=2
    elif candidate in fixture_root.parents:
        fields[4]=0;fields[0]&=~0o022
    return os.stat_result(fields)
os.lstat=metadata
original_scandir=os.scandir
def entries(directory):
    with original_scandir(directory) as stream:
        return [SimpleNamespace(name=entry.name,path=entry.path,
            stat=lambda *,follow_symlinks=True,p=entry.path:metadata(p)) for entry in stream]
os.scandir=entries
'''


def unpack(directory):
    with tarfile.open(fileobj=io.BytesIO(bytes(DOCUMENT['bundle'])), mode='r:gz') as archive:
        for member in archive.getmembers():
            destination = directory / member.name
            assert member.isfile() and not member.issym() and member.size < 1048576
            assert destination.resolve().is_relative_to(directory.resolve())
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.extractfile(member).read())
            destination.chmod(0o644)
    document = json.loads((directory / 'inventory.yml').read_text())
    hosts = document['all']['hosts']
    assert len(hosts) == 1
    return next(iter(hosts.values()))


def generated_entries(directory, variables):
    folder = directory / 'validator'
    sys.path.insert(0, str(folder))
    import av_helpers
    import av_units
    import av_admission
    original_hash = hashlib.sha256(b''.join((folder / name).read_bytes()
                                          for name in av_helpers.profile(folder))).hexdigest()
    assert variables['arc_validator_helpers'] == original_hash
    assert (folder / 'networks.json').is_file()
    assert len(av_helpers.profile(folder)) > 16
    (folder / 'control.py').write_text('from pathlib import Path\nPath(MARKER).write_text("interpreted")\n')
    identity = hashlib.sha256(b''.join((folder / name).read_bytes()
                                     for name in av_helpers.profile(folder))).hexdigest()
    state = {'contract': variables['arc_validator_contract'], 'accounts':
             {'execution': 997, 'consensus': 996, 'engine': 995}, 'signer_used': False}
    for intent in DOCUMENT['governance']:
        selector, raw = av_admission.public_intent(state, intent)
        assert selector == intent['data'][2:10] and raw.hex() == intent['data'][2:]
    source = {'images': {name: 'a' * 64 for name in ('arc-node-execution', 'arc-node-consensus', 'arc-snapshots')}}
    with mock.patch.object(av_units.release, 'qualify', return_value=source):
        units, _ = av_units.make(types.SimpleNamespace(), state, DOCUMENT['source'], DOCUMENT['policy'], folder, identity)
    commands = []
    for component, text in units.items():
        number = '996' if component == 'consensus' else '997'
        assert 'User=' + number + '\n' in text
        assert 'LimitCORE=0\n' in text
        if component != 'consensus':
            assert 'LoadCredential' not in text
        for line in text.splitlines():
            if line.startswith(('ExecCondition=', 'ExecStartPre=', 'ExecStartPost=')):
                commands.append((line.partition('=')[2].lstrip('+'), True))
    commands.append((av_helpers.systemd_command(folder, identity, 'firewall-load', 'firewall'), True))
    commands.append((DOCUMENT['ssh'].removeprefix('sudo -n '), False))
    assert len(commands) == 9
    return folder, identity, commands


def exercise(folder, identity, command, condition, scenario):
    argv = shlex.split(command)
    assert argv[:3] == ['/usr/bin/python3', '-I', '-c'] and len(argv) == 4
    raw = argv[3]
    if raw.startswith("exec(bytes.fromhex('"):
        raw = bytes.fromhex(raw.split("'", 2)[1]).decode()
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary).resolve()
        namespace = root / 'namespace'
        destination = namespace / 'releases' / identity
        destination.parent.mkdir(parents=True)
        shutil.copytree(folder, destination)
        (namespace / 'current').symlink_to('releases/' + identity)
        target = destination / 'control.py'
        marker = root / 'interpreted'
        if scenario == 'file-write': target.chmod(0o666)
        if scenario == 'directory-write': destination.chmod(0o777)
        if scenario == 'ancestor-write': namespace.chmod(0o777)
        if scenario == 'symlink':
            target.rename(root / 'outside'); target.symlink_to(root / 'outside')
        if scenario == 'hardlink': os.link(target, root / 'alias')
        if scenario == 'hash': target.write_text(target.read_text() + '# changed\n')
        setup = SETUP.replace('ROOT', repr(str(root))).replace('TARGET', repr(str(target))).replace('SCENARIO', repr(scenario))
        setup += ('\nimport runpy\noriginal_run=runpy.run_path\ndef run(path,**kwargs):\n'
                  ' return original_run(path,init_globals={"MARKER":' + repr(str(marker)) + '},**kwargs)\nrunpy.run_path=run\n')
        program = raw.replace('/usr/local/lib/erpc/arc-validator', str(namespace))
        result = subprocess.run([sys.executable, '-I', '-c', setup + program], capture_output=True, timeout=10)
        assert marker.exists() == (scenario == 'safe'), (scenario, result.stderr.decode())
        assert (result.returncode == 0) == (scenario == 'safe'), (scenario, result.stderr.decode())
        if scenario != 'safe' and condition:
            assert result.returncode == 255, (scenario, result.returncode)


with tempfile.TemporaryDirectory() as temporary:
    directory = pathlib.Path(temporary).resolve()
    variables = unpack(directory)
    assert variables['arc_validator_contract']['public_key'] != variables['arc_validator_contract']['peer_public_key']
    assert variables['arc_validator_archive_sha256'] == DOCUMENT['source']['archive_sha256']
    assert 'tcp dport 2223 ' in variables['arc_validator_firewall']
    assert 'validator/' not in variables['arc_validator_loader']  # Script path is a separate argv value.
    folder, identity, commands = generated_entries(directory, variables)
    for command, condition in commands:
        for scenario in ('safe', 'file-write', 'directory-write', 'ancestor-write', 'symlink', 'hardlink', 'owner', 'hash'):
            exercise(folder, identity, command, condition, scenario)
print('compiled validator bundle and 72 generated-entrypoint scenarios passed')
