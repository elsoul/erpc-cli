#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute the actual SSH probe on inert state; only root metadata is modeled."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.dont_write_bytecode = True
program = sys.argv[1]
contract = {'name': 'inert', 'profile': 'agave-native-rpc'}
scenarios = ('safe', 'missing', 'partial', 'foreign-contract', 'writable-file', 'writable-parent',
             'hardlink', 'file-link', 'foreign-owner', 'duplicate', 'null', 'bad-revision',
             'migration-before-owner','migration-pending','migration-complete','migration-missing','migration-foreign')
for scenario in scenarios:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve(); directory = root / 'state'; directory.mkdir()
        owner = directory / 'owner.json'
        owner.write_text(json.dumps({'contract': contract, 'initialized': scenario != 'partial'})); owner.chmod(0o600)
        helper = directory / 'helper-revision.json'; helper.write_text(json.dumps({'revision': 'a'*64})); helper.chmod(0o600)
        if scenario == 'partial': helper.unlink()
        if scenario == 'missing': owner.unlink()
        if scenario == 'foreign-contract': owner.write_text(json.dumps({'contract': {'name': 'other'}, 'initialized': True}))
        if scenario == 'writable-file': owner.chmod(0o666)
        if scenario == 'writable-parent': directory.chmod(0o777)
        if scenario == 'hardlink': os.link(owner, root / 'alias')
        if scenario == 'file-link': owner.rename(root / 'outside'); owner.symlink_to(root / 'outside')
        if scenario == 'duplicate': owner.write_text('{"contract":{},"contract":{},"initialized":true}')
        if scenario == 'null': owner.write_text('null')
        if scenario == 'bad-revision': helper.write_text('{"revision":"../escape"}')
        if scenario.startswith('migration-'):
            scope={'intent':'b'*32,'source_sha256':'c'*64}
            owner.write_text(json.dumps({'contract':contract,'initialized':True,'migration':scope,'initial_halt':'d'*32}))
            marker=directory/'migration.json'
            marker.write_text(json.dumps({'contract':contract,'scope':scope,'phase':'complete' if scenario=='migration-complete' else 'preparing'}));marker.chmod(0o600)
            if scenario=='migration-before-owner':owner.unlink()
            if scenario=='migration-missing':marker.unlink()
            if scenario=='migration-foreign':marker.write_text(json.dumps({'contract':{'name':'foreign'},'scope':scope,'phase':'preparing'}))
        model = '''import os
from pathlib import Path
real_lstat=Path.lstat
real_fstat=os.fstat
fixture=Path(FIXTURE)
def metadata(path,*args,**kwargs):
    value=list(real_lstat(path,*args,**kwargs));value[4]=0
    if path in fixture.parents:value[0]&=~0o022
    return os.stat_result(value)
def descriptor(fd):
    value=list(real_fstat(fd));value[4]=3 if FOREIGN else 0
    return os.stat_result(value)
Path.lstat=metadata
os.fstat=descriptor
'''.replace('FIXTURE', repr(str(root))).replace('FOREIGN', repr(scenario == 'foreign-owner'))
        result = subprocess.run([sys.executable, '-I', '-c', model + program.replace('/var/lib/erpc-solana/state', str(directory))],
            input=json.dumps({'contract': contract}).encode(), capture_output=True, timeout=10)
        assert (result.returncode == 0) == (scenario in ('safe', 'missing', 'partial','migration-before-owner','migration-pending','migration-complete')), (scenario, result.stderr)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            assert value['reserved'] == (scenario != 'missing')
            assert value['initialized'] == (scenario in ('safe','migration-complete'))
            assert value['helper_revision'] == ('a'*64 if scenario in ('safe','migration-complete') else None)
        else:
            assert result.stdout == b'' and result.stderr == b'Native Solana ownership inspection failed\n'
print(str(len(scenarios))+' actual native SSH ownership probe scenarios passed')
