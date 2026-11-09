# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual generated systemd argv against inert files; no sudo, service or node.

Only root UID and the ancestors outside the fixture are modeled. Real descriptor
opens, modes, symlinks, hardlinks and concurrent-source mutation are exercised.
"""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
sys.dont_write_bytecode = True
UNIT = json.load(sys.stdin)['unit']
SETUP = r'''
import os
from pathlib import Path
from types import SimpleNamespace
original_fstat = os.fstat
target = Path(TARGET)
fixture = Path(FIXTURE)
identity = target.stat()
reads = 0
def inspect(fd):
    global reads
    value = original_fstat(fd)
    fields = {name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
    fields['st_uid'] = 0
    # The temporary test's containing directories are not system root paths.
    # Model their protected ancestry, retaining every mode inside the fixture.
    ancestors = [p.stat() for p in fixture.parents]
    if any((value.st_dev,value.st_ino)==(p.st_dev,p.st_ino) for p in ancestors):
        fields['st_mode'] &= ~0o022
    if (value.st_dev,value.st_ino)==(identity.st_dev,identity.st_ino):
        reads += 1
        if SCENARIO == 'owner': fields['st_uid'] = 9
        if SCENARIO == 'changed-read' and reads == 1:
            target.write_text(target.read_text() + '# changed\n')
    return SimpleNamespace(**fields)
os.fstat = inspect
'''


class Entrypoint(unittest.TestCase):
    def test_generated_guard_authenticates_opened_bytes_before_interpretation(self):
        line = next(line.partition('=')[2] for line in UNIT.splitlines()
                    if line.startswith('ExecStartPre='))
        argv = shlex.split(line.lstrip('+'))
        self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-c'])
        self.assertEqual(argv[4:], ['guard'])
        source = bytes.fromhex(argv[3].split("'", 2)[1]).decode()
        for scenario in ('safe','file-write','parent-write','ancestor-write',
                         'symlink','hardlink','owner','changed-read'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                directory = root / 'managed' / 'helpers'
                directory.mkdir(parents=True)
                target = directory / 'bitcoin-control'
                marker = root / 'interpreted'
                target.write_text('open(' + repr(str(marker)) + ',"w").write("inert")\n')
                target.chmod(0o644)
                if scenario == 'file-write': target.chmod(0o666)
                if scenario == 'parent-write': directory.chmod(0o777)
                if scenario == 'ancestor-write': directory.parent.chmod(0o777)
                if scenario == 'symlink':
                    target.rename(root / 'outside')
                    target.symlink_to(root / 'outside')
                if scenario == 'hardlink': os.link(target, root / 'alias')
                setup = SETUP.replace('TARGET',repr(str(target))).replace('FIXTURE',repr(str(root))).replace('SCENARIO',repr(scenario))
                program = source.replace('/usr/local/lib/erpc/bitcoin-control',str(target))
                result = subprocess.run([sys.executable,'-I','-c',setup + program,'guard'],
                                        capture_output=True,timeout=10)
                self.assertEqual(result.returncode == 0, scenario == 'safe', result.stderr.decode())
                self.assertEqual(marker.exists(), scenario == 'safe')
        print('8 actual generated Bitcoin systemd entrypoint scenarios passed')


if __name__ == '__main__': unittest.main()
