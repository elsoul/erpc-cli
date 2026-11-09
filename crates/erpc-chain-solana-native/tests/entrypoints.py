#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute generated build entrypoints against inert files, never a compiler.

UID0 and temp-path ancestors are modeled; modes, links, source interpretation,
Python isolation, argv and filesystem markers are real.
"""
import os
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'templates/node'))
import native_build_jobs as jobs
import native_entrypoint as entry
import native_gateway as gateway
import native_proof as proof
import native_runtime_unit as runtime
from mounts import owner
CARRIED_PROGRAM = None


class Entrypoints(unittest.TestCase):
    def test_canonical_program_and_path_domain(self):
        canonical = (ROOT.parent / 'erpc-ssh/src/python-trust.py').read_text()
        self.assertEqual(entry.TRUST, canonical)
        self.assertEqual((ROOT / 'templates/node/native_trust.py').read_text(), canonical)
        for bad in ('/tmp/build.py', '/tmp/native_build.py', '/tmp/'+'a'*64+'/../native_build.py',
                    '/tmp/$bad/'+'a'*64+'/native_build.py'):
            with self.assertRaises(ValueError): entry.build_command(bad)

    def test_actual_fetch_compile_entrypoints_authenticate_before_inert_interpretation(self):
        scenarios = ('safe', 'file-write', 'directory-write', 'ancestor-write', 'symlink', 'hardlink', 'owner', 'fifo')
        for phase in (('carried',) if CARRIED_PROGRAM is not None else ('fetch', 'compile', 'condition', 'guard', 'gateway-condition', 'gateway-guard', 'proof-condition', 'proof-guard')):
            for scenario in scenarios:
                with self.subTest(phase=phase, scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary).resolve(); helper = root / ('a'*64); helper.mkdir()
                    runtime_phase = phase in ('carried', 'condition', 'guard', 'gateway-condition', 'gateway-guard', 'proof-condition', 'proof-guard')
                    path = helper / ('native_runtime_control.py' if runtime_phase else 'native_build.py'); marker = root / 'interpreted'
                    expected_args = ['play'] if phase == 'carried' else ([phase] if runtime_phase else [phase, 'b'*32])
                    evil = root / 'pythonpath'; evil.mkdir(); poison = root / 'poisoned'
                    (evil / 'erpc_entry_fixture.py').write_text('from pathlib import Path\nPath('+repr(str(poison))+').touch()\n')
                    (helper / 'erpc_entry_fixture.py').write_text('VALUE = "trusted sibling"\n')
                    path.write_text('import sys, erpc_entry_fixture\nfrom pathlib import Path\n'
                        'assert sys.argv[1:] == '+repr(expected_args)+'\n'
                        'assert erpc_entry_fixture.VALUE == "trusted sibling"\n'
                        'Path('+repr(str(marker))+').write_text("interpreted")\n')
                    if phase == 'carried':
                        command = shlex.join(['/usr/bin/python3', '-I', '-c', CARRIED_PROGRAM, str(path), 'play'])
                    elif phase in ('proof-condition', 'proof-guard'):
                        with patch.object(proof.helpers, 'RELEASES', root), patch.object(proof, 'OUTPUT', root):
                            unit = proof.definition({'uid':20002,'gid':20002}, 'a'*64, 'b'*32, 'c'*32,
                                                    root / ('bls-public-'+'c'*32+'.txt'))
                        prefix = 'ExecCondition=+' if phase == 'proof-condition' else 'ExecStartPre=+'
                        command = next(line[len(prefix):] for line in unit.splitlines() if line.startswith(prefix))
                    elif phase in ('gateway-condition', 'gateway-guard'):
                        with patch.object(gateway.helpers,'RELEASES',root),patch.object(gateway.helpers,'verify',return_value=helper):
                            account={'name':'erpc-solana-gateway','home':'/var/lib/erpc-solana-gateway','shell':'/usr/sbin/nologin','uid':20004,'gid':20004}
                            unit=gateway.definition(account,'a'*64).decode()
                        prefix='ExecCondition=+' if phase=='gateway-condition' else 'ExecStartPre=+'
                        command=next(line[len(prefix):] for line in unit.splitlines() if line.startswith(prefix))
                    elif phase in ('condition', 'guard'):
                        with patch.object(runtime, 'HELPERS', root):
                            unit = runtime.render(owner(), json.loads((ROOT / 'templates/node/catalog.json').read_bytes()),
                                                  'b'*32, 'a'*64, 'sync', '5'*44, {'uid':20001,'gid':20001})
                        prefix = 'ExecCondition=+' if phase == 'condition' else 'ExecStartPre=+'
                        command = next(line[len(prefix):] for line in unit.splitlines() if line.startswith(prefix))
                    else:
                        with patch.object(jobs, 'HELPERS', root):
                            _, unit = jobs.unit('a'*64, 'b'*32, phase)
                        command = next(line[len('ExecStart='):] for line in unit.splitlines() if line.startswith('ExecStart='))
                    argv = shlex.split(command); argv = argv[argv.index('/usr/bin/python3'):]
                    self.assertEqual(argv[:3], ['/usr/bin/python3', '-I', '-c'])
                    self.assertEqual(argv[4:], [str(path), 'play'] if phase == 'carried' else expected_args)
                    if phase == 'carried': program = argv[3]
                    else:
                        encoded = argv[3].removeprefix("exec(bytes.fromhex('").removesuffix("'))")
                        self.assertTrue(all(char in '0123456789abcdef' for char in encoded))
                        program = bytes.fromhex(encoded).decode()
                    self.assertTrue(program.startswith(entry.TRUST))
                    if scenario == 'file-write': path.chmod(0o666)
                    if scenario == 'directory-write': helper.chmod(0o777)
                    if scenario == 'ancestor-write': root.chmod(0o777)
                    if scenario == 'symlink':
                        moved = root / 'inert'; path.rename(moved); path.symlink_to(moved)
                    if scenario == 'hardlink': os.link(path, root / 'alias')
                    if scenario == 'fifo': path.unlink(); os.mkfifo(path)
                    model = '''import os
from pathlib import Path
from types import SimpleNamespace
original_lstat = os.lstat
fixture_root = Path(ROOT)
fixture_target = Path(TARGET)
def metadata(path, *args, **kwargs):
    fields = list(original_lstat(path, *args, **kwargs)); candidate = Path(path)
    if candidate == fixture_root or fixture_root in candidate.parents:
        if fields[4] == os.getuid(): fields[4] = 0
        if SCENARIO == 'owner' and candidate == fixture_target: fields[4] = 2
    elif candidate in fixture_root.parents:
        fields[4] = 0; fields[0] &= ~0o022
    return os.stat_result(fields)
os.lstat = metadata
original_scandir = os.scandir
def entries(directory):
    with original_scandir(directory) as stream:
        return [SimpleNamespace(name=item.name, path=item.path,
            stat=lambda *, follow_symlinks=True, path=item.path: metadata(path)) for item in stream]
os.scandir = entries
'''.replace('ROOT', repr(str(root))).replace('TARGET', repr(str(path))).replace('SCENARIO', repr(scenario))
                    environment = dict(os.environ, PYTHONPATH=str(evil), PYTHONDONTWRITEBYTECODE='1')
                    result = subprocess.run([argv[0], '-I', '-c', model + program, *argv[4:]],
                                            env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode == 0, scenario == 'safe', result.stderr.decode())
                    if phase in ('condition','gateway-condition','proof-condition') and scenario != 'safe': self.assertEqual(result.returncode, 255)
                    self.assertEqual(marker.exists(), scenario == 'safe')
                    self.assertFalse(poison.exists())

if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--carried':
        CARRIED_PROGRAM = sys.argv[2]
        sys.argv = [sys.argv[0]]
    unittest.main()
