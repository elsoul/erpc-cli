# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Run actual rendered systemd inline programs before inert script interpretation.

Only installation paths, expected-root UID and unrelated temporary-directory
ancestors are modeled. Target file/directory modes, links and program bytes are
real. No sudo, client, node, credential or host configuration is used.
"""
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile

with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()),mode='r:gz') as archive:
    node=archive.extractfile('node/erpc-kaia.service').read().decode()
    firewall=archive.extractfile('node/firewall.service.j2').read().decode().replace('{{ kaia_systemd_control }}',sys.argv[1])
commands=[line.partition('=')[2] for text in (node,firewall) for line in text.splitlines() if line.startswith(('ExecStart=','ExecStartPre=','ExecStop='))]
assert len(commands)==4
for command in commands:
    argv=shlex.split(command)
    assert argv[:3]==['/usr/bin/python3','-I','-c'] and len(argv)==5
    encoded=argv[3].removeprefix("exec(bytes.fromhex('").removesuffix("'))")
    assert all(c in '0123456789abcdef' for c in encoded)
    original=bytes.fromhex(encoded).decode()
    prefix="runpy.run_path('";installed=original.rsplit(prefix,1)[1].split("'",1)[0]
    assert installed.startswith('/usr/local/lib/erpc/kaia/releases/') and '/current/' not in installed
    for scenario in ('safe','file-write','directory-write','ancestor-write','symlink','hardlink','owner'):
        with tempfile.TemporaryDirectory(prefix='kaia-entrypoint-') as temporary:
            root=Path(temporary).resolve();directory=root/'release';directory.mkdir()
            path=directory/'control.py';marker=root/'interpreted'
            path.write_text('from pathlib import Path\nPath('+repr(str(marker))+').write_text("interpreted")\n')
            if scenario=='file-write':path.chmod(0o666)
            if scenario=='directory-write':directory.chmod(0o777)
            if scenario=='ancestor-write':root.chmod(0o777)
            if scenario=='symlink':
                moved=root/'inert';path.rename(moved);path.symlink_to(moved)
            if scenario=='hardlink':os.link(path,root/'alias')
            program=original.replace(installed,str(path)).replace(str(Path(installed).parent),str(directory))
            setup='''import os
from pathlib import Path
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
from types import SimpleNamespace
def entries(directory):
    with original_scandir(directory) as stream:
        return [SimpleNamespace(name=entry.name,path=entry.path,
            stat=lambda *,follow_symlinks=True,p=entry.path:metadata(p)) for entry in stream]
os.scandir=entries
'''.replace('ROOT',repr(str(root))).replace('TARGET',repr(str(path))).replace('SCENARIO',repr(scenario))
            result=subprocess.run([argv[0],'-I','-c',setup+program,*argv[4:]],capture_output=True,timeout=10,check=False)
            assert (result.returncode==0)==(scenario=='safe'),(scenario,result.stderr.decode())
            assert marker.exists()==(scenario=='safe'),scenario
print(json.dumps({'rendered_entries':len(commands),'inert_execution_scenarios':len(commands)*7}))
