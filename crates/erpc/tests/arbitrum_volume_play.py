# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled Rust bundle -> actual carried entry/play/dispatch -> public result.

Filesystem receipts and source bytes are real. The existing author's volume
fixture supplies inert NSS/process/mount observations. Only the outer sealed
entry's root UID/ancestry is modeled during its trusted_imports call; no carried
source is edited. No native process, credential, mount or transaction is used.
"""
import contextlib
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2] / 'erpc-chain-nitro'
sys.path.insert(0, str(ROOT / 'tests'))
from validator_volumes import Volumes
import control
import installer
import locking
import protocol
import publication
import storage


@contextlib.contextmanager
def modeled_entry_uid(entry, anchor):
    """Keep the canonical entry program intact; virtualize only its root gate."""
    previous = sys.getprofile()
    active = []
    raw_lstat, raw_scan = os.lstat, os.scandir
    def metadata(path, info):
        fields = list(info)
        fields[4] = 0
        if Path(path) in anchor.parents:
            fields[0] &= ~0o022
        return os.stat_result(fields)
    class Entries:
        def __init__(self, directory): self.iterator = raw_scan(directory)
        def __enter__(self): return self
        def __exit__(self, *args): self.iterator.close()
        def __iter__(self): return self
        def __next__(self):
            item = next(self.iterator)
            return SimpleNamespace(name=item.name, path=item.path,
                stat=lambda *,follow_symlinks=False: metadata(item.path,item.stat(follow_symlinks=follow_symlinks)))
    def profile(frame, event, _argument):
        if frame.f_code.co_filename != str(entry) or frame.f_code.co_name != 'trusted_imports':
            return
        if event == 'call':
            active.extend((patch.object(os,'lstat',side_effect=lambda path,*a,**kw:metadata(path,raw_lstat(path,*a,**kw))),
                           patch.object(os,'scandir',side_effect=Entries)))
            for item in active: item.start()
        elif event == 'return':
            while active: active.pop().stop()
    sys.setprofile(profile)
    try: yield
    finally:
        sys.setprofile(previous)
        while active: active.pop().stop()


def invoke(entry, arguments, request, anchor):
    stdout, stderr = io.StringIO(), io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(storage.encode(request)))
    code = 0
    with patch.object(sys,'argv',[str(entry),*arguments]), patch.object(sys,'stdin',stdin), \
         contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), modeled_entry_uid(entry,anchor):
        try: runpy.run_path(str(entry),run_name='__main__')
        except SystemExit as result: code = result.code
    return code, stdout.getvalue(), stderr.getvalue()


def exercise(raw):
    fixture = Volumes('runTest'); fixture.setUp()
    try:
        original = fixture.legacy()
        fixture.offset = 23
        root = fixture.f.root
        run = root/'runs/r-original-volume-upgrade'
        bundle = run/'bundle'; bundle.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive.getmembers():
                path = Path(member.name)
                assert member.isfile() and not path.is_absolute() and '..' not in path.parts
                destination = bundle/path; destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
        (run/'bundle.tar.gz').write_bytes(raw)
        inventory = json.loads((bundle/'inventory.yml').read_bytes())
        hosts = inventory['all']['hosts']; assert len(hosts) == 1
        request = next(iter(hosts.values()))['validator_request']
        assert request['contract'] == fixture.expected
        assert request == {'action':'upgrade-volume-authority','contract':fixture.expected,'original_root':None}
        source = bundle/'validator/node'
        # The fixture instruments already-imported host modules. Require every
        # cached helper to be byte-identical to this compiled carried profile,
        # so a stale bundle can never pass by borrowing newer local code.
        for path in source.glob('*.py'):
            module = sys.modules.get(path.stem)
            if module is not None:
                assert Path(module.__file__).read_bytes() == path.read_bytes(), path.name
        play = bundle/'validator/ansible/control.yml'
        text = play.read_text()
        encoded = re.search(r'argv: \[(.+)\]',text).group(1)
        argv = next(csv.reader([encoded],skipinitialspace=True))
        argv = [value.replace('{{ playbook_dir }}',str(play.parent)) for value in argv]
        assert argv[:2] == ['/usr/bin/python3','-I']
        assert '{{ validator_request | to_json }}' in text
        entry = Path(argv[2]); assert entry.resolve() == source/'entry.py'
        try:
            import ansible
            import yaml
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:
            pass
        else:
            assert ansible.__version__ == '2.18.19'
            task = yaml.safe_load(text)[0]['tasks'][0]['ansible.builtin.command']
            rendered = Templar(loader=DataLoader(),variables={
                'playbook_dir':str(play.parent),'validator_request':request}).template(task)
            assert rendered['argv'] == argv
            assert json.loads(rendered['stdin']) == request
        patch.object(installer,'RUNS',run.parent).start()
        patch.object(locking,'CONTROL',root/'original-operation.lock').start()
        target = {'phase':'observing','version':protocol.VERSION,'commit':protocol.COMMIT,
                  'image':protocol.IMAGE,'image_id':protocol.IMAGE_ID,
                  'helpers_sha256':publication.profile(source)[0],'config_id':'d'*64}
        private = [
            {'action':'prepare','contract':fixture.expected,'intent':'e'*32,'target':target},
            {'action':'import-wallet','contract':fixture.expected,'intent':'e'*32,'secret':'INERT_CONCEALED_INPUT','restore':False},
            {'action':'import-upstreams','contract':fixture.expected,'intent':'e'*32,'secret':'INERT_CONCEALED_INPUT'},
            {'action':'firewall-confirm','contract':fixture.expected,'intent':'e'*32,'operation':'r-inert','bundle':'f'*64},
            dict(request,secret='INERT_CONCEALED_INPUT')]
        result_path = run/'validator-public-result.json'
        for value in private:
            with patch.object(control,'dispatch',side_effect=AssertionError('must not dispatch private input')) as dispatch, \
                 patch.object(installer,'public_result',side_effect=AssertionError('must not publish private input')) as publish:
                code,stdout,stderr = invoke(entry,argv[3:],value,root)
                assert code == 1 and not stdout and 'INERT_CONCEALED_INPUT' not in stderr
                dispatch.assert_not_called(); publish.assert_not_called()
            assert not result_path.exists()
            assert (fixture.state.root/'owner.json').read_bytes() == original['owner.json']
        real_dispatch, real_publish = control.dispatch, installer.public_result
        with patch.object(control,'dispatch',wraps=real_dispatch) as dispatch, \
             patch.object(installer,'public_result',wraps=real_publish) as publish:
            code,stdout,stderr = invoke(entry,argv[3:],request,root)
            assert code == 0 and not stderr, (code,stderr)
            dispatch.assert_called_once_with(request)
            assert publish.call_count == 1
        assert json.loads(stdout) == {'public_result_written':True,'run':run.name}
        assert fixture.stops == [False]
        assert fixture.state.fence()['stopped']
        assert fixture.state.owner(fixture.expected)['phase'] == 'assertion-validator-v2'
        for name,contents in original.items():
            if name != 'owner.json': assert (fixture.state.root/name).read_bytes() == contents
        record = json.loads(result_path.read_bytes())
        assert record['request_sha256'] == hashlib.sha256(storage.encode(request)).hexdigest()
        assert record['helpers_sha256'] == publication.profile(source)[0]
        assert record['bundle_sha256'] == hashlib.sha256(raw).hexdigest()
        assert record['result'] == {'volume_authority':'original','stopped':True,'runtime_started':False}
        return record
    finally: fixture.doCleanups()


if __name__ == '__main__':
    result = exercise(sys.stdin.buffer.read())
    print(json.dumps(result,separators=(',',':'),sort_keys=True))
