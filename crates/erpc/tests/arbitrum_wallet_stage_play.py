# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Compiled public request/bundle -> real entry/play/dispatch and original cipher.

Only original OS/NSS/runtime/encryption boundaries come from the author's inert
fixture. The raw carried source, production routing, protected files and digest
bindings are unchanged. No generated or operational key, host or send is used.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]/'erpc-chain-nitro'
sys.path.insert(0,str(ROOT/'tests'));sys.path.insert(0,str(Path(__file__).parent))
from validator_wallet_stage import Stage
from validator_provider_stage import Provider
from arbitrum_volume_play import invoke
import control
import host
import installer
import locking
import protocol
import publication
import storage


def exercise(raw):
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        inventory=json.load(archive.extractfile('inventory.yml'))
    request=next(iter(inventory['all']['hosts'].values()))['validator_request']
    provider=request['action']=='provider-stage-authorize'
    owner=(Provider if provider else Stage)('runTest');owner.expected_override=request['contract'];owner.setUp()
    fixture=owner.fixture if provider else owner
    try:
        assert provider or request['action']=='wallet-stage-authorize' and request['restore'] is False
        root=fixture.history.root;run=root/'runs/r-original-wallet-stage';bundle=run/'bundle';bundle.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive:
                relative=Path(member.name)
                assert member.isfile() and not relative.is_absolute() and '..' not in relative.parts
                destination=bundle/relative;destination.parent.mkdir(parents=True,exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
        (run/'bundle.tar.gz').write_bytes(raw)
        source=bundle/'validator/node'
        for path in source.glob('*.py'):
            cached=sys.modules.get(path.stem)
            if cached is not None:assert Path(cached.__file__).read_bytes()==path.read_bytes(),path.name
        patch.object(installer,'RUNS',run.parent).start();patch.object(locking,'CONTROL',root/'operation.lock').start()
        # The fixture models source publication for host operations. The public
        # result itself must use the actual complete carried profile digest.
        from importlib.util import module_from_spec,spec_from_file_location
        spec=spec_from_file_location('profile_digest',source/'publication.py')
        digests=module_from_spec(spec);spec.loader.exec_module(digests)
        patch.object(publication,'profile',side_effect=digests.profile).start()
        play=bundle/'validator/ansible/control.yml';entry=source/'entry.py'
        try:
            import ansible,yaml
            from ansible.parsing.dataloader import DataLoader
            from ansible.template import Templar
        except ImportError:
            assert not os.environ.get('ERPC_REQUIRE_PINNED_ANSIBLE'),'pinned Ansible test cannot skip'
        else:
            assert ansible.__version__=='2.18.19'
            task=yaml.safe_load(play.read_text())[0]['tasks'][0]['ansible.builtin.command']
            actual=Templar(loader=DataLoader(),variables={'playbook_dir':str(play.parent),'validator_request':request}).template(task)
            assert actual['argv']==['/usr/bin/python3','-I',str(play.parent/'../node/entry.py'),'play-control']
            assert json.loads(actual['stdin'])==request
        real_dispatch=control.dispatch
        with patch.object(control,'dispatch',wraps=real_dispatch) as dispatched:
            code,stdout,stderr=invoke(entry,['play-control'],request,root)
        assert code==0 and not stderr,(code,stderr)
        dispatched.assert_called_once_with(request)
        public=json.loads((run/'validator-public-result.json').read_bytes())
        assert public['result']['requires_import'] is True
        if not provider:assert public['result']['observer_required'] is False
        assert public['request_sha256']==hashlib.sha256(storage.encode(request)).hexdigest()
        assert public['helpers_sha256']==digests.profile(source)[0]
        assert public['bundle_sha256']==hashlib.sha256(raw).hexdigest()
        assert not (host.ROOT/'key-origin.json').exists() and fixture.ciphers=={}
        private=dict(request,action='provider-stage-import' if provider else 'wallet-stage-import',
                     secret=owner.raw if provider else fixture.raw.decode())
        with patch.object(control,'dispatch',side_effect=AssertionError('private body cannot enter public channel')) as dispatched:
            code,stdout,stderr=invoke(entry,['play-control'],private,root)
        assert code==1 and fixture.raw.decode() not in stdout+stderr;dispatched.assert_not_called()
        # Same exact schema produced by the CLI's private-body encoder; real
        # dispatch/custody writes root-only ciphertext without granting runtime.
        result=real_dispatch(protocol.request(private))
        if provider:
            assert result['upstreams_verified'] and not fixture.running
            assert (host.UPSTREAM_CUSTODY/'upstreams.cred').is_file() and not (host.CUSTODY/'wallet.cred').exists()
        else:
            assert result['original_verified'] and fixture.running
            assert (host.CUSTODY/'wallet.cred').is_file()
        assert not (host.RUNTIME/'wallet').exists()
        assert not (host.ROOT/'signer-activated.json').exists()
        return public
    finally:owner.doCleanups()


if __name__=='__main__':print(json.dumps(exercise(sys.stdin.buffer.read()),sort_keys=True,separators=(',',':')))
