# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Check the actual Rust-created bundle/profile and strict systemd rendering."""
import hashlib
import io
import json
import sys
import tarfile
raw=sys.stdin.buffer.read()
try:
    import jinja2
except ImportError:
    print('optional pinned Jinja runtime unavailable');raise SystemExit(0)
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
    files={member.name:archive.extractfile(member).read() for member in archive.getmembers()}
inventory=json.loads(files['inventory.yml'])
assert len(inventory['all']['hosts'])==1
variables=next(iter(inventory['all']['hosts'].values()))
assert variables['validator_ssh_port']==22
assert variables['validator_request']['contract']['role']=='assertion-validator'
assert 'node/control.py' not in files
profile={name.rsplit('/',1)[1]:data for name,data in files.items() if name.startswith('validator/node/')}
assert len(profile)>30 and 'upstreams.py' in profile
expected=hashlib.sha256(b''.join(name.encode()+b'\0'+hashlib.sha256(data).digest() for name,data in sorted(profile.items()))).hexdigest()
assert expected==variables['validator_request']['target']['helpers_sha256']
env=jinja2.Environment(undefined=jinja2.StrictUndefined)
env.filters['to_json']=json.dumps
for phase in ('observing','active'):
    variables['validator_request']['target']['phase']=phase
    for kind in ('nitro','upstreams','firewall'):
        source=files['validator/ansible/'+kind+'.service.j2'].decode()
        rendered=env.from_string(source).render(**variables)
        assert 'User=0' in rendered
        assert '/usr/bin/python3 -I -c ' in rendered
        if kind!='firewall':
            assert 'ExecCondition=' in rendered
            assert rendered.index('ExecCondition=')<rendered.index('ExecStartPre=')
            assert 'LimitCORE=0' in rendered
        assert ('LoadCredentialEncrypted=arbitrum-wallet:' in rendered)==(kind=='nitro' and phase=='active')
    env.from_string(files['validator/ansible/firewall.nft.j2'].decode()).render(**variables)
print('actual complete source digest and eight strict unit/firewall renders passed')
