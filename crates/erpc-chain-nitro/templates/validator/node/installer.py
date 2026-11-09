# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Receipt-bound Ansible phases; the outer node run owns /opt/erpc."""
import hashlib
import scope
import http.client
import os
import re
from pathlib import Path
import accounts
import configuration
import container
import credentials
import crypto
import custody
import host
import protocol
import publication
import parent_tls
import runtime
import services
from state import State
from storage import decode, directory, encode, read, require, sync_directory, write

CHAIN_PATH = scope.CHAIN_DOCUMENT[1]
RUNS = Path('/opt/erpc/runs')
CHAIN_SHA = scope.CHAIN_DOCUMENT[2]


def fetch_document(document):
    # The sealed source fixes every host/path/hash; no URL input or redirects.
    hostname,path,digest=document
    connection=http.client.HTTPSConnection(hostname,timeout=30)
    try:
        connection.request('GET',path)
        response=connection.getresponse();raw=response.read(1048577)
        require(response.status==200 and len(raw)<=1048576 and hashlib.sha256(raw).hexdigest()==digest,
                'official pinned chain document is unavailable or changed')
        return raw
    finally:connection.close()


def fetch_chain():return fetch_document(scope.CHAIN_DOCUMENT)


def common_source(source):
    # Bundle layout work/validator/node; common reviewed helper sits at work/.
    path = source.parent.parent/'rpc-firewall.py'
    return read(path, 1048576)


def unit_record(role, raw, run=host.command):
    value = services.show(role, run)
    require(value['LoadState'] == 'loaded' and set(services.FIXED) <= set(value)
            and value['FragmentPath'] == str(host.UNITS/services.NAMES[role])
            and value['User'] == '0' and value['Group'] == '0', 'published unit has an unexpected credential recipient')
    if role != 'firewall':
        require(value['ExecCondition'] and value['ExecStartPre'] and value['ExecStart']
                and value['NoNewPrivileges'] == 'yes', 'published native unit lacks its checked conditions')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'loaded': {key: value[key] for key in services.FIXED}}


def public_config(state, expected, target, chain):
    directory(host.CONFIG, create=True, mode=0o755)
    path = host.CONFIG/'public'; directory(path, create=True, mode=0o755)
    require(hashlib.sha256(chain).hexdigest() == CHAIN_SHA, 'chain metadata pin differs')
    tls,_ = parent_tls.sealed(state, expected)
    node = encode(configuration.public(expected['wallet'], target['phase']))
    write(path/'node.json', node, mode=0o644); write(path/'chain-info.json', chain, mode=0o644)
    write(host.CONFIG/'contract.json', encode(expected), mode=0o644)
    write(path/'parent-ca.pem', tls['public_ca'].encode(), mode=0o644)
    record={'contract': expected, 'target': target,
                                   'node_sha256': hashlib.sha256(node).hexdigest(), 'chain_sha256': CHAIN_SHA,
                                   'parent_ca_sha256': tls['ca_sha256']}
    if scope.GENESIS_DOCUMENT is not None:
        raw=fetch_document(scope.GENESIS_DOCUMENT)
        write(path/'genesis.json',raw,mode=0o644)
        record['genesis_sha256']=scope.GENESIS_DOCUMENT[2]
    state.put('configuration.json',record)


def verify_config(state, expected, target):
    tls,_ = parent_tls.sealed(state, expected)
    wanted={
        'contract': expected, 'target': target,
        'node_sha256': hashlib.sha256(encode(configuration.public(expected['wallet'], target['phase']))).hexdigest(),
        'chain_sha256': CHAIN_SHA, 'parent_ca_sha256': tls['ca_sha256']}
    if scope.GENESIS_DOCUMENT is not None:
        wanted['genesis_sha256']=scope.GENESIS_DOCUMENT[2]
        require(hashlib.sha256(read(host.CONFIG/'public/genesis.json')).hexdigest()==wanted['genesis_sha256'],
                'original custom genesis changed')
    require(state.get('configuration.json')==wanted,'public native configuration receipt differs')
    require(read(host.CONFIG/'public/node.json') == encode(configuration.public(expected['wallet'], target['phase']))
            and hashlib.sha256(read(host.CONFIG/'public/chain-info.json')).hexdigest() == CHAIN_SHA
            and decode(read(host.CONFIG/'contract.json')) == expected
            and read(host.CONFIG/'public/parent-ca.pem') == tls['public_ca'].encode(), 'public native configuration or contract changed')


def short_firewall(control, request, source):
    expected, state, intent = control.expected, control.state, request['intent']
    state.pending(expected, intent); control.quiet(); host.namespaces()
    raw = common_source(source)
    directory(host.FIREWALL, create=True, mode=0o700)
    directory(host.FIREWALL_HELPER.parent, create=True, mode=0o755)
    write(host.FIREWALL_HELPER, raw, mode=0o700)
    state.put('common-firewall.json', {'contract': expected, 'sha256': hashlib.sha256(raw).hexdigest()})
    directory(host.CONFIG, create=True, mode=0o755)
    write(host.CONFIG/'contract.json', encode(expected), mode=0o644)
    unit = read(source.parent/'ansible/firewall.service', 262144)
    write(host.UNITS/services.NAMES['firewall'], unit, mode=0o644)
    control.run(['/usr/bin/systemctl', 'daemon-reload'])
    actual = unit_record('firewall', unit, control.run)
    previous = state.get('units.json') if (state.root/'units.json').exists() else {'contract': expected, 'units': {}}
    require(previous['contract'] == expected, 'old unit receipt belongs to another owner')
    previous['units']['firewall'] = actual; state.put('units.json', previous)
    root = source.parent.parent.parent
    operation = root.name; bundle = hashlib.sha256(read(root/'bundle.tar.gz', 64*1024*1024)).hexdigest()
    candidate = source.parent.parent/'firewall-candidate.nft'
    read(candidate, 1048576)
    control.run(['/usr/sbin/nft', '-c', '-f', str(candidate)])
    runtime.common(state, expected, 'apply', operation, bundle)
    control.run(['/usr/bin/systemctl', 'enable', services.NAMES['firewall']])
    return {'firewall_pending': True, 'operation': operation, 'bundle': bundle}


def deploy(control, request, source, operation, bundle):
    state, expected, target, intent = control.state, control.expected, request['target'], request['intent']
    runtime.common(state, expected, 'require-confirmed', operation, bundle)
    state.pending(expected, intent); control.quiet(); host.namespaces()
    publication.verify(state, expected, target); accounts.verify(state, expected)
    public_config(state, expected, target, fetch_chain())
    units = state.get('units.json'); require(units['contract'] == expected, 'original unit receipt differs')
    contents = {}
    for role, name in [('node', 'nitro'), ('transport', 'upstreams')]:
        contents[role] = read(source.parent/'ansible'/ (name+'.service'), 262144)
        write(host.UNITS/services.NAMES[role], contents[role], mode=0o644)
    control.run(['/usr/bin/systemctl', 'daemon-reload'])
    for role, raw in contents.items(): units['units'][role] = unit_record(role, raw, control.run)
    state.put('units.json', units); verify_config(state, expected, target)
    runtime.common(state, expected, 'require-confirmed', operation, bundle)
    state.activate(expected, intent, control.qualify)
    try: return control.start_units()
    except Exception:
        state.stop(expected, control.shutdown)
        raise


def public_result(source, request, result):
    run=source.parent.parent.parent
    require(source.name=='node' and source.parent.name=='validator' and source.parent.parent.name=='bundle'
            and run.parent==RUNS and re.fullmatch('r-[a-z0-9-]+',run.name) and len(run.name)<=80,
            'public probe is not inside its sealed original run')
    bundle=hashlib.sha256(read(run/'bundle.tar.gz',64*1024*1024)).hexdigest()
    helpers,_=publication.profile(source)
    value={'schema':scope.PUBLIC_RESULT,'run':run.name,'bundle_sha256':bundle,
           'helpers_sha256':helpers,'request_sha256':hashlib.sha256(encode(request)).hexdigest(),'result':result}
    raw=encode(value);require(len(raw)<=65536,'public validator result exceeds its bound')
    write(run/'validator-public-result.json',raw,mode=0o644)
    return {'public_result_written':True,'run':run.name}


def play(args, request, source):
    from control import Control, dispatch
    if args==['play-control']:
        require(request['action'] in ('preflight','init','metadata','status','start','restart','stop','destroy','identity',
                                      'registration-prepare','registration-validate','registration-status',
                                      'upgrade-volume-authority','wallet-stage-authorize','provider-stage-authorize'),
                'private or deployment input cannot use the public result channel')
        result=dispatch(request)
        return public_result(source,request,result)
    require(args and args[0] in ('play-init', 'play-pull', 'play-publish', 'play-before-firewall',
                                'play-firewall', 'play-confirmed', 'play-deploy'), 'unknown sealed playbook phase')
    action = args[0]; expected = request['contract']
    if action == 'play-init':
        require(len(args) == 1 and request['action'] == 'init', 'invalid original initialization phase')
        return dispatch(request)
    require(request['action'] == 'prepare', 'playbook must bind the exact original prepare envelope')
    control = Control(expected); control.owner(); host.namespaces()
    target = request['target']; digest, _ = publication.profile(source); protocol.target(target, digest)
    if action == 'play-pull':
        require(len(args) == 1, 'invalid image prefetch phase')
        accounts.verify(control.state, expected); host.capacity(control.state, expected)
        previous = control.state.get('active.json')['target'] if (host.ROOT/'active.json').exists() else None
        protocol.transition(previous, target, (host.ROOT/'signer-activated.json').exists())
        container.client(); container.engine()
        if container.find() is not None:
            require((host.ROOT/'container.json').exists(), 'unowned named native container cannot be adopted')
        control.run(container.cli('pull', target['image']), timeout=3600)
        container.image(target)
        return {'image_verified': True, 'image': target['image']}
    if action in ('play-confirmed', 'play-deploy') and control.state.fence()['intent'] is None:
        require(len(args) == 3 and control.state.completed(expected, request['intent']) == target,
                'delayed deployment does not identify the original completed operation')
        runtime.common(control.state, expected, 'require-confirmed', args[1], args[2])
        publication.verify(control.state, expected, target); verify_config(control.state, expected, target)
        if action == 'play-confirmed': return {'confirmed': True, 'already_activated': True}
        try: return control.start_units()
        except Exception:
            control.state.stop(expected, control.shutdown)
            raise
    control.state.pending(expected, request['intent'])
    if action == 'play-publish':
        require(len(args) == 1, 'invalid helper publication phase')
        return publication.publish(control.state, expected, request['intent'], source, control.quiet)
    publication.verify(control.state, expected, target)
    if action == 'play-before-firewall':
        require(len(args) == 1, 'invalid firewall preparation phase')
        control.quiet(); accounts.verify(control.state, expected)
        credentials.inspect(control.state, expected)
        if target['phase']=='active': custody.inspect(control.state, expected)
        crypto.self_test()
        parent_tls.ensure(control.state, expected, request['intent'], control.quiet)
        return {'credentials_verified': True, 'phase': target['phase']}
    if action == 'play-firewall':
        require(len(args) == 1, 'invalid short firewall phase')
        return short_firewall(control, request, source)
    require(len(args) == 3, 'deployment requires an immutable caller firewall receipt')
    if action == 'play-confirmed':
        runtime.common(control.state, expected, 'require-confirmed', args[1], args[2])
        return {'confirmed': True}
    return deploy(control, request, source, args[1], args[2])
