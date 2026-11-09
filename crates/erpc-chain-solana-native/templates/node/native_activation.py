# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit first-voter transition and retained original public proof authority.

The exclusive-identity statement is an operator assertion, not remote proof
that no copy exists. Native history validation remains mandatory at startup.
"""
import hashlib
from native_files import encoded, require, sync_file, sync_directory
from native_state import token
import native_accounts as accounts
import native_custody as custody
import native_deployment as deployment
import native_helpers as helpers
import native_proof as proof
import native_runtime_unit as units
import native_validator as validator

RECORD = 'validator-activation.json'


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def binding(contract, value):
    validator.registration(value)
    require(contract['profile'] == 'agave-native'
            and value['network'] == contract['network']
            and value['identity'] == contract['identity_account']
            and value['vote_account'] == contract['vote_account']
            and value['withdrawer'] == contract['authority_account'],
            'validator registration differs from the original host contract')
    return value


def request_record(state, contract, intent):
    state.owner(contract)
    record = state.get('validator-request-' + token(intent) + '.json')
    require(set(record) == {'contract', 'intent', 'registration', 'exclusive_identity', 'previous_sha256'}
            and record['contract'] == contract and record['intent'] == intent
            and record['exclusive_identity'] is True, 'original validator activation request differs')
    binding(contract, record['registration'])
    require(isinstance(record['previous_sha256'], str) and len(record['previous_sha256']) == 64
            and all(c in '0123456789abcdef' for c in record['previous_sha256']), 'invalid original observer receipt')
    return record


def authorize(state, contract, request, run):
    from native_runtime_control import status
    require(set(request) == {'action', 'contract', 'intent', 'registration', 'exclusive_identity'}
            and request['action'] == 'authorize-validator' and request['contract'] == contract
            and request['exclusive_identity'] is True, 'explicit original exclusive validator identity required')
    state.owner(contract); state.recovery_clear(contract)
    policy = binding(contract, request['registration']); intent = token(request['intent'])
    pending = state.current(contract, intent) if (state.directory / 'pending.json').exists() else None
    if (state.directory / RECORD).exists():
        original, _ = approved(state, contract, check_custody=False)
        require(original['registration'] == policy, 'original verified registration cannot be replaced')
    accounts.verify(state, contract)
    revision = helpers.publish()
    raw, _, profile = deployment.source(revision, contract['network'])
    previous = state.get('active.json')
    published = (pending is not None and previous['intent'] == intent
                 and previous['receipt']['mode'] == 'validator' and not (state.directory / 'cutover.json').exists())
    require(previous['receipt']['mode'] == 'sync' or published,
            'first validator activation requires its original synchronized runtime')
    build = previous['receipt']['build']; build_intent = token(build['request']['intent'])
    require(build['request'] == deployment.jobs.request(raw, contract['network'], build_intent)
            and build['source'] == {key: profile[key] for key in ('commit', 'cargo_lock_sha256', 'rust')},
            'activation must reuse the currently qualified native build; update synchronization first')
    deployment.publication.verify(units.RELEASES / build_intent, build)
    target = {key: build['request'][key] for key in ('network', 'version', 'commit', 'catalog_sha256')}
    target.update(helper_revision=revision, mode='validator', identity=contract['identity_account'], build_intent=build_intent)
    record = {'contract': contract, 'intent': intent, 'registration': policy,
              'exclusive_identity': True, 'previous_sha256': digest(previous)}
    name = 'validator-request-' + intent + '.json'
    if (state.directory / name).exists():
        saved = request_record(state, contract, intent)
        if published:
            record['previous_sha256'] = saved['previous_sha256']
        require(saved == record, 'original validator activation inputs changed')
    if pending is not None:
        require(pending['action'] == 'activate-validator' and pending['target'] == target,
                'another deployment must be completed or explicitly recovered first')
        require(request_record(state, contract, intent) == record, 'pending validator request differs')
    else:
        require(state.guard(contract) == previous and not state.halt()['retired'], 'original synchronization is stopped')
        observed = status(state, contract, run)
        require(observed.get('mode') == 'sync' and observed.get('rpc_ready') is True,
                'original synchronization must be healthy before validator activation')
        validator.observe(policy, profile['genesis'])
        require(state.guard(contract) == previous, 'original synchronization changed during admission observation')
        state.put(name, record)
        sync_file(state.directory / name); sync_directory(state.directory)
        state.authorize(contract, intent, target, 'activate-validator')
    state.put('candidate-' + intent + '.json', build)
    return {'intent': intent, 'target': target, 'runtime_changed': False, 'runtime_published': published}


def before_cutover(state, contract, intent, run):
    from native_runtime_control import status
    operation, _ = deployment.candidate(state, contract, intent)
    require(operation['action'] == 'activate-validator', 'first validator transition requires explicit activation')
    record = request_record(state, contract, intent)
    path = state.directory / 'cutover.json'
    if path.exists():
        cutover = state.get(path.name)
        require(all(cutover[key] == operation[key] for key in ('intent', 'halt', 'target'))
                and digest(cutover['previous']) == record['previous_sha256'], 'original validator cutover differs')
    else:
        previous = state.guard(contract)
        require(digest(previous) == record['previous_sha256'], 'original synchronization approval changed')
        observed = status(state, contract, run)
        require(observed.get('mode') == 'sync' and observed.get('rpc_ready') is True,
                'original synchronization is no longer healthy')
        require(state.guard(contract) == previous, 'original synchronization changed during qualification')
    _, _, profile = deployment.source(operation['target']['helper_revision'], contract['network'])
    return validator.observe(record['registration'], profile['genesis'])


def approved(state, contract, reference=None, check_custody=True):
    state.owner(contract)
    record = state.get(RECORD)
    require(set(record) == {'contract', 'intent', 'registration', 'proof', 'plaintext_sha256'}
            and record['contract'] == contract, 'original validator activation receipt differs')
    token(record['intent']); binding(contract, record['registration'])
    evidence = state.get('validator-proof-' + record['intent'] + '.json')
    require(record['proof'] == evidence and evidence['contract'] == contract
            and evidence['intent'] == record['intent'] and evidence['bls'] == record['registration']['bls'],
            'original native BLS evidence differs from registered voting authority')
    require(isinstance(record['plaintext_sha256'],str) and len(record['plaintext_sha256'])==64
            and all(c in '0123456789abcdef' for c in record['plaintext_sha256']), 'invalid original validator material digest')
    if check_custody:
        identity = custody.complete(state, contract, 'validator')
        require(identity['public'] == contract['identity_account']
                and identity['plaintext_sha256'] == record['plaintext_sha256'], 'original activated validator key changed')
    result = {'intent': record['intent'], 'sha256': digest(record)}
    if reference is not None:
        require(reference == result, 'runtime no longer references its original validator activation')
    return record, result


def finish(state, contract, intent, run):
    operation, build = deployment.candidate(state, contract, intent)
    require(operation['target']['mode'] == 'validator', 'validator evidence cannot be attached to a non-voting runtime')
    cutover = state.get('cutover.json')
    require(all(cutover[key] == operation[key] for key in ('intent', 'halt', 'target')), 'validator is not in its original stopped cutover')
    proof.stop(state, contract, run)
    identity = custody.complete(state, contract, 'validator')
    if operation['action'] == 'activate-validator':
        request = request_record(state, contract, intent)
        require(digest(cutover['previous']) == request['previous_sha256'], 'validator transition changed its original observer')
        evidence = state.get('validator-proof-' + token(intent) + '.json')
        installed = proof.owned(state, contract)
        require(evidence == dict(installed, bls=request['registration']['bls'])
                and installed['intent'] == intent and installed['helper_revision'] == operation['target']['helper_revision']
                and installed['build_intent'] == operation['target']['build_intent']
                and installed['cipher_sha256'] == identity['cipher_sha256']
                and installed['keygen_sha256'] == build['files']['solana-keygen']['sha256'],
                'completed native derivation does not match original registered BLS or custody')
        record = {'contract': contract, 'intent': intent, 'registration': request['registration'],
                  'proof': evidence, 'plaintext_sha256': identity['plaintext_sha256']}
        _, _, profile = deployment.source(operation['target']['helper_revision'], contract['network'])
        validator.observe(record['registration'], profile['genesis'])
        state.current(contract, intent)
        if not (state.directory / RECORD).exists():
            state.put(RECORD, record)
        else:
            original, _ = approved(state, contract)
            require(original['registration'] == record['registration'], 'original verified registration cannot be replaced')
    else:
        require((state.directory / RECORD).exists(), 'new voting identity requires explicit activation')
    record, reference = approved(state, contract)
    _, _, profile = deployment.source(operation['target']['helper_revision'], contract['network'])
    validator.observe(record['registration'], profile['genesis'])
    sync_file(state.directory / RECORD); sync_directory(state.directory)
    return reference


def qualify(state, contract, reference, genesis):
    record, _ = approved(state, contract, reference)
    return validator.observe(record['registration'], genesis)
