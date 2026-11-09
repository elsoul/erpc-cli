#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Explicit supported legacy adoption from independent historical account/source records."""
import base64
import os
import pathlib
import shlex
import stat
from arc_files import digest, encoded, require
import arc_accounts as accounts
import arc_custody as custody
import arc_helpers as helpers
import arc_process as process
import arc_protocol as protocol
import arc_release as release
import arc_storage as storage
import arc_units as units

JOURNAL = '/etc/erpc/arc/authority/legacy-migration.json'


def binding(request):
    return digest(encoded({key: request[key] for key in ('contract', 'target', 'policy', 'evidence')}))


def evidence(c, request):
    value = request.get('evidence')
    require(isinstance(value, dict) and set(value) == {'uid', 'gid', 'machine', 'highest', 'proofs'},
            'independent original Arc account/source records are required')
    for field in ('uid', 'gid'):
        require(type(value[field]) is int and 100 <= value[field] <= 2147483647 and value[field] != 65534,
                'invalid historical Arc numeric identity')
    require(value['machine'] == c.machine(), 'historical Arc machine identity differs from this host')
    highest = value['highest']
    require(isinstance(highest, dict) and set(highest) == {'version', 'commit'} and
            isinstance(highest['commit'], str) and len(highest['commit']) == 40 and
            all(char in '0123456789abcdef' for char in highest['commit']), 'invalid original Arc highest source record')
    require(release.version(highest['version']) >= release.version(request['target']['version']),
            'historical highest Arc source record predates the current inventory source')
    if highest['version'] == request['target']['version']:
        require(highest['commit'] == request['target']['commit'], 'historical Arc source commit differs')
    require(isinstance(value['proofs'], dict) and set(value['proofs']) == {'passwd', 'group', 'machine', 'source'} and
            all(isinstance(item, str) and len(item) == 64 and all(ch in '0123456789abcdef' for ch in item)
                for item in value['proofs'].values()), 'historical Arc evidence hashes are incomplete')
    return value


def original_state(c, request):
    data = evidence(c, request)
    state = {'schema': 'erpc-arc-original-authority-v1', 'contract': protocol.contract(request['contract']),
             'machine': c.machine(), 'service_uid': data['uid'], 'service_gid': data['gid'],
             'service_home': storage.DATA_HOME, 'account_established': True, 'generation': 1,
             'stopped': ['execution', 'consensus'], 'retired': True, 'phase': 'migrating',
             'migration_binding': binding(request), 'migration_evidence': data,
             'source_floor': {**data['highest'], 'archive_sha256': None, 'platform': request['target']['platform']},
             'source': request['target'], 'policy': protocol.policy(request['policy'], request['contract']),
             'native_started': True, 'bootstrap_complete': True}
    accounts.verify(c, state)
    return state


def original_tree(state, root, device):
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        require(info.st_dev == device and info.st_uid == state['service_uid'] and
                info.st_gid == state['service_gid'] and not info.st_mode & 0o022,
                'legacy Arc history ownership, mode or device is unqualified')
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                    'legacy Arc history contains a link or special file')


def directories(c, state, recorded=None, finish=False):
    c.protected('/var/lib', directory=True)
    record = recorded if recorded is not None else {'filesystem': storage.filesystem(c), 'directories': {}}
    require(storage.filesystem(c) == storage.volume(record['filesystem']), 'original Arc filesystem differs during migration')
    current_home = c.path(storage.DATA_HOME).lstat()
    for name in ('root', 'execution', 'consensus'):
        path = c.path(storage.DATA_HOME) if name == 'root' else c.path(storage.DATA_HOME) / name
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_dev == current_home.st_dev,
                    'legacy Arc data is not on its original qualified volume')
            old = info.st_uid == state['service_uid'] and info.st_gid == state['service_gid'] and stat.S_IMODE(info.st_mode) in (0o700, 0o750)
            new = name == 'root' and info.st_uid == c.owner and stat.S_IMODE(info.st_mode) == 0o755
            require(old or (recorded is not None and new), 'legacy Arc data ownership or mode is unqualified')
            observed = storage.identity(info)
            if recorded is None:
                record['directories'][name] = observed
            require(storage.same(info, record['directories'].get(name), current_home.st_dev) and
                    storage.observation(info, path.lstat()) and
                    storage.observation(current_home, c.path(storage.DATA_HOME).lstat()),
                    'legacy Arc data directory was replaced')
            if finish:
                if name == 'root':
                    os.fchown(fd, c.owner, c.owner)
                    os.fchmod(fd, 0o755)
                else:
                    os.fchmod(fd, 0o700)
                os.fsync(fd)
        finally:
            os.close(fd)
        if finish:
            c.sync(path.parent)
    for name, relative in (('execution', 'db/mdbx.dat'), ('consensus', 'store.db')):
        original_tree(state, c.path(storage.DATA_HOME) / name, current_home.st_dev)
        path = c.path(storage.DATA_HOME) / name / relative
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == state['service_uid'] and
                info.st_size > 0 and not info.st_mode & 0o022, 'legacy Arc database is missing or unqualified')
    return record


def legacy_units(c, request):
    folder = pathlib.Path(__file__).resolve().parent.parent / 'legacy-rendered'
    actual = {}
    for component, name in process.UNITS.items():
        path = '/' + str((folder / name).relative_to(c.root))
        expected = c.read(path, limit=65536)
        current = c.read('/etc/systemd/system/' + name, limit=65536)
        require(current == expected, 'legacy Arc unit differs from the supported managed definition')
        actual[component] = current.decode()
    return actual


def check(c, request):
    target = release.source(request['target'])
    c.platform()
    c.namespaces()
    if c.protected(JOURNAL, missing=True).exists():
        journal = c.json(JOURNAL, private=True)
        require(journal.get('binding') == binding(request), 'original Arc migration request differs')
        evidence(c, request)
    else:
        state = original_state(c, request)
        directories(c, state)
        legacy_units(c, request)
        require(c.protected(custody.CREDENTIAL).exists(), 'legacy Arc original encrypted credential is missing')
    c.mkdir('/opt/arc/downloads', mode=0o755)
    c.mkdir('/opt/arc/releases', mode=0o755)
    archive = '/opt/arc/downloads/' + release.identifier(target) + '.tar.gz'
    c.protected(archive, missing=True)
    return {'archive': archive}


def argv(text):
    lines = text.replace('\\\n', ' ').splitlines()
    command = [line[len('ExecStart='):] for line in lines if line.startswith('ExecStart=')]
    require(len(command) == 1, 'legacy Arc native command is ambiguous')
    value = shlex.split(command[0])
    return [part.replace('%d', '/run/credentials/arc-consensus.service') for part in value]


def _migrate(c, request):
    check(c, request)
    source = release.install(c, request['target'], '/opt/arc/downloads/' + release.identifier(request['target']) + '.tar.gz')
    if c.protected(JOURNAL, missing=True).exists():
        journal = c.json(JOURNAL, private=True, resync=True)
        require(journal.get('binding') == binding(request), 'original Arc migration differs')
        state = journal['state']
    else:
        state = original_state(c, request)
        layout = directories(c, state)
        texts = legacy_units(c, request)
        current = c.path('/opt/arc/current')
        info = current.lstat()
        root = '/opt/arc/' + request['target']['version']
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == c.owner and os.readlink(current) == root,
                'legacy Arc current source is not the qualified original release')
        runtime = {}
        for component, name in process.BINARIES.items():
            require(release.file_hash(c, root + '/' + name) == source['images'][name],
                    'legacy Arc executable differs from the qualified official archive')
            runtime[component] = {'binary': root + '/' + name, 'sha256': source['images'][name], 'argv': argv(texts[component])}
        cipher = c.read(custody.CREDENTIAL, limit=16384, private=True)
        require(custody.public(c, custody.decrypt(c, cipher)) == request['contract']['public_key'],
                'legacy Arc encrypted identity is not the original inventory public key')
        state['credential'] = {'ciphertext': base64.b64encode(cipher).decode(), 'sha256': digest(cipher),
                               'public_key': request['contract']['public_key']}
        state['runtime'] = runtime
        state['storage'] = {'home': layout['directories']['root'], 'filesystem': layout['filesystem'], 'prepared': True}
        state['directories'] = {name: layout['directories'][name] for name in storage.LAYERS}
        journal = {'schema': 'erpc-arc-legacy-migration-v1', 'binding': binding(request),
                   'state': state, 'layout': layout, 'units': texts}
        c.migration_fallback = (state, texts)
        c.write(JOURNAL, journal)
    c.migration_fallback = (state, journal['units'])
    require(journal.get('schema') == 'erpc-arc-legacy-migration-v1', 'unknown Arc migration journal')
    if c.protected('/etc/erpc/arc/authority/owner.json', missing=True).exists():
        saved = c.state(request['contract'])
        require(saved.get('migration_binding') == binding(request), 'another Arc original owner is already reserved')
        if saved.get('migrated') is True:
            return {'migration': 'already-recorded', 'runtime_unchanged': True}
        state = saved
    accounts.verify(c, state)
    directories(c, state, journal['layout'])
    c.mkdir('/etc/erpc/arc/authority/units')
    # Old and inert-current definitions are both durable before any unit replacement.
    for component, text in journal['units'].items():
        receipt = {'contract': state['contract'], 'component': component, 'sha256': digest(text.encode()),
                   'text': text, 'runtime': journal['state']['runtime'], 'source': request['target']}
        c.write(units.record_name(receipt['sha256']), receipt)
    c.save(state)
    folder = pathlib.Path(__file__).resolve().parent
    state['helpers'] = helpers.publish(c, folder, request['helpers'])
    c.save(state)
    common_source = '/' + str((folder.parent / 'rpc-firewall.py').relative_to(c.root))
    c.write_bytes('/usr/local/lib/erpc/rpc-firewall.py', c.read(common_source), 0o700)
    c.common().prepare_guards()
    c.write_bytes('/etc/erpc/arc/startup-revoked', b'explicit original Arc migration')
    c.command('/usr/bin/systemctl', 'daemon-reload')
    c.shutdown(state)
    for component in process.UNITS:
        c.command('/usr/bin/systemctl', 'disable', process.UNITS[component])
    inert = {component: '# Original Arc migration remains retired\n[Unit]\nDescription=Arc retired ' + component + '\n[Service]\nType=oneshot\nExecStart=/usr/bin/false\n'
             for component in process.UNITS}
    units.publish(c, state, inert, journal['state']['runtime'], request['target'])
    process.quiescent(c, state, set(process.UNITS), units.historical_runtimes(c, state))
    directories(c, state, journal['layout'], finish=True)
    state['migrated'], state['phase'], state['retired'] = True, 'retired', True
    state['stopped'] = ['execution', 'consensus']
    state.pop('intent', None)
    c.save(state)
    return {'migration': 'original-account-recorded', 'stopped': True, 'data_preserved': True}


def migrate(c, request):
    c.migration_fallback = None
    try:
        return _migrate(c, request)
    except Exception:
        if c.migration_fallback is not None:
            state, originals = c.migration_fallback
            def proof(component, historical=False):
                raw = c.read('/etc/systemd/system/' + process.UNITS[component])
                if raw == originals[component].encode():
                    return
                units.proof(c, state, component, historical=True)
            try:
                process.stop(c, state, set(process.UNITS), [state['runtime']], proof)
            except Exception:
                pass
            for component, name in process.UNITS.items():
                try:
                    proof(component, historical=True)
                    c.command('/usr/bin/systemctl', 'disable', name, check=False)
                except Exception:
                    pass
        raise
