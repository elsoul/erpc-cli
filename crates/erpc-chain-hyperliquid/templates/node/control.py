#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed node/consensus lifecycle; financial signing and broadcasts stay external."""
# BEGIN ERPC TRUSTED IMPORTS
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Embedded verbatim in helpers that need sibling modules. Startup uses -I;
# only this checked directory is added, after the standard-library paths.
def trusted_imports(directory):
    import os
    import stat
    import sys
    path = os.fspath(directory)
    if not os.path.isabs(path):
        raise ValueError('helper directory must be an absolute path')
    current = os.path.sep
    for part in path.split(os.path.sep)[1:]:
        if part in ('', '.'):
            continue
        if part == '..':
            # The component being left was already checked as a real root-only
            # directory. Never normalize away an unchecked symlink ancestor.
            current = os.path.dirname(current)
            continue
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('helper ancestors must be real root-owned directories')
    path = current
    if path == os.path.sep:
        raise ValueError('the filesystem root is not a helper directory')
    # Do not create root0700 bytecode caches before an unprivileged helper
    # imports the same module. Existing readable caches remain fully checked.
    sys.dont_write_bytecode = True
    pending = [path]
    while pending:
        for child in os.scandir(pending.pop()):
            info = child.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('helper modules must be writable only by root')
            if stat.S_ISDIR(info.st_mode):
                if (child.name == '__pycache__'
                        and not os.access(child.path, os.X_OK, effective_ids=True)):
                    # No traversal means Python cannot read any cached module
                    # here and must use the checked source. Denied listing alone
                    # (e.g. mode0711) is not sufficient for this exception.
                    continue
                pending.append(child.path)
            elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('helper modules cannot be links or special files')
    if path not in sys.path:
        sys.path.append(path)
# END ERPC TRUSTED IMPORTS
import os
from pathlib import Path
import sys
PublicError = ()


def main():
    global PublicError
    import fcntl
    import resource
    trusted_imports(Path(__file__).absolute().parent)
    import erpc_hl_host as host
    import erpc_hl_processes as processes
    import erpc_hl_public as public
    import erpc_hl_setup as setup
    from erpc_hl_common import ENV, ROOT, Refused, execute, json_bytes, owned_directory, require, token, unique_json
    from erpc_hl_state import State
    PublicError = Refused
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    require(os.geteuid() == 0, 'root is required')
    host.protected_paths()
    state = State(ROOT)
    if len(sys.argv) == 3 and sys.argv[1] in ('condition','guard', 'guard-validator', 'firewall-load'):
        c = host.contract(state.get('owner.json')['contract'])
        require(c['owner'] == token(sys.argv[2]), 'unit owner differs from its original reservation')
        if sys.argv[1] in ('condition','guard','guard-validator'):
            installed,_,_=host.ready(c)
            if sys.argv[1]=='guard-validator':
                require(c['role']=='validator' and installed['operation']['target'].get('mode')=='validator',
                        'runtime credential requested outside its activated validator profile')
                import erpc_hl_validator
                erpc_hl_validator.verify_runtime(c)
        else:
            host.common_firewall().dispatch('load')
        return
    if len(sys.argv) == 5 and sys.argv[1] == 'logs':
        c = host.contract(state.get('owner.json')['contract'])
        require(c['owner'] == token(sys.argv[2]), 'journal owner differs from its original reservation')
        require(sys.argv[3].isascii() and sys.argv[3].isdigit() and len(sys.argv[3]) <= 5
                and int(sys.argv[3]) <= 10000 and sys.argv[4] in ('once', 'follow'), 'invalid bounded journal request')
        argv = ['/usr/bin/journalctl', '--no-pager', '-o', 'short-iso', '-n', sys.argv[3],
                '-u', 'erpc-hyperliquid-node', '-u', 'erpc-hyperliquid-rpc', '-u', 'erpc-hyperliquid-retention']
        if sys.argv[4] == 'follow':
            argv.append('--follow')
        os.execvpe(argv[0], argv, ENV)
    require(sys.argv[1:] in ([], ['play']), 'unsupported controller invocation')
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536, 'request exceeded its bound')
    request = unique_json(raw)
    require(isinstance(request, dict) and set(request) <= {'action', 'contract', 'target', 'policy', 'intent', 'firewall',
                                                        'key_file','restore','keys_unhosted','original_uuid'},
            'unrecognized lifecycle request fields')
    action = request.get('action')
    if action!='import-validator':
        require(not any(name in request for name in ('key_file','restore','keys_unhosted')),
                'private custody data belongs only to its explicit import operation')
    require('original_uuid' not in request or action=='recover-validator-filesystem',
            'original filesystem UUID belongs only to explicit stopped recovery')
    c = host.contract(request.get('contract'))
    fd = None
    if sys.argv[1:] != ['play'] and action != 'status':
        owned_directory(Path('/opt/erpc'))
        fd = os.open('/opt/erpc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(fd)
            raise Refused('another node operation owns the host') from None
    try:
        if action == 'preflight':
            result = host.preflight(request)
        elif action == 'initialize':
            result = host.initialize(request)
        else:
            state.check(c)
            if action=='import-validator':
                require(sys.argv[1:]!=['play'],'consensus custody uses direct concealed stdin, never a carried play')
                result=host.import_validator(request)
            elif action == 'authorize':
                _, target, _, _, _ = host.qualified(request, exact=False)
                result = {'intent': state.authorize(c, token(request.get('intent')), target)}
            elif action == 'prepare':
                result = host.prepare(request)
            elif action == 'recover-validator-filesystem':
                import erpc_hl_validator
                require(c['role']=='validator' and isinstance(request.get('original_uuid'),str),
                        'explicit validator original filesystem UUID is required')
                erpc_hl_validator.native_path(c,original_uuid=request['original_uuid'])
                result={'private_filesystem_upgraded':True,'stopped':True,'history_preserved':True,
                        'next_action':'deploy the qualified current controller before starting'}
            elif action == 'recover-preparation':
                result = state.recover_preparation(c, host.stop_owned)
            elif action == 'check-deploy':
                _, target, _, _, _ = host.qualified(request, exact=False)
                current = state.current(c, token(request.get('intent')))
                require(current['target'] == target, 'firewall request differs from its authorized deployment')
                result = {'authorized': True}
            elif action in ('firewall-apply', 'firewall-confirm'):
                require(action != 'firewall-apply' or sys.argv[1:] == ['play'],
                        'firewall application requires the carried operation lock')
                result = host.firewall_operation(c, token(request.get('intent')), request.get('firewall'),
                                                'apply' if action == 'firewall-apply' else 'confirm')
            elif action == 'activate':
                intent = token(request.get('intent'))
                current = state.current(c, intent)
                prepared = state.get('prepared.json')
                require(prepared['operation'] == current, 'prepared target differs from activation intent')
                receipt = {'configuration': prepared['configuration'], 'firewall': request.get('firewall')}
                host.public_receipt(receipt['configuration'], c['network'])
                host.firewall(receipt['firewall'])
                state.finish(c, intent, receipt)
                try:
                    host.ready(c, intent)
                    services=['erpc-hyperliquid-node.service','erpc-hyperliquid-retention.timer']
                    if current['target'].get('mode')!='validator':services.append('erpc-hyperliquid-rpc.service')
                    execute(['/usr/bin/systemctl','enable','erpc-hyperliquid-firewall.service',*services])
                    execute(['/usr/bin/systemctl','start',*services])
                    host.started(c,current['target'].get('mode','follower'))
                    state.consume(c, intent)
                except Exception:
                    state.cancel(c, False, host.stop_owned)
                    raise
                result = {'started': True, 'readiness': 'separate synchronization observation required'}
            elif action in ('stop', 'retire'):
                state.cancel(c, action == 'retire', lambda: host.stop_owned(retire=action == 'retire'))
                result = {'stopped': True, 'retired': action == 'retire', 'data_preserved': True}
            elif action in ('start', 'restart'):
                if action == 'restart':
                    state.cancel(c, False, host.stop_owned)
                manual = (ROOT / 'stopped').exists()
                installed,_,_=host.ready(c, manual=manual)
                try:
                    if manual:
                        state.manual_ready(c)
                    services=['erpc-hyperliquid-node.service','erpc-hyperliquid-retention.timer']
                    if installed['operation']['target'].get('mode')!='validator':services.append('erpc-hyperliquid-rpc.service')
                    execute(['/usr/bin/systemctl','start',*services])
                    host.started(c,installed['operation']['target'].get('mode','follower'))
                except Exception:
                    state.cancel(c,False,host.stop_owned)
                    raise
                result = {'started': True}
            elif action == 'status':
                result = host.observe(c)
            else:
                raise Refused('unsupported Hyperliquid node operation')
        print(json_bytes(result).decode())
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Only controller-defined fixed messages are operator-visible. Native
        # argv, HTTP bodies and key-bearing child output never enter errors.
        print(str(error) if isinstance(error, PublicError) else 'Hyperliquid operation failed; retained data was not deleted', file=sys.stderr)
        # A condition rejection must be a failed startup (eligible for the
        # configured bounded restart delay), never an apparently successful skip.
        sys.exit(255 if len(sys.argv)>1 and sys.argv[1]=='condition' else 1)
