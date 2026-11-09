#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Resume only an incomplete, owned bootstrap; never erase a running database."""
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile


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

if __name__ == '__main__':
    trusted_imports('/usr/local/lib/erpc')
import rollup_control as c


DATABASE_ROOTS = {'db', 'static_files', 'rocksdb', 'reth.toml'}


def archive_hash(path):
    c.require(path.is_file() and not path.is_symlink(), 'unsafe snapshot archive')
    with path.open('rb') as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
        return digest.hexdigest()


def extract_op(archive, destination):
    """Run as the follower user, with a read-only system and only staging writable."""
    c.require(os.geteuid() != 0, 'snapshot extraction must not run as root')
    c.require(destination.is_dir() and not destination.is_symlink(), 'unsafe bootstrap directory')
    decoder = subprocess.Popen(['zstd', '-dc', str(archive)], stdout=subprocess.PIPE)
    prefix = None
    written = 0
    try:
        with tarfile.open(fileobj=decoder.stdout, mode='r|') as entries:
            for member in entries:
                path = PurePosixPath(member.name)
                c.require(not path.is_absolute() and '..' not in path.parts, 'snapshot archive escapes its data directory')
                parts = path.parts
                if not parts:
                    continue
                if prefix is None:
                    prefix = '' if parts[0] in DATABASE_ROOTS else parts[0]
                if prefix:
                    c.require(parts[0] == prefix, 'inconsistent snapshot wrapper directory')
                    parts = parts[1:]
                if not parts:
                    continue
                c.require(member.isdir() or member.isfile(), 'snapshot links/devices are refused')
                if parts[0] not in DATABASE_ROOTS:
                    continue  # Do not import a publisher's peer identity, JWT or logs.
                target = destination.joinpath(*parts)
                for ancestor in [target, *target.parents]:
                    if ancestor == destination.parent:
                        break
                    c.require(not ancestor.is_symlink(), 'bootstrap output contains a symlink')
                if member.isdir():
                    target.mkdir(mode=0o750, parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
                temporary = target.with_name(target.name + '.erpc-incomplete')
                c.require(not temporary.is_symlink(), 'unsafe bootstrap temporary file')
                source = entries.extractfile(member)
                c.require(source is not None, 'snapshot member has no content')
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
                with os.fdopen(fd, 'wb') as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                c.require(temporary.stat().st_size == member.size, 'snapshot member was truncated')
                os.chmod(temporary, 0o640)
                os.replace(temporary, target)
                written += 1
        c.require(decoder.wait() == 0 and written > 0, 'snapshot decompression failed or database is empty')
    finally:
        if decoder.poll() is None:
            decoder.kill()
        decoder.wait()
        decoder.stdout.close()


def activate_completed(state):
    c.guard(state, 'execution')
    names = c.units(state['contract'])
    c.run(['systemctl', 'enable', names['upstreams'], names['execution'], names['consensus'], names['rpc']])
    c.run(['systemctl', 'start', '--no-block', names['upstreams'], names['execution'], names['consensus'], names['rpc']])


def worker(contract):
    state = c.read_state()
    c.check(state, contract)
    if state.get('bootstrap_done'):
        fd = os.open(c.LOCK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            current = c.read_state()
            c.check(current, contract)
            c.require(current.get('lifecycle_generation', 0) == state.get('lifecycle_generation', 0),
                      'bootstrap completion was canceled by a later lifecycle operation')
            activate_completed(current)
        finally:
            os.close(fd)
        return
    c.guard(state, 'bootstrap')
    conf, data, opt = c.paths(contract)
    c.root_file(conf / 'network.json')
    config = json.loads((conf / 'network.json').read_bytes())
    snapshot = state['bootstrap']
    destination = data / 'execution'
    cache = data / 'bootstrap-cache'
    c.require(destination.is_dir() and cache.is_dir() and not destination.is_symlink() and not cache.is_symlink(), 'bootstrap directories are unsafe')
    user = 'erpc-' + contract['family']
    clean_environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': str(data)}
    if snapshot['kind'] == 'base-manifest':
        manifest = conf / 'base-manifest.json'
        c.root_file(manifest)
        c.require(hashlib.sha256(manifest.read_bytes()).hexdigest() == snapshot['sha256'], 'Base bootstrap manifest changed')
        command = ['runuser', '-u', user, '--', str(opt / 'current/base-reth-node'), 'download',
                   '--chain', config['execution_chain'], '--datadir', str(destination),
                   '--manifest-path', str(manifest), '--non-interactive', '--resumable=true',
                   '--' + contract['history']]
        subprocess.run(command, env=clean_environment, check=True)
    elif snapshot['kind'] == 'op-archive':
        archive = cache / 'snapshot.tar.zst'
        valid = archive.exists() and archive_hash(archive) == snapshot['sha256']
        if not valid:
            # The URL and hash are a fixed first-party pair selected before this
            # job. A retry resumes those bytes; it never switches to "latest".
            subprocess.run(['runuser', '-u', user, '--', 'curl', '--fail', '--show-error',
                            '--proto', '=https', '--continue-at', '-', '--output', str(archive),
                            snapshot['url']], env=clean_environment, check=True)
        if archive_hash(archive) != snapshot['sha256']:
            archive.unlink()  # Only an invalid download cache; no database data is removed.
            raise c.Refused('snapshot SHA-256 mismatch; retry downloads fresh bytes')
        subprocess.run(['runuser', '-u', user, '--', '/usr/bin/python3', '-I', str(c.LIB / 'rollup_bootstrap.py'),
                        '--extract-op', str(archive), str(destination)], env=clean_environment, check=True)
    elif snapshot['kind'] == 'genesis':
        c.require(not any(destination.iterdir()), 'genesis bootstrap data was unexpectedly modified')
    else:
        raise c.Refused('unknown bootstrap strategy')
    # Completion is the only mutation after the long operation. Re-read ownership
    # and intent under the common run lock so a retired/superseded job cannot start.
    fd = os.open(c.LOCK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        current = c.read_state()
        c.check(current, contract)
        c.require(current['phase'] == 'bootstrapping' and current['bootstrap'] == snapshot
                  and current.get('pair') == state.get('pair')
                  and current.get('deploy_intent') == state.get('deploy_intent')
                  and current.get('lifecycle_generation', 0) == state.get('lifecycle_generation', 0), 'bootstrap was stopped, retired or superseded')
        # Keep the downloader's prune configuration outside the writable datadir.
        generated = destination / 'reth.toml'
        c.require(not generated.is_symlink(), 'unsafe generated execution configuration')
        contents = generated.read_bytes() if generated.exists() else b''
        c.atomic(conf / 'reth.toml', contents, 0o644)
        receipt = json.loads((conf / 'installation.json').read_bytes())
        receipt['files'][str(conf / 'reth.toml')] = hashlib.sha256(contents).hexdigest()
        c.atomic(conf / 'installation.json', json.dumps(receipt, sort_keys=True).encode(), 0o644)
        current['bootstrap_done'] = True
        current['phase'] = 'installed'
        c.write_state(current)
        activate_completed(current)
    finally:
        os.close(fd)


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--extract-op':
        extract_op(Path(sys.argv[2]), Path(sys.argv[3]))
        return
    c.require(os.geteuid() == 0 and len(sys.argv) == 5, 'invalid bootstrap invocation')
    owner, family, network, history = sys.argv[1:]
    worker({'owner': owner, 'family': family, 'network': network, 'history': history})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Owned bootstrap incomplete; resume the same source after inspecting its journal', file=sys.stderr)
        sys.exit(1)
