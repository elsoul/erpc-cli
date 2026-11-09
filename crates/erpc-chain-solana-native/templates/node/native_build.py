#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Unprivileged fetch/compile worker. Root publishes artifacts only after quiescence."""
import fcntl
import hashlib
import os
from pathlib import Path
import pwd
import re
import resource
import stat
import struct
import subprocess
import sys

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

if __name__ == "__main__":
    trusted_imports(Path(__file__).absolute().parent)

from native_files import atomic, digest_file, encoded, json_value, read, require, root_directory

JOBS = Path('/var/lib/erpc-solana-build/jobs')
TOOLCHAINS = Path('/opt/erpc/solana/toolchains')
MAX_BINARY = 3_000_000_000
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'


def build_environment(work, compiler, frozen):
    """Never inherit SSH agents, provider credentials, cargo/rustup or shell overrides."""
    result = {'PATH': str(compiler / 'bin') + ':/usr/bin:/bin',
              'HOME': str(work / 'home'), 'CARGO_HOME': str(work / 'cargo-home'),
              'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
              'NO_RUSTUP_OVERRIDE': '1', 'CARGO_BUILD_JOBS': '2',
              'RUSTC': str(compiler / 'bin/rustc'), 'RUSTDOC': str(compiler / 'bin/rustdoc'),
              'CARGO_NET_GIT_FETCH_WITH_CLI': 'true',
              'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
              'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': 'https', 'GIT_NO_REPLACE_OBJECTS': '1',
              'CC': '/usr/bin/clang', 'CXX': '/usr/bin/clang++', 'PROTOC': '/usr/bin/protoc'}
    if frozen:
        result['CARGO_NET_OFFLINE'] = 'true'
        result['PATH'] = str(work / 'shim') + ':' + result['PATH']
    return result


def execute(args, env, cwd, *, capture=False, timeout=1800, maximum=65536):
    require(args and str(args[0]).startswith('/'), 'absolute build executable required')
    completed = subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=False,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None, timeout=timeout, close_fds=True)
    require(completed.returncode == 0, 'qualified source-build subprocess failed')
    if capture:
        require(len(completed.stdout) <= maximum and len(completed.stderr) <= 65536,
                'build metadata exceeds its bound')
        return completed.stdout
    return b''


def git(args, env, source, capture=False, maximum=65536):
    return execute(['/usr/bin/git', '--no-pager', '-c', 'core.hooksPath=/dev/null',
                    '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '-c', 'credential.helper=',
                    '-c', 'core.askPass=', '-c', 'fsck.skipList=/dev/null', *args], env, source, capture=capture, maximum=maximum)


def qualify_tree(source, env):
    # Never let assume-unchanged/skip-worktree flags hide modified source inputs.
    # fsck checks the object graph; every tracked blob is then hashed from its
    # actual filesystem bytes, independently of Git's working-tree stat cache.
    git(['fsck', '--strict', '--no-reflogs', '--no-dangling'], env, source, True)
    tree = git(['ls-tree', '-r', '-z', '--full-tree', 'HEAD'], env, source, True, 8 * 1024 * 1024)
    count, tracked = 0, set()
    for entry in tree.split(b'\0'):
        if not entry:
            continue
        count += 1
        require(count <= 100000, 'qualified source tree exceeds its file bound')
        metadata, filename = entry.split(b'\t', 1)
        mode, kind, expected = metadata.split()
        relative = Path(os.fsdecode(filename))
        require(kind == b'blob' and mode in (b'100644', b'100755', b'120000')
                and not relative.is_absolute() and '..' not in relative.parts,
                'unsupported source tree member')
        tracked.add(str(relative))
        path = source / relative
        for parent in relative.parents:
            candidate = source / parent
            require(candidate.is_dir() and not candidate.is_symlink(), 'source ancestor redirected')
        if mode == b'120000':
            require(path.is_symlink() and path.resolve().is_relative_to(source.resolve()),
                    'source symlink escapes the qualified checkout')
            content = os.fsencode(os.readlink(path))
        else:
            content = read(path, 64 * 1024 * 1024, os.geteuid())
            require(bool(path.stat().st_mode & 0o111) == (mode == b'100755'), 'source executable mode changed')
        actual = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
        require(actual.encode() == expected, 'tracked source bytes differ from the qualified tree')
    require(count > 0, 'empty source tree')
    return tracked


def qualify_extra_inputs(source, env, tracked):
    # Enumerate actual files, independently of Git ignores, index flags or
    # core.worktree. Only Git metadata and Cargo's ordinary target directory
    # are outside the source input set; never follow an untracked symlink.
    pending, entries = [source], 0
    while pending:
        with os.scandir(pending.pop()) as children:
            for child in children:
                entries += 1
                require(entries <= 100000, 'source input enumeration exceeds its bound')
                relative = str(Path(child.path).relative_to(source))
                if relative in ('.git', 'target'):
                    continue
                if child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    require(relative in tracked, 'untracked source input is outside the qualified tree')
    target = source / 'target'
    if target.exists() or target.is_symlink():
        info = target.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                'compiler output directory is redirected or untrusted')
    require(Path(env['CARGO_HOME']) == source.parent / 'cargo-home'
            and Path(env['HOME']) == source.parent / 'home', 'compiler cache or home escapes its job')
    # Cargo searches the actual cwd's ancestors as well as CARGO_HOME. Include
    # lexical ancestors too, so a symlink alias cannot conceal an extra config.
    directories = {source, *source.parents, source.resolve(), *source.resolve().parents}
    for directory in directories:
        for filename in ('config', 'config.toml'):
            path = directory / '.cargo' / filename
            if path.exists() or path.is_symlink():
                require(directory.resolve() == source.resolve() and not path.is_symlink() and filename == 'config.toml'
                        and '.cargo/config.toml' in tracked, 'unqualified hierarchical Cargo configuration')
    for directory in (Path(env['CARGO_HOME']), Path(env['HOME'])):
        if directory.exists() or directory.is_symlink():
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                    'compiler home or cache is redirected or untrusted')
    for filename in ('config', 'config.toml'):
        path = Path(env['CARGO_HOME']) / filename
        require(not path.exists() and not path.is_symlink(), 'unqualified Cargo cache configuration')


def qualify_source(catalog, profile, source, env):
    import tomllib
    require(source.is_dir() and not source.is_symlink()
            and (source / '.git').is_dir() and not (source / '.git').is_symlink(),
            'source checkout is missing or redirected')
    head = git(['rev-parse', '--verify', 'HEAD'], env, source, True).decode().strip()
    require(head == profile['commit'], 'source commit differs from the qualified profile')
    tracked = qualify_tree(source, env)
    qualify_extra_inputs(source, env, tracked)
    require(not (source / '.gitmodules').exists(), 'unexpected source submodule policy')
    lock = read(source / 'Cargo.lock', 1048576, os.geteuid())
    require(hashlib.sha256(lock).hexdigest() == profile['cargo_lock_sha256'], 'upstream Cargo.lock changed')
    packages = tomllib.loads(lock.decode())['package']
    git_sources = set()
    for item in packages:
        origin = item.get('source')
        if origin is None:
            continue
        require(origin == REGISTRY or origin in catalog['git_sources'], 'unqualified dependency origin')
        if origin.startswith('git+'):
            git_sources.add(origin)
        else:
            require(re.fullmatch('[a-f0-9]{64}', item.get('checksum', '')), 'registry package lacks an exact checksum')
    require(git_sources == set(catalog['git_sources']), 'upstream pinned git dependencies differ')
    toolchain = tomllib.loads(read(source / 'rust-toolchain.toml', 16384, os.geteuid()).decode())
    require(toolchain['toolchain']['channel'] == profile['rust'], 'source compiler pin differs')
    return {'commit': head, 'cargo_lock_sha256': profile['cargo_lock_sha256'], 'rust': profile['rust']}


def elf(path, owner):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                and 64 <= info.st_size <= MAX_BINARY, 'invalid native candidate file')
        header = stream.read(64)
        require(header[:7] == b'\x7fELF\x02\x01\x01'
                and struct.unpack_from('<HH', header, 16) in ((2, 62), (3, 62)),
                'candidate is not a Linux x86-64 ELF executable')
    return {'size': info.st_size, 'sha256': digest_file(path, MAX_BINARY)}


def fetch(catalog, profile, job, work):
    compiler, source = TOOLCHAINS / profile['rust'], work / 'source'
    env = build_environment(work, compiler, False)
    for path in (work / 'home', work / 'cargo-home'):
        path.mkdir(mode=0o700, exist_ok=True)
    if not source.exists():
        source.mkdir(mode=0o700)
        git(['init', '--quiet'], env, source)
    if not (work / 'fetch-result.json').exists():
        # This checkout is private to one explicit intent. Interrupted fetches
        # resume the exact commit; no branch head or implicit latest is used.
        git(['fetch', '--no-tags', '--depth=1', catalog['repository'], profile['commit']], env, source)
        git(['checkout', '--detach', profile['commit']], env, source)
    qualified = qualify_source(catalog, profile, source, env)
    execute([compiler / 'bin/cargo', 'fetch', '--locked'], env, source)
    require(qualify_source(catalog, profile, source, env) == qualified, 'source changed during fetch')
    atomic(work / 'fetch-result.json', encoded({'request': job, 'source': qualified}))


def compile_source(catalog, profile, job, work):
    compiler, source = TOOLCHAINS / profile['rust'], work / 'source'
    env = build_environment(work, compiler, True)
    qualified = qualify_source(catalog, profile, source, env)
    fetched = json_value(read(work / 'fetch-result.json', 16384, os.geteuid()))
    require(fetched == {'request': job, 'source': qualified}, 'dependency fetch belongs to another build intent')
    shim = work / 'shim'
    shim.mkdir(mode=0o700, exist_ok=True)
    # The upstream ./cargo wrapper honors NO_RUSTUP_OVERRIDE. Only production
    # build calls are allowed; the vendor's DCOU unit-graph check remains intact.
    wrapper = '#!/bin/sh\nset -eu\n[ "$1" = build ] || exit 64\nexec ' + str(compiler / 'bin/cargo') + ' "$@" --frozen\n'
    atomic(shim / 'cargo', wrapper.encode(), 0o500)
    output = work / 'output'
    execute(['/bin/bash', source / 'scripts/cargo-install-all.sh', *catalog['build_options'], output],
            env, source, timeout=14400)
    require(qualify_source(catalog, profile, source, env) == qualified, 'source changed during compilation')
    artifacts = {name: elf(output / 'bin' / name, os.geteuid()) for name in catalog['publish_binaries']}
    atomic(work / 'build-result.json', encoded({'request': job, 'source': qualified, 'files': artifacts}))


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    require(len(sys.argv) == 3 and sys.argv[1] in ('fetch', 'compile'), 'invalid build worker request')
    action, intent = sys.argv[1:]
    require(re.fullmatch('[a-f0-9]{32}', intent), 'invalid build intent')
    account = pwd.getpwnam('erpc-solana-build')
    require(os.getuid() == os.geteuid() == account.pw_uid != 0
            and os.getgid() == account.pw_gid != 0 and set(os.getgroups()) <= {account.pw_gid}
            and os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64' and sys.version_info >= (3, 12),
            'build worker requires its isolated Linux account and Python3.12')
    job_directory = JOBS / intent
    root_directory(job_directory)
    job = json_value(read(job_directory / 'request.json', 16384))
    catalog_bytes = read(Path(__file__).parent / 'catalog.json', 65536)
    catalog = json_value(catalog_bytes)
    network = job.get('network')
    require(network in ('mainnet', 'testnet'), 'invalid build network')
    profile = catalog['networks'][network]
    require(job == {'schema': 1, 'network': network, 'intent': intent,
                    'commit': profile['commit'], 'version': profile['version'],
                    'catalog_sha256': hashlib.sha256(catalog_bytes).hexdigest()},
            'build request differs from its immutable catalog')
    work = job_directory / 'work'
    info = work.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == account.pw_uid
            and info.st_mode & 0o7777 == 0o700, 'build workspace ownership differs')
    lock = os.open(job_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        (fetch if action == 'fetch' else compile_source)(catalog, profile, job, work)
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Isolated Agave build failed; inspect the public build journal and retry its exact intent', file=sys.stderr)
        sys.exit(1)
