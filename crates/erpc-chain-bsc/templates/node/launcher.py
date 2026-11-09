#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Select one complete protected revision before loading any BSC controller code."""
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
# BEGIN ERPC TRUSTED RELEASE
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
# Used only by the explicit release-pointer command API, never generic imports.
def trusted_release(namespace, profiles):
    import hashlib
    import os
    import re
    import stat
    if not os.path.isabs(namespace) or os.path.normpath(namespace) != namespace:
        raise ValueError('invalid helper release namespace')
    current = os.path.sep
    for part in namespace.split(os.path.sep)[1:]:
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('release namespace ancestors must be real root-owned directories')
    pointer = os.path.join(namespace, 'current')
    info = os.lstat(pointer)
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
        raise ValueError('only a root-owned current release pointer is allowed')
    selected = os.readlink(pointer)
    prefix = namespace + '/releases/'
    if selected.startswith('releases/'):
        selected = namespace + '/' + selected
    if not selected.startswith(prefix) or not re.fullmatch('[a-f0-9]{64}', selected[len(prefix):]):
        raise ValueError('release pointer must select one immutable SHA-256 directory')
    # Resolve no further symlinks. The selected real path remains stable even
    # if a concurrent authorized publication replaces the current pointer.
    trusted_imports(selected)
    cache = os.path.join(selected, '__pycache__')
    if os.path.exists(cache) and not os.path.isdir(cache):
        raise ValueError('helper cache must be a protected real directory')
    names = set(os.listdir(selected)) - {'__pycache__'}
    matching = [profile for profile in profiles if set(profile) == names]
    if len(matching) != 1:
        raise ValueError('helper release does not match an allowed complete file profile')
    digest = hashlib.sha256()
    for name in matching[0]:
        if not re.fullmatch('[A-Za-z0-9_.-]+', name) or name in ('.', '..'):
            raise ValueError('invalid helper profile member')
        source = os.path.join(selected, name)
        info = os.lstat(source)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ValueError('helper profile members must be protected real files')
        with open(source, 'rb') as stream:
            for block in iter(lambda: stream.read(128 * 1024), b''):
                digest.update(block)
    if digest.hexdigest() != selected[len(prefix):]:
        raise ValueError('helper release content differs from its immutable digest')
    return selected
# END ERPC TRUSTED RELEASE
import runpy

selected = trusted_release('/usr/local/lib/erpc/bsc', [
    ['control.py', 'bootstrap.py', 'catalog.json'],
    ['control.py', 'bootstrap.py', 'validator.py', 'catalog.json'],
])
runpy.run_path(selected + '/control.py', run_name='__main__')
