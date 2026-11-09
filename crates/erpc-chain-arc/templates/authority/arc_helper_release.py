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
