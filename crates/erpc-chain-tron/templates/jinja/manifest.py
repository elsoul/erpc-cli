#!/usr/bin/python3 -I
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Record only verified public artifacts; caller already owns the host run lock."""
import json
import os
from pathlib import Path
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

if __name__ == '__main__':
    trusted_imports(Path(__file__).absolute().parent)
from control import Control, digest
from identity import unique_object


def main():
    if len(sys.argv) != 4:
        raise ValueError('expected release directory, intent and exact reviewed target')
    directory, intent, raw = sys.argv[1:]
    target = json.loads(raw, object_pairs_hook=unique_object)
    controller = Control()
    contract = controller.read('/etc/tron/contract.json')
    controller.phase(contract, intent, target)
    if directory != '/opt/tron/releases/' + target['tag'] + '-' + target['architecture']:
        raise ValueError('manifest directory differs from the intended target')
    root = Path(directory)
    if digest(root / 'FullNode.jar') != target['jar_sha256'] or digest(root / 'network.conf') != target['config_sha256']:
        raise ValueError('installed release/config digest changed')
    value = dict(directory=directory, network=target['network'], architecture=target['architecture'],
                 genesis=target['genesis'], client_version=target['version'], target=target,
                 jar_sha256=target['jar_sha256'], config_sha256=target['config_sha256'],
                 inspector_sha256=digest(root / 'erpc/ErpcTronKey.class'),
                 node_config_sha256=digest(Path('/etc/tron/node.conf')))
    controller.stopped()
    controller.write('/etc/tron/release.json',value,mode=0o644)


if __name__ == '__main__':
    main()

