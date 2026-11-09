# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Externally authenticate root helper ancestors before script interpretation."""
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
from pathlib import Path
from erpc_monad_common import HELPERS, require


def command(name='control.py',condition=False):
    require(name in ('control.py','cleanup.py'),'unknown fixed systemd entrypoint')
    source=Path(__file__).read_text().split('# BEGIN ERPC TRUSTED IMPORTS\n',1)[1].split('# END ERPC TRUSTED IMPORTS',1)[0]
    invocation='trusted_imports('+repr(str(HELPERS))+')\nrunpy.run_path('+repr(str(HELPERS/name))+',run_name="__main__")'
    if condition:
        # systemd255 interprets exit1..254 as a skipped ExecCondition. An
        # external authentication or import failure must instead fail startup.
        invocation=('try:\n'+''.join('    '+line+'\n' for line in invocation.splitlines())
            +'except SystemExit as error:\n    if error.code not in (None,0):\n        raise SystemExit(255) from None\n    raise\n'
            +'except BaseException:\n    print("Native startup condition authentication failed",file=sys.stderr)\n    raise SystemExit(255) from None\n')
    code=source+'\nimport runpy,sys\n'+invocation
    return '/usr/bin/python3 -I -c "exec(bytes.fromhex(\''+code.encode().hex()+'\'))"'
