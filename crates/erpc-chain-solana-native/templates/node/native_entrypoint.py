# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Build workers authenticate their protected source before Python interprets it."""
from pathlib import Path
import re
from native_files import require

TRUST = r'''# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
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
'''


def build_command(path):
    return command(path, 'native_build.py')


def runtime_command(path):
    return command(path, 'native_runtime_control.py')


def proof_command(path):
    return command(path, 'native_runtime_control.py', proof=True)


def command(path, filename, proof=False):
    path = Path(path)
    require(filename in ('native_build.py', 'native_runtime_control.py')
            and path.is_absolute() and path.name == filename
            and re.fullmatch('[a-f0-9]{64}', path.parent.name)
            and all(part not in ('.', '..') and re.fullmatch('[A-Za-z0-9_.-]+', part)
                    for part in path.parts[1:]), 'invalid immutable build helper path')
    conditions = "(['condition'], ['gateway-condition'], ['proof-condition'])" if proof else "(['condition'], ['gateway-condition'])"
    program = (TRUST + '\nimport runpy, sys\ntry:\n trusted_imports(' + repr(str(path.parent)) + ')\n'
               + ' runpy.run_path(' + repr(str(path)) + ", run_name='__main__')\n"
               + "except BaseException as error:\n"
               + " if isinstance(error, SystemExit) and error.code in (None, 0): raise\n"
               + " print('Native helper authentication or execution failed', file=sys.stderr)\n"
               + " sys.exit(255 if sys.argv[1:] in " + conditions + " or (len(sys.argv)==3 and sys.argv[1]=='migration-run-condition') else 1)\n")
    # Hex keeps systemd specifiers, quoting and variable expansion out of code.
    return '/usr/bin/python3 -I -c "exec(bytes.fromhex(\'' + program.encode().hex() + '\'))"'
