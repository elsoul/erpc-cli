#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic proc records and a Linux-only inert child, never a node process."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_process as process


class Processes(unittest.TestCase):
    def fixture(self, root, pid, uid):
        directory=root/str(pid);directory.mkdir()
        (directory/'stat').write_text(str(pid)+' (inert name with ) parenthesis) S '+'0 '*18+'90210 0\n')
        (directory/'status').write_text('Name:\tinert\nUid:\t'+'\t'.join(str(uid) for _ in range(4))+'\n')
        return directory

    def test_saved_effective_and_filesystem_uid_are_checked_not_only_real_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=self.fixture(root,123,2001)
            with patch.object(process,'PROC',root):
                process.assert_quiescent(2002)
                for position in range(4):
                    ids=[2002]*4;ids[position]=2001
                    (directory/'status').write_text('Uid:\t'+'\t'.join(map(str,ids))+'\n')
                    with self.assertRaises(ValueError):process.assert_quiescent(2001)

    def test_pid_reuse_ambiguous_uid_and_unknown_metadata_are_not_treated_as_idle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=self.fixture(root,123,2002)
            with patch.object(process,'PROC',root):
                with patch.object(process,'generation',side_effect=[123,456]):
                    with self.assertRaises(ValueError):process.assert_quiescent(2001)
                (directory/'status').write_text('Uid: 2002 2002 2002 2002\nUid: 2002 2002 2002 2002\n')
                with self.assertRaises(ValueError):process.assert_quiescent(2001)
                with patch.object(process,'bounded',side_effect=PermissionError('inert denied metadata')):
                    with self.assertRaises(PermissionError):process.assert_quiescent(2001)

    @unittest.skipUnless(sys.platform=='linux' and os.getuid()!=0,'Linux non-root proc acceptance')
    def test_inert_process_outside_any_managed_systemd_unit_is_still_detected(self):
        child=subprocess.Popen([sys.executable,'-I','-c','import time; time.sleep(30)'])
        try:
            with patch.object(process,'PROC',types.SimpleNamespace(iterdir=lambda:iter([Path('/proc')/str(child.pid)]))):
                with self.assertRaises(ValueError):process.assert_quiescent(os.getuid())
        finally:
            child.terminate();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
