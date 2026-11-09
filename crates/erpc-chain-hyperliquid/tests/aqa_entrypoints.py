# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual emitted AQA programs: only inert fixture code executes after authentication."""
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import entrypoints_test as shared
sys.path.insert(0,str(Path(__file__).parents[1]/'templates/aqa'))
import erpc_aqa_units as units
from erpc_aqa_common import RUNTIME_FILES,UNIT


def exercise(command,inner_exit=None):
    shared.exercise(command,RUNTIME_FILES,inner_exit,'/usr/local/lib/erpc/hyperliquid-aqa')


class Entrypoints(unittest.TestCase):
    def test_actual_condition_guard_launcher_observer_and_boot_programs(self):
        rendered=units.render({'owner':'a'*32},{'uid':995,'gid':995})
        for name,key in [(UNIT,'ExecCondition='),(UNIT,'ExecStartPre='),(UNIT,'ExecStart='),
                         (units.OBSERVER,'ExecStart='),(units.FIREWALL_UNIT,'ExecStart=')]:
            with self.subTest(name=name,key=key):
                command=next(line[len(key):] for line in rendered[name].splitlines() if line.startswith(key))
                exercise(command)
        native=rendered[UNIT]
        self.assertIn('WorkingDirectory=/\n',native)
        self.assertIn('LoadCredentialEncrypted=.env:',native)
        self.assertIn('User=995\nGroup=995',native)
        self.assertIn('StandardOutput=null\nStandardError=null',native)
        self.assertFalse(any(line.startswith('Environment=') and 'PUBLISHER_PRIVATE_KEY' in line for line in native.splitlines()))
        self.assertNotIn('LoadCredential',rendered[units.OBSERVER])

    def test_condition_errors_are_failures_not_successful_skips(self):
        rendered=units.render({'owner':'a'*32},{'uid':995,'gid':995})[UNIT]
        command=next(line[len('ExecCondition='):] for line in rendered.splitlines() if line.startswith('ExecCondition='))
        for code in (0,1,7,255,'error'):exercise(command,inner_exit=code)


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--ssh':exercise(sys.argv[2])
    else:unittest.main()
