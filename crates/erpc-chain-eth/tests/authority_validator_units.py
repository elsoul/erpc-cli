# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original unit bindings and root-startup leftovers with inert kernel records."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_accounts as fixture
import eth_validator_units as units
import eth_process as processes


class Units(unittest.TestCase):
    def test_privileged_startup_member_cannot_be_hidden_by_missing_mainpid_or_normal_uid_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'self').mkdir();(root/'self/cgroup').write_bytes(b'0::/inert-controller\n')
            child=root/'99999999';child.mkdir();(child/'cgroup').write_text('0::/system.slice/'+units.UNITS[1]+'\n')
            with patch.object(processes,'PROC',root),patch.object(processes,'generation',return_value=(42,b'S')), \
                 patch.object(processes,'credentials',return_value={'Uid':(0,0,0,0)}):
                with self.assertRaisesRegex(ValueError,'privileged startup'):units.privileged_starters_absent([units.UNITS[1]])
                units.privileged_starters_absent([units.UNITS[0]])
                with patch.object(processes,'generation',return_value=(42,b'Z')):units.privileged_starters_absent([units.UNITS[1]])
                (root/'self/cgroup').write_bytes(b'1:cpu:/inert\n2:memory:/inert\n')
                with self.assertRaisesRegex(ValueError,'unified'):units.privileged_starters_absent([units.UNITS[1]])

    def test_rendered_native_signer_keeps_no_auto_restart_and_never_exposes_a_password(self):
        f=fixture.Accounts();f.setUp();self.addCleanup(f.doCleanups)
        plan=fixture.accounts.provision(f.state,'validator')
        target={'pair':'reth-v2.8.1--lighthouse-v8.3.2','fee_recipient':'0x'+'1'*40,
                'artifacts':{'reth':{'sha256':'a'*64},'lighthouse':{'sha256':'b'*64}}}
        for network in ('mainnet','hoodi'):
            contract=dict(f.c,network=network)
            receipt=units.render(contract,target,plan,'c'*64,'d'*32)
            signer=receipt['definitions'][units.UNITS[3]]
            self.assertIn('Restart=no\n',signer);self.assertIn('TimeoutStartSec=660\n',signer)
            self.assertIn('LimitCORE=0\n',signer);self.assertNotIn('LoadCredential',signer)
            self.assertIn('User='+str(plan['users']['ev-validator']['uid'])+'\n',signer)
            argv=receipt['arguments'][units.UNITS[3]]
            self.assertNotIn('--datadir',argv);self.assertNotIn('--init-slashing-protection',argv)
            self.assertIn('--disable-auto-discover',argv);self.assertIn('--beacon-nodes-tls-certs',argv)
            self.assertEqual(argv[argv.index('--beacon-nodes')+1],'https://127.0.0.3:5052')
            self.assertNotIn('voting_keystore_password',signer)


if __name__=='__main__':unittest.main()
