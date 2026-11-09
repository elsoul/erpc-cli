#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Strict rendering of original financial/observer service and firewall profiles."""
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
try:
    from jinja2 import Environment,StrictUndefined
except ImportError:
    Environment=None


@unittest.skipUnless(Environment is not None,'strict render uses the pinned Ansible/Jinja Python')
class Render(unittest.TestCase):
    def test_all_runtime_phases_keep_root_credentials_checked_conditions_and_tls_dependency(self):
        environment=Environment(undefined=StrictUndefined,autoescape=False,keep_trailing_newline=True)
        count=0
        for phase in ('observing','active'):
            for addresses in ([],['198.51.100.1/32']):
                values={'validator_request':{'target':{'phase':phase}},'validator_runtime_command':'/usr/bin/python3 -I -c "checked-runtime"',
                        'validator_condition_command':'/usr/bin/python3 -I -c "checked-condition-255"','validator_family':'arbitrum',
                        'validator_management_v4':addresses,'validator_management_v6':['2001:db8::1/128'],'validator_ssh_port':2200}
                rendered={}
                for path in (ROOT/'templates/validator/ansible').glob('*.j2'):
                    rendered[path.name]=environment.from_string(path.read_text()).render(**values);count+=1
                node=rendered['nitro.service.j2'];parent=rendered['upstreams.service.j2']
                self.assertIn('User=0\nGroup=0',node);self.assertIn('User=0\nGroup=0',parent)
                self.assertIn('BindsTo=erpc-arbitrum-upstreams.service',node)
                self.assertIn('ExecStartPost=/usr/bin/python3 -I -c "checked-runtime" runtime-ready transport',parent)
                for content in (node,parent):
                    self.assertIn('ExecCondition=/usr/bin/python3 -I -c "checked-condition-255"',content)
                    self.assertIn('Restart=no',content);self.assertIn('LimitCORE=0',content)
                self.assertEqual('LoadCredentialEncrypted=arbitrum-wallet:' in node,phase=='active')
                self.assertIn('LoadCredentialEncrypted=arbitrum-parent-tls:',parent)
                firewall=rendered['firewall.nft.j2']
                self.assertIn('policy drop',firewall);self.assertIn('tcp dport 2200 ip6',firewall)
                self.assertNotIn('dport 8547',firewall);self.assertNotIn('dport 18545',firewall)
        self.assertEqual(count,16)


if __name__=='__main__':unittest.main()
