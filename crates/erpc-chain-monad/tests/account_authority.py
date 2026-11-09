# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Original numeric cancellation and credential preconditions; inert service boundary."""
import copy
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import host_failures as fixture
import namespace_test as namespaces
control=fixture.control
common=fixture.common
state=fixture.state


class OriginalAuthority(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.state=state.State(self.root)
        self.contract={'owner':'a'*32,'network':'testnet','role':'rpc',
            'partuuid':'abcdefab-abcd-abcd-abcd-abcdefabcdef','public_ip':'8.8.8.8','name_record_sequence':1,
            'secp':'02'+'11'*32,'bls':'22'*48,'beneficiary':'0x'+'0'*40,'auth_address':'0x'+'0'*40}
        self.state.put('owner.json',{'contract':self.contract})
        self.identities={'erpc-monad':{'uid':995,'gid':995},'erpc-monad-proxy':{'uid':996,'gid':996}}
        for name in ('accounts.json','account-reservation.json'):self.state.put(name,self.identities)
        self.patches=[]
        def install(obj,name,value):
            item=patch.object(obj,name,value);item.start();self.patches.append(item)
        self.addCleanup(lambda:[item.stop() for item in reversed(self.patches)])
        install(control,'ROOT',self.root);install(control,'STATE',self.state)
        install(state,'read',lambda path:common.read(path,owner=os.getuid()))
        install(control.namespace,'paths',lambda **_:None)
        install(control,'approved_processes',lambda:{'native':'inert-public-digest'})
        install(control,'gateway_processes',lambda:{'gateway':'inert-public-digest'})
        self.stops=[]
        install(control.processes,'stop',lambda uid,approved:self.stops.append(uid))
        install(control.accounts,'accounts',lambda _:(_ for _ in ()).throw(ValueError('inert NSS drift')))

    def test_nss_drift_blocks_key_recipient_but_stops_original_numeric_writers(self):
        with self.assertRaisesRegex(ValueError,'NSS'):control.account()
        self.assertEqual(self.stops,[])
        self.assertTrue(control.dispatch({'operation':'stop','contract':self.contract})['stopped'])
        self.assertEqual(self.stops,[995,996])
        self.assertTrue((self.root/'stopped').exists())

    def test_write_failure_still_attempts_both_original_scopes_and_never_claims_durability(self):
        with patch.object(state.State,'marker',side_effect=OSError('inert full disk')), \
             patch.object(state.State,'put',side_effect=OSError('inert full disk')):
            with self.assertRaisesRegex(ValueError,'not persisted'):
                control.dispatch({'operation':'stop','contract':self.contract})
        self.assertEqual(self.stops,[995,996])
        self.assertEqual(self.state.get('accounts.json'),self.identities)

    def test_one_owned_stop_failure_does_not_suppress_other_original_uid_attempt(self):
        def fail(uid,approved):
            self.stops.append(uid)
            if uid==995:raise OSError('inert native service refusal')
        with patch.object(control.processes,'stop',fail),self.assertRaises(ValueError):control.stop_native()
        self.assertEqual(self.stops,[995,996])

    def test_foreign_contract_and_missing_original_receipt_cannot_adopt_current_nss(self):
        with self.assertRaises(ValueError):control.dispatch({'operation':'stop','contract':dict(self.contract,owner='b'*32)})
        self.assertEqual(self.stops,[])
        (self.root/'account-reservation.json').unlink()
        with self.assertRaises(FileNotFoundError):control.stop_native()
        self.assertEqual(self.stops,[])

    def test_first_condition_refuses_original_nss_before_decrypting_native_identity(self):
        with patch.object(control.os,'geteuid',return_value=0),patch.object(control.os,'umask'), \
             patch.object(control.resource,'setrlimit'),patch.object(control,'owned_directory'), \
             patch.object(control.sys,'argv',['control.py','condition',self.contract['owner']]), \
             patch.object(control.STATE,'guard',return_value={'receipt':{'configuration':{}}}), \
             patch.object(control,'paths'),patch.object(control,'inspect_device',return_value={}), \
             patch.object(control,'device_access',side_effect=lambda _:control.account()), \
             patch.object(control,'read_identity') as decrypt,self.assertRaisesRegex(ValueError,'NSS'):
            control.main()
        decrypt.assert_not_called()

    def test_skipped_condition_or_redirected_loaded_identity_never_reports_started(self):
        def healthy(argv,**kwargs):
            return fixture.types.SimpleNamespace(stdout=b'ActiveState=active\nSubState=running\nMainPID=123\nUser=995\nGroup=995\n')
        # The gateway has its independent numeric recipient.
        def service(argv,**kwargs):
            value=healthy(argv,**kwargs)
            if any('gateway' in arg for arg in argv):value.stdout=value.stdout.replace(b'995',b'996')
            return value
        with patch.object(control,'execute',service):control.started()
        for original,replacement in [(b'active',b'inactive'),(b'MainPID=123',b'MainPID=0'),(b'User=995',b'User=erpc-monad')]:
            def changed(argv,**kwargs):
                value=service(argv,**kwargs);value.stdout=value.stdout.replace(original,replacement);return value
            with patch.object(control,'execute',changed),self.assertRaises(ValueError):control.started()



class CommonBoundary(unittest.TestCase):
    def test_standalone_common_source_is_authenticated_before_interpretation(self):
        f=namespaces.Namespace();f.setUp();self.addCleanup(f.doCleanups)
        marker=f.root/'executed'
        text='from pathlib import Path\nPath('+repr(str(marker))+').touch()\nclass Firewall:\n def __init__(self,family):assert family=="monad"\n def dispatch(self,action,*values):return (action,values)\n'
        f.root.joinpath('lib/rpc-firewall.py').write_text(text)
        with patch.object(control,'read',lambda path:common.read(path,owner=os.getuid())):
            self.assertEqual(control.firewall('guard'),('guard',()))
            marker.unlink();control.namespace.FIREWALL.chmod(0o666)
            with self.assertRaises(ValueError):control.firewall('guard')
            self.assertFalse(marker.exists())


if __name__=='__main__':unittest.main()
