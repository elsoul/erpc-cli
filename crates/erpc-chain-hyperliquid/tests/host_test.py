# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Closed requests and observation attribution; no accounts, clients or host mutation."""
import copy
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parents[1] / 'templates/node'))
import erpc_hl_common as common
import erpc_hl_host as h
import erpc_hl_state as state


class Host(unittest.TestCase):
    def test_helper_pointer_interruption_resumes_only_a_complete_closed_original_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();namespace=root/'helpers';namespace.mkdir()
            original_lstat=os.lstat; original_scandir=os.scandir; original_replace=os.replace
            def metadata(path,*args,**kwargs):
                fields=list(original_lstat(path,*args,**kwargs));candidate=Path(path)
                if candidate==root or root in candidate.parents:
                    if fields[4]==os.getuid():fields[4]=0
                elif candidate in root.parents:
                    fields[4]=0;fields[0]&=~0o022
                return os.stat_result(fields)
            def scan(path):
                class Entries(list):
                    def __enter__(self): return iter(self)
                    def __exit__(self,*_): return False
                with original_scandir(path) as values:
                    return Entries(SimpleNamespace(name=item.name,path=item.path,
                        is_dir=item.is_dir,is_file=item.is_file,is_symlink=item.is_symlink,
                        stat=lambda *,follow_symlinks=True,p=item.path:metadata(p)) for item in values)
            def interrupted(source,destination):
                if Path(destination)==namespace/'current':raise OSError('inert pointer publication interruption')
                original_replace(source,destination)
            with patch.object(h,'HELPERS',namespace),patch.object(h,'read',lambda p:common.read(p,owner=os.getuid())), \
                 patch.object(os,'lstat',metadata),patch.object(Path,'lstat',metadata),patch.object(os,'scandir',scan):
                revision=h.helper_digest()
                with patch.object(os,'replace',interrupted),self.assertRaises(OSError):h.publish_helpers(revision)
                self.assertTrue((namespace/'current.pending').is_symlink())
                self.assertFalse((namespace/'current').exists())
                h.protected_tree(namespace)
                h.publish_helpers(revision)
                self.assertFalse((namespace/'current.pending').is_symlink())
                self.assertEqual(os.readlink(namespace/'current'),str(namespace/'releases'/revision))
                (namespace/'current.pending').symlink_to(root)
                with self.assertRaisesRegex(ValueError,'closed release'):h.protected_tree(namespace)
                self.assertTrue((namespace/'current.pending').is_symlink())

    def test_qualification_binds_policy_exact_supervisor_and_complete_carried_files(self):
        with patch.object(h, 'read', lambda path: common.read(path, owner=os.getuid())):
            catalog = common.unique_json(h.read(h.SOURCE / 'catalog.json'))
            pin = catalog['networks']['testnet']['supervisor']
            policy = {'rpc_allow': [], 'management_allow': ['192.0.2.1/32']}
            request = {'contract': {'owner':'a'*32,'role':'rpc','network':'testnet','public_ip':'8.8.8.8'},
                       'policy':policy,'target':{key:pin[key] for key in ('id','sha256','signed_at')}}
            request['target'].update(helper_sha=h.helper_digest(),config_id=common.digest(common.json_bytes(policy)))
            self.assertEqual(h.qualified(request)[0],request['contract'])
            for changed in ('policy','helper','network','role'):
                other = copy.deepcopy(request)
                if changed == 'policy':other['policy']['rpc_allow']=['0.0.0.0/0']
                if changed == 'helper':other['target']['helper_sha']='f'*64
                if changed == 'network':other['contract']['network']='mainnet'
                if changed == 'role':other['contract']['role']='validator'
                with self.subTest(changed=changed),self.assertRaises(ValueError):h.qualified(other)
            with self.assertRaises(ValueError):h.policy({'rpc_allow':[],'management_allow':['::/0']})

    def test_status_never_accepts_wrong_owner_or_attributes_a_changed_socket_to_the_native_node(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contract = {'owner':'a'*32,'role':'rpc','network':'testnet','public_ip':'8.8.8.8'}
            selected = state.State(root);selected.put('owner.json',{'contract':contract})
            with patch.object(h,'ROOT',root),patch.object(h,'protected_paths'), \
                 patch.object(state,'read',lambda path:common.read(path,owner=os.getuid())):
                with self.assertRaises(ValueError):h.observe(dict(contract,owner='b'*32))
                with patch.object(h,'ready',side_effect=OSError('private host output')):
                    result=h.observe(contract)
                    self.assertFalse(result['ready']);self.assertEqual(result['phase'],'initialized')
                    self.assertNotIn('private',str(result))
                ready=({'operation':{'target':{'id':'visor-inert'}}},{h.setup.NATIVE:{'uid':995},h.setup.GATEWAY:{'uid':996}},
                       {'supervisor':{'sha256':'a'*64}})
                with patch.object(h,'ready',return_value=ready), \
                     patch.object(h.processes,'listener',side_effect=[['old'],['new']]), \
                     patch.object(h.public,'observe',return_value={'ready':True}), \
                     patch.object(h.processes,'observed_images') as images:
                    self.assertFalse(h.observe(contract)['ready']);images.assert_not_called()
                with patch.object(h,'ready',return_value=ready), \
                     patch.object(h.processes,'listener',return_value=['same']), \
                     patch.object(h.public,'observe',return_value={'ready':True}), \
                     patch.object(h.processes,'observed_images',return_value=[{'name':'hl-visor','sha256':'b'*64}]):
                    self.assertFalse(h.observe(contract)['ready'])

    def test_retirement_preserves_original_uid_drain_and_attempts_every_disable_after_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);selected=state.State(root)
            selected.put('account-reservation.json',{h.setup.NATIVE:{'uid':995,'gid':995},h.setup.GATEWAY:{'uid':996,'gid':996}})
            calls=[]
            def execute(argv,**kwargs):
                calls.append(argv)
                raise OSError('private disable error')
            with patch.object(h,'ROOT',root),patch.object(state,'read',lambda path:common.read(path,owner=os.getuid())), \
                 patch.object(h.processes,'stop',side_effect=OSError('private drain error')) as stop,patch.object(h,'execute',execute):
                with self.assertRaisesRegex(ValueError,'retirement disable failed') as error:h.stop_owned(retire=True)
                self.assertNotIn('private',str(error.exception))
                stop.assert_called_once_with([995,996])
                self.assertEqual(len(calls),len(h.processes.UNITS))
                self.assertTrue((root/'account-reservation.json').exists())


if __name__ == '__main__':unittest.main()
