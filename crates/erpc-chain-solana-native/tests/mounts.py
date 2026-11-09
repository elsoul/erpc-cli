#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Linux mount metadata and public ownership failure fixtures; no real mounts."""
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'templates/node'))
import native_contract as contract
import native_mounts as mounts


def owner():
    return {'schema':1,'profile':'agave-native','inventory_id':'a'*26,'name':'fixture','network':'mainnet',
            'host_binding':'b'*64,'identity_account':'2'*44,'vote_account':'3'*44,'authority_account':'4'*44,
            'volumes':{kind:'10000000-0000-0000-0000-00000000000'+str(i)
                       for i,kind in enumerate(contract.MOUNTS,1)}}


def namespace():
    return ''.join(str(100+i)+' 10 8:'+str(i)+' / '+str(path)+' rw,relatime - ext4 /dev/inert'+str(i)+' rw\n'
                   for i,path in enumerate(contract.MOUNTS.values(),1))


class Mounts(unittest.TestCase):
    def test_public_ownership_rejects_legacy_padding_duplicate_devices_and_extra_fields(self):
        valid=owner();self.assertEqual(contract.validate(valid),valid)
        for key,value in [('profile','solv'),('network','devnet'),('identity_account','1'*32),
                          ('identity_account','z'*44),('identity_account','1'+valid['identity_account']),
                          ('authority_account',valid['identity_account']),('private_key','inert extra field')]:
            changed=dict(valid);changed[key]=value
            with self.assertRaises(ValueError):contract.validate(changed)
        changed=owner();changed['volumes']['ledger']=changed['volumes']['accounts']
        with self.assertRaises(ValueError):contract.validate(changed)

    def test_missing_readonly_overmounted_and_aliased_filesystems_are_refused(self):
        base=namespace()
        self.assertEqual(set(mounts.selected_mounts(mounts.parse(base))),set(contract.MOUNTS))
        for bad in [base.splitlines()[0]+'\n',base.replace('rw,relatime','ro,relatime',1),
                    base.replace('- ext4','- tmpfs',1),base.replace('8:2','8:1',1),
                    base+'201 10 8:1 / /other rw - ext4 /dev/inert1 rw\n',
                    base+'201 10 8:4 / /mnt/erpc-solana-ledger rw - ext4 /dev/inert4 rw\n']:
            with self.subTest(bad=bad),self.assertRaises(ValueError):mounts.selected_mounts(mounts.parse(bad))

    def test_the_mount_table_read_is_the_hosts_and_not_a_units_namespace(self):
        # A start condition runs inside the unit's namespace, where ReadWritePaths
        # are binds; read from /proc/self they would be refused as nested mounts.
        self.assertEqual(str(mounts.MOUNTINFO), '/proc/1/mountinfo')

    def test_nested_mounts_and_same_device_bind_mounts_are_refused_before_capacity(self):
        base=namespace()
        for kind,path in contract.MOUNTS.items():
            for device in ('8:9','8:'+str(list(contract.MOUNTS).index(kind)+1)):
                extra='201 101 '+device+' / '+str(path)+'/nested/deeper rw - ext4 /dev/inert rw\n'
                with self.subTest(kind=kind,device=device),self.assertRaises(ValueError):
                    mounts.selected_mounts(mounts.parse(base+extra))
        with self.assertRaises(ValueError):
            mounts.selected_mounts(mounts.parse(base.replace(' / /mnt/erpc-solana-ledger',' /subtree /mnt/erpc-solana-ledger')))

    def test_ambiguous_or_truncated_mount_metadata_does_not_become_an_empty_namespace(self):
        for bad in ('',namespace()+namespace(),'bad metadata',namespace().replace(' / /mnt',' / /mnt/../mnt',1),
                    namespace().replace(' / /mnt',r' / /mnt\123',1)):
            with self.assertRaises(ValueError):mounts.parse(bad)

    def test_actual_device_capacity_and_namespace_changes_are_checked(self):
        selected=mounts.parse(namespace());binding=owner();called=[]
        originals=Path.stat
        lookup={str(contract.MOUNTS[k]):i for i,k in enumerate(contract.MOUNTS,1)}
        lookup.update({str(mounts.UUIDS/v):i for i,v in enumerate(binding['volumes'].values(),1)})
        def device(path,*args,**kwargs):
            if str(path) not in lookup:return originals(path,*args,**kwargs)
            number=os.makedev(8,lookup[str(path)])
            return types.SimpleNamespace(st_mode=stat.S_IFBLK if path.parent==mounts.UUIDS else stat.S_IFDIR,
                                         st_rdev=number,st_dev=number)
        def usage(path):
            called.append(path)
            return types.SimpleNamespace(total=2_000_000_000_000,free=1_800_000_000_000)
        with patch.object(mounts,'root_directory'),patch.object(Path,'stat',device),patch.object(mounts.shutil,'disk_usage',usage):
            with patch.object(mounts,'read_mounts',return_value=selected):
                report=mounts.inspect(binding,initial=True)
                self.assertEqual(set(called),set(contract.MOUNTS.values()))
                self.assertEqual(set(report),set(contract.MOUNTS))
                with patch.object(mounts.shutil,'disk_usage',return_value=types.SimpleNamespace(total=2_000_000_000_000,free=1)):
                    with self.assertRaises(ValueError):mounts.inspect(binding)
                wrong=dict(binding);wrong['volumes']=dict(binding['volumes'],ledger=binding['volumes']['snapshots'],snapshots=binding['volumes']['ledger'])
                with self.assertRaises(ValueError):mounts.inspect(wrong)
            changed=mounts.parse(namespace().replace('101 10','301 10'))
            with patch.object(mounts,'read_mounts',side_effect=[selected,changed]):
                with self.assertRaises(ValueError):mounts.inspect(binding)


if __name__=='__main__':unittest.main()
