#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual original-data records, rename/fsync faults and admission; no native DB."""
import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'templates/node'))
import native_source_floor as floor
import native_state as lifecycle
import native_files as files
import native_deployment as deploy
from mounts import owner


def qualified(version='4.3.2', commit='c'*40):
    return {'version':version,'commit':commit,'cargo_lock_sha256':'d'*64,
            'rust':'1.97.1','rust_manifest_sha256':'e'*64}


def prepare_fixture(state, contract, root, node):
    """Real data directories and records; only isolated-account UID metadata is modeled."""
    paths={kind:root/('data-'+kind) for kind in ('accounts','ledger','snapshots')}
    for path in paths.values(): (path/'data').mkdir(parents=True,mode=0o700)
    patch.object(floor.units,'MOUNTS',paths).start()
    original=Path.lstat
    def metadata(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        if path in [mount/'data' for mount in paths.values()]:
            fields=list(value);fields[4]=node['uid'];fields[5]=node['gid'];return os.stat_result(fields)
        return value
    patch.object(Path,'lstat',metadata).start()
    patch.object(floor,'sync_file',lambda p:files.sync_file(p,os.getuid())).start()
    state.put('data.json',{'contract':contract,'uid':node['uid'],'gid':node['gid']})
    floor.initialize(state,contract)
    return paths


class Floor(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(temporary.name);directory=self.root/'state';directory.mkdir()
        self.contract=owner();self.state=lifecycle.State(directory)
        patch.object(lifecycle,'read',lambda p,n:files.read(p,n,os.getuid())).start()
        patch.object(floor,'sync_file',lambda p:files.sync_file(p,os.getuid())).start()
        self.state.reserve(self.contract)
        self.node={'uid':os.getuid(),'gid':os.getgid()}
        self.state.put('accounts.json',{'contract':self.contract,'accounts':{'node':self.node},'opening_protocol':1})
        self.state.put('data.json',{'contract':self.contract,**self.node})
        self.mounts={kind:self.root/kind for kind in ('accounts','ledger','snapshots')}
        for path in self.mounts.values(): (path/'data').mkdir(parents=True,mode=0o700)
        patch.object(floor.units,'MOUNTS',self.mounts).start()

    def test_acquisition_does_not_raise_the_original_data_opening_floor(self):
        self.assertIsNone(floor.check(self.state,self.contract,qualified()))
        floor.initialize(self.state,self.contract)
        floor.check(self.state,self.contract,qualified('4.4.0'))
        self.assertIsNone(floor.highest(floor.records(self.state,self.contract)))
        floor.claim(self.state,self.contract,qualified())
        self.assertEqual(floor.highest(floor.records(self.state,self.contract)),qualified())
        floor.check(self.state,self.contract,qualified('4.5.0'))
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],qualified())

    def test_boot_guard_cannot_race_a_controller_floor_write_or_lower_its_result(self):
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        real=self.state.put;attempts=[]
        def concurrent(name,value):
            if name==floor.PENDING:
                # A separate open file description models the boot guard while
                # controller publication still holds the actual directory lock.
                with self.assertRaises(BlockingIOError):floor.claim(self.state,self.contract,qualified())
                with self.assertRaises(BlockingIOError):floor.initialize(self.state,self.contract)
                attempts.append(name)
            return real(name,value)
        higher=qualified('4.4.0','f'*40)
        with patch.object(self.state,'put',side_effect=concurrent):floor.claim(self.state,self.contract,higher)
        self.assertEqual(attempts,[floor.PENDING])
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],higher)
        with self.assertRaisesRegex(ValueError,'below'):floor.claim(self.state,self.contract,qualified())

    def test_semver_prerelease_order_and_same_version_source_compiler_substitution(self):
        values=['4.4.0-alpha','4.4.0-alpha.1','4.4.0-alpha.beta','4.4.0-beta','4.4.0-beta.2','4.4.0-beta.10','4.4.0-rc.1','4.4.0','4.4.1']
        self.assertEqual(sorted(reversed(values),key=floor.version),values)
        for invalid in ('4.3','04.3.2','4.3.2-beta.01','4.3.2+unknown','4.3.2\n',True):
            with self.assertRaises(ValueError):floor.version(invalid)
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        for key,value in [('version','4.3.1'),('commit','f'*40),('cargo_lock_sha256','f'*64),('rust','1.98.1'),('rust_manifest_sha256','f'*64)]:
            with self.subTest(key=key),self.assertRaises(ValueError):floor.check(self.state,self.contract,dict(qualified(),**{key:value}))

    def test_real_directory_fsync_failure_retains_the_higher_pending_authority(self):
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        higher=qualified('4.4.0','f'*40);real=os.fsync
        def fault(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode) and (self.state.directory/floor.PENDING).exists():
                if self.state.get(floor.PENDING)['highest']==higher:raise OSError('inert directory persistence fault')
            return real(fd)
        with patch.object(os,'fsync',side_effect=fault):
            for _ in range(2):
                with self.assertRaises(OSError):floor.claim(self.state,self.contract,higher)
        self.assertEqual(self.state.get(floor.PENDING)['highest'],higher)
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],qualified())
        with self.assertRaisesRegex(ValueError,'below'):floor.check(self.state,self.contract,qualified())
        stops=[];self.state.stop(self.contract,lambda:stops.append('owned shutdown'))
        self.assertEqual(stops,['owned shutdown'])
        floor.claim(self.state,self.contract,higher)
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],higher)
        with self.assertRaisesRegex(ValueError,'below'):floor.claim(self.state,self.contract,qualified())

    def test_original_pending_can_recover_a_missing_completed_copy_but_not_missing_history(self):
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        self.state.remove(floor.COMPLETE)
        floor.initialize(self.state,self.contract)
        self.assertEqual(self.state.get(floor.COMPLETE),self.state.get(floor.PENDING))
        self.state.remove(floor.COMPLETE)
        floor.claim(self.state,self.contract,qualified())
        self.assertEqual(self.state.get(floor.COMPLETE),self.state.get(floor.PENDING))
        self.state.put('active.json',{'inert':'opened runtime marker'})
        self.state.remove(floor.COMPLETE);self.state.remove(floor.PENDING)
        with self.assertRaisesRegex(ValueError,'missing'):floor.check(self.state,self.contract,qualified())
        with self.assertRaisesRegex(ValueError,'used or unrecorded'):floor.initialize(self.state,self.contract)

    def test_data_replacement_and_old_account_protocol_cannot_adopt_original_records(self):
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        path=self.mounts['ledger']/'data';path.rename(self.mounts['ledger']/'retained');path.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'ownership'):floor.check(self.state,self.contract,qualified())
        path.rmdir();(self.mounts['ledger']/'retained').rename(path)
        previous=self.state.get('accounts.json');previous.pop('opening_protocol');self.state.put('accounts.json',previous)
        with self.assertRaisesRegex(ValueError,'history upgrade'):floor.check(self.state,self.contract,qualified())

    def test_prior_account_decoder_rejects_the_new_protocol_before_any_account_or_runtime_access(self):
        # The closed receipt check from native_accounts.verify at b12e25de.
        # Older startup and authorize-build use this before touching native data.
        namespace={'require':files.require}
        exec("def verify(state, contract):\n"
             "    state.owner(contract)\n"
             "    receipt = state.get('accounts.json')\n"
             "    require(set(receipt) == {'contract', 'accounts'} and receipt['contract'] == contract,\n"
             "            'service identity receipt belongs to another owner')\n", namespace)
        with self.assertRaisesRegex(ValueError,'another owner'):
            namespace['verify'](self.state,self.contract)

    def test_explicit_historical_minimum_is_not_inferred_from_current_pin(self):
        (self.mounts['ledger']/'data'/'retained-db').write_bytes(b'inert original database bytes')
        self.state.put('active.json',{'inert':'previous runtime'})
        with self.assertRaises(ValueError):floor.initialize(self.state,self.contract)
        historical={'version':'4.3.2','commit':'c'*40}
        floor.initialize(self.state,self.contract,historical)
        with self.assertRaises(ValueError):floor.claim(self.state,self.contract,qualified('4.3.1'))
        with self.assertRaises(ValueError):floor.claim(self.state,self.contract,qualified(commit='f'*40))
        floor.claim(self.state,self.contract,qualified())
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],qualified())
        self.assertEqual((self.mounts['ledger']/'data'/'retained-db').read_bytes(),b'inert original database bytes')

    def test_uuid_bound_data_survives_kernel_device_number_remapping(self):
        floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,qualified())
        before=self.state.get(floor.COMPLETE);real=Path.lstat
        def remapped(path,*args,**kwargs):
            value=real(path,*args,**kwargs)
            if path in [mount/'data' for mount in self.mounts.values()]:
                fields=list(value);fields[2]+=1000;return os.stat_result(fields)
            return value
        with patch.object(Path,'lstat',side_effect=remapped,autospec=True):
            floor.check(self.state,self.contract,qualified())
        self.assertEqual(self.state.get(floor.COMPLETE),before)

    def test_actual_build_admission_rejects_older_catalog_and_preserves_original_state(self):
        raw=(Path(__file__).resolve().parents[1]/'templates/node/catalog.json').read_bytes();old=json.loads(raw)
        network=self.contract['network'];source=old['networks'][network]
        baseline=floor.from_profile(source);floor.initialize(self.state,self.contract);floor.claim(self.state,self.contract,baseline)
        old_directory=self.root/('c'*64);old_directory.mkdir();(old_directory/'catalog.json').write_bytes(raw)
        new_directory=self.root/('d'*64);new_directory.mkdir()
        lower=copy.deepcopy(old);lower['networks'][network]['version']='4.3.1';lower['networks'][network]['commit']='f'*40
        (new_directory/'catalog.json').write_bytes(files.encoded(lower))
        self.state.put('active.json',{'receipt':{'helper_revision':'c'*64,'mode':'sync','identity':'5'*44}})
        request={'action':'authorize-build','contract':self.contract,'intent':'a'*32,'mode':'sync','identity':'5'*44,'operation':'update'}
        original=self.state.get('active.json')
        with patch.object(deploy.accounts,'verify',return_value={'node':self.node}), \
             patch.object(deploy.helpers,'publish',return_value='d'*64), \
             patch.object(deploy.helpers,'verify',side_effect=lambda value:self.root/value), \
             patch.object(deploy,'read',lambda p,n:files.read(p,n,os.getuid())):
            with self.assertRaisesRegex(ValueError,'below'):deploy.authorize(self.state,self.contract,request)
        self.assertFalse((self.state.directory/'pending.json').exists())
        self.assertEqual(self.state.get('active.json'),original)
        self.assertEqual(self.state.get(floor.COMPLETE)['highest'],baseline)


if __name__=='__main__':unittest.main()
