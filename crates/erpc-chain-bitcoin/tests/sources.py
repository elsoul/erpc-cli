# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Durable DB-opening source floors with inert qualified native artifacts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import lifecycle
c=lifecycle.c


class Sources(unittest.TestCase):
    def setUp(self):
        self.fixture=lifecycle.HostTests('runTest');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.state=c.read_state()

    def candidate(self):
        pin=dict(self.fixture.pin,version='32.0',commit='d'*40,sha256='e'*64)
        c.CATALOG['32.0']={'commit':pin['commit'],'artifacts':{pin['platform']:pin['sha256']}}
        directory=c.release_dir(pin);(directory/'bin').mkdir(parents=True)
        for name in ('bitcoind','bitcoin-cli'):
            (directory/'bin'/name).write_text('inert qualified 32 '+name)
            (directory/'bin'/name).chmod(0o755)
        c.register_native(self.state,pin,hashlib.sha256((directory/'bin/bitcoind').read_bytes()).hexdigest(),
                          hashlib.sha256((directory/'bin/bitcoin-cli').read_bytes()).hexdigest())
        (directory/'verified.json').write_text(json.dumps(pin))
        return pin

    def published(self,pin):
        query=self.fixture.request('authorize',generation=c.generation(c.read_state()))
        query['pin']=pin
        c.locked(query);c.locked(dict(query,action='begin-install'))
        # Model the already-authenticated artifact publication; the actual
        # activation, original source records and fsync paths remain unchanged.
        c.UNIT_PATH.write_text(query['unit'])
        (c.OPT/'current').unlink();(c.OPT/'current').symlink_to(c.release_dir(pin))
        value=c.read_state();value.update(phase='installed',installed=pin);c.save(value)
        self.fixture.calls.clear()
        return query

    def test_source_floor_survives_stale_owner_metadata_and_refuses_same_version_substitution(self):
        pin=self.candidate();query=self.published(pin)
        c.locked(dict(query,action='activate'))
        self.assertEqual(c.source_floor(c.read_state()),pin)
        stale=c.read_state();stale['installed']=self.fixture.pin;c.save(stale)
        rejected=self.fixture.request('authorize',generation=c.generation(stale))
        self.fixture.calls.clear()
        with self.assertRaises(c.Refused):c.locked(rejected)
        self.assertEqual(self.fixture.calls,[])
        before=(c.ROOT/'native-releases.json').read_bytes()
        with self.assertRaises(c.Refused):c.register_native(stale,dict(pin,commit='f'*40),'a'*64,'b'*64)
        self.assertEqual((c.ROOT/'native-releases.json').read_bytes(),before)

    def test_pending_floor_is_authoritative_and_boot_requires_the_exact_reserved_source(self):
        pin=self.candidate();self.published(pin)
        value=c.read_state();value['intent']=None;c.save(value)
        with self.assertRaises(c.Refused):c.guard(value)
        c.original_write('source-floor.pending.json',{'scope':c.runtime_scope(value),'source':c.native_key(pin)})
        self.assertEqual(c.source_floor(value),pin)
        with self.assertRaises(c.Refused):c.check_source_floor(value,self.fixture.pin)

    def test_each_source_barrier_failure_prevents_start_and_retries_preserve_the_same_floor(self):
        pin=self.candidate();query=self.published(pin)
        original_sync=os.fsync
        for fault in range(1,9):
            with self.subTest(fault=fault):
                query['action']='authorize';query['generation']=c.generation(c.read_state())
                c.locked(query)
                self.fixture.calls.clear();self.fixture.service='inactive';count=0
                def failed(fd):
                    nonlocal count
                    count+=1
                    if count==fault:raise OSError('inert original source barrier')
                    return original_sync(fd)
                with patch.object(c.os,'fsync',side_effect=failed),self.assertRaises(OSError):
                    c.locked(dict(query,action='activate'))
                self.assertNotIn(['/usr/bin/systemctl','start',c.UNIT],self.fixture.calls)
                self.assertEqual(self.fixture.service,'inactive')
                self.assertTrue(c.stopped())
                with self.assertRaises(c.Refused):c.guard(c.read_state())
                self.assertEqual((c.ROOT/'data/chainstate-fixture').read_text(),'persistent-state')
        query['generation']=c.generation(c.read_state());c.locked(query)
        c.locked(dict(query,action='activate'))
        self.assertEqual(c.source_floor(c.read_state()),pin)
        self.assertEqual(self.fixture.service,'active')

    def test_missing_or_foreign_source_scope_does_not_adopt_current_images(self):
        (c.ROOT/'source-floor.json').unlink()
        with self.assertRaises(c.Refused):c.guard(self.state)
        value=copy.deepcopy(self.state);value['layout']['data']['uuid']='00000000-0000-0000-0000-000000000002'
        with self.assertRaises(c.Refused):c.native_releases(value)
        self.assertEqual(self.fixture.calls,[])


if __name__=='__main__':unittest.main()
