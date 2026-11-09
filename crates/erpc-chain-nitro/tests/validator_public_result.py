#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Exact source/run/bundle/request binding for fresh carried public probes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/validator/node'))
sys.path.insert(0,str(ROOT.parent/'erpc-chain-rollup/templates/scripts'))
import installer
import publication
import storage


class PublicResult(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(tmp.name).resolve()
        patch.object(storage,'ROOT_UID',os.getuid()).start();patch.object(storage,'TRUST_ANCHOR',self.root).start()
        self.runs=self.root/'runs';patch.object(installer,'RUNS',self.runs).start()
        self.run=self.runs/'r-inert-public-probe';self.source=self.run/'bundle/validator/node';self.source.mkdir(parents=True)
        for name in ('entry.py','control.py','upstreams.py'):(self.source/name).write_text('# inert checked profile\n')
        self.bundle=b'inert sealed original bundle';(self.run/'bundle.tar.gz').write_bytes(self.bundle)
        self.request={'action':'preflight'};self.result={'data_uuid':'00000000-0000-0000-0000-000000000001','free_bytes':6000000000000}

    def test_actual_public_dispatch_does_not_need_contract_or_interpret_task_logs(self):
        import control
        with patch.object(control,'dispatch',return_value=self.result) as dispatch:
            acknowledgement=installer.play(['play-control'],self.request,self.source)
        dispatch.assert_called_once_with(self.request)
        self.assertEqual(acknowledgement,{'public_result_written':True,'run':self.run.name})
        record=json.loads((self.run/'validator-public-result.json').read_bytes())
        self.assertEqual(set(record),{'schema','run','bundle_sha256','helpers_sha256','request_sha256','result'})
        self.assertEqual(record['bundle_sha256'],hashlib.sha256(self.bundle).hexdigest())
        self.assertEqual(record['helpers_sha256'],publication.profile(self.source)[0])
        self.assertEqual(record['request_sha256'],hashlib.sha256(storage.encode(self.request)).hexdigest())
        self.assertEqual(record['result'],self.result)

    def test_unsealed_location_or_linked_output_is_not_adopted(self):
        other=self.root/'outside/validator/node';other.mkdir(parents=True)
        for path in self.source.iterdir():shutil.copy(path,other/path.name)
        with self.assertRaisesRegex(ValueError,'sealed'):installer.public_result(other,self.request,self.result)
        outside=self.root/'retain';outside.write_text('inert unrelated file')
        (self.run/'validator-public-result.json').symlink_to(outside)
        with self.assertRaises((ValueError,OSError)):installer.public_result(self.source,self.request,self.result)
        self.assertEqual(outside.read_text(),'inert unrelated file')

    def test_private_channel_or_oversized_result_cannot_publish(self):
        import control
        with patch.object(control,'dispatch') as dispatch:
            with self.assertRaises(ValueError):installer.play(['play-control'],{'action':'import-wallet'},self.source)
            dispatch.assert_not_called()
        with self.assertRaises(ValueError):installer.public_result(self.source,self.request,{'inert':'x'*65536})
        self.assertFalse((self.run/'validator-public-result.json').exists())


if __name__=='__main__':unittest.main()
