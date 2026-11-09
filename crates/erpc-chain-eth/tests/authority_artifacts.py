# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Official archive shapes with inert payloads, no signing keys or native execution."""
import hashlib
import io
import os
from pathlib import Path
import sys
import tarfile
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).parent))
import authority_runtime as fixtures


class Extraction(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.Runtime();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.names={'reth':'reth-fixture.tar.gz','lighthouse':'lighthouse-fixture.tar.gz'}

    def archive(self,client,extra=None):
        file=self.fixture.root/'opt'/self.names[client]
        with tarfile.open(file,'w:gz') as archive:
            item=tarfile.TarInfo(client);item.size=20;item.mode=0o777
            archive.addfile(item,io.BytesIO(b'inert public payload'))
            if client=='reth':
                directory=tarfile.TarInfo('LICENSES/');directory.type=tarfile.DIRTYPE;archive.addfile(directory)
                for name in ('README.md','LICENSES/MIT.txt'):
                    member=tarfile.TarInfo(name);member.size=4;archive.addfile(member,io.BytesIO(b'test'))
            if extra is not None:
                name,kind=extra;member=tarfile.TarInfo(name);member.type=kind;member.linkname=str(self.fixture.root/'outside')
                if kind==tarfile.REGTYPE:member.size=4;archive.addfile(member,io.BytesIO(b'extra'[:4]))
                else:archive.addfile(member)
        return hashlib.sha256(file.read_bytes()).hexdigest()

    def reserve(self,extra=None):
        f=self.fixture;source={key:f.target[key] for key in ('pair','rpc_bind','metrics_bind','checkpoint')}
        source.update(reth_commit='1'*40,lighthouse_commit='2'*40,reth_archive=self.archive('reth',extra),lighthouse_archive=self.archive('lighthouse'))
        f.request('reserve-deploy',intent=f.intent,target=source,operation='deploy');return source

    def extract(self):return self.fixture.request('extract',intent=self.fixture.intent,archives=self.names)

    def test_primary_release_shapes_preserve_public_execute_modes_under_private_umask(self):
        self.reserve();old=os.umask(0o077)
        try:self.extract();self.extract()
        finally:os.umask(old)
        stage=self.fixture.root/'opt'/(self.fixture.target['pair']+'.pending-'+self.fixture.intent)
        self.assertEqual(set(p.name for p in stage.iterdir()),{'reth','lighthouse'})
        self.assertEqual(stage.stat().st_mode&0o777,0o755)
        for client in self.names:
            self.assertEqual((stage/client).read_bytes(),b'inert public payload')
            self.assertEqual((stage/client).stat().st_mode&0o777,0o555)

    def test_links_devices_unknown_members_and_duplicates_never_get_native_execution_authority(self):
        for extra in [('reth',tarfile.SYMTYPE),('reth',tarfile.LNKTYPE),('reth',tarfile.REGTYPE),('../outside',tarfile.REGTYPE),('unexpected',tarfile.FIFOTYPE)]:
            with self.subTest(extra=extra):
                if self.fixture.state.exists('pending.json'):
                    self.fixture.request('recover',intent=self.fixture.intent);self.fixture.intent=hex(int(self.fixture.intent,16)+1)[2:].rjust(32,'0')
                outside=self.fixture.root/'outside';outside.write_bytes(b'original unrelated data')
                self.reserve(extra)
                with self.assertRaises(ValueError):self.extract()
                self.assertEqual(outside.read_bytes(),b'original unrelated data')
                self.assertFalse(self.fixture.active)

    def test_digest_change_and_canceled_intent_refuse_before_extraction(self):
        self.reserve();file=self.fixture.root/'opt'/self.names['reth'];file.write_bytes(b'changed unsigned bytes')
        with self.assertRaises(ValueError):self.extract()
        stage=self.fixture.root/'opt'/(self.fixture.target['pair']+'.pending-'+self.fixture.intent)
        self.assertEqual(list(stage.iterdir()),[])
        self.fixture.request('stop')
        with self.assertRaises(ValueError):self.extract()


if __name__=='__main__':unittest.main()
