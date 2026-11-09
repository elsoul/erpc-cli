# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Exercise archive boundaries and interrupted publication using tiny fixtures."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).parents[1]/'templates/node/bootstrap.py'
spec=importlib.util.spec_from_file_location('bsc_bootstrap',SOURCE)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)


def archive(entries):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w') as tar:
        for name,kind,body in entries:
            item=tarfile.TarInfo(name);item.type=kind;item.size=len(body) if kind==tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):item.linkname='/outside'
            tar.addfile(item,io.BytesIO(body) if item.isfile() else None)
    stream.seek(0);return stream


class Bootstrap(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(folder.name)
        patch.object(b.shutil,'disk_usage',return_value=type('Usage',(),{'free':100_000_000_000_000})()).start()
        patch.object(b.os,'chown').start()
        self.snapshot={'id':'testnet-fixture','manifest_sha256':'f'*64,'files':[{'filename':'testnet-fixture.tar.lz4','URL':'https://github.com/fixture','md5':'a'*32,'estimated_bytes':1000}]}
        self.raw=archive([('server/data-seed/geth/chaindata/0001.sst',tarfile.REGTYPE,b'database fixture')]).getvalue()
        def download(*args):
            p=self.root/'cached.tar';p.write_bytes(self.raw);return p
        patch.object(b,'download',side_effect=download).start()
        def extract(path,stage,ceiling):
            with path.open('rb') as stream:b.extract_stream(stream,stage,ceiling)
        patch.object(b,'extract',side_effect=extract).start()

    def bootstrap(self):b.bootstrap(self.root,'owned',self.snapshot,995,995,100000)

    def test_publishes_only_database_entries_and_repeat_preserves_running_data(self):
        self.bootstrap();path=self.root/'data/geth/chaindata/0001.sst'
        self.assertEqual(path.read_bytes(),b'database fixture')
        path.write_text('advanced current database')
        self.bootstrap();self.assertEqual(path.read_text(),'advanced current database')
        self.assertEqual(json.loads((self.root/'bootstrap.json').read_text())['phase'],'complete')

    def test_traversal_absolute_links_devices_keys_and_duplicate_files_fail_before_publish(self):
        entries=[('../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('prefix/geth/keystore/key',tarfile.REGTYPE),('prefix/geth/chaindata/link',tarfile.SYMTYPE),('prefix/geth/chaindata/hard',tarfile.LNKTYPE),('prefix/geth/chaindata/device',tarfile.CHRTYPE)]
        for name,kind in entries:
            with self.subTest(name=name):
                self.raw=archive([(name,kind,b'bad')]).getvalue()
                with self.assertRaises(b.Refused):self.bootstrap()
                self.assertFalse((self.root/'data/geth').exists())
        self.raw=archive([('geth/chaindata/a',tarfile.REGTYPE,b'one'),('geth/chaindata/a',tarfile.REGTYPE,b'two')]).getvalue()
        with self.assertRaises(FileExistsError):self.bootstrap()
        self.assertFalse((self.root/'data/geth').exists())

    def test_interrupted_extraction_restarts_only_staging_and_reuses_owned_intent(self):
        original=b.extract
        with patch.object(b,'extract',side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):self.bootstrap()
        self.assertFalse((self.root/'data/geth').exists())
        (self.root/'snapshot-stage/stale').write_text('uncommitted')
        self.bootstrap();self.assertFalse((self.root/'snapshot-stage/stale').exists())
        changed=copy.deepcopy(self.snapshot);changed['manifest_sha256']='e'*64
        with self.assertRaises(b.Refused):b.bootstrap(self.root,'owned',changed,995,995,100000)
        self.assertTrue((self.root/'data/geth/chaindata/0001.sst').exists())

    def test_crash_after_atomic_rename_resumes_without_reextracting_or_overwriting(self):
        real=b.durable_json
        def failure(path,value):
            if value['phase']=='complete':raise RuntimeError('crash after publish')
            real(path,value)
        with patch.object(b,'durable_json',side_effect=failure):
            with self.assertRaises(RuntimeError):self.bootstrap()
        self.assertTrue((self.root/'data/geth/chaindata/0001.sst').exists())
        with patch.object(b,'extract',side_effect=AssertionError('must not re-extract')):self.bootstrap()

    def test_foreign_data_symlink_and_low_space_do_not_get_adopted(self):
        (self.root/'data/geth/chaindata').mkdir(parents=True)
        with self.assertRaises(b.Refused):self.bootstrap()
        self.assertFalse((self.root/'bootstrap.json').exists())
        (self.root/'data/geth/chaindata').rmdir();(self.root/'data/geth').rmdir()
        (self.root/'data/geth').symlink_to(self.root/'other')
        with self.assertRaises(b.Refused):self.bootstrap()
        (self.root/'data/geth').unlink()
        with patch.object(b.shutil,'disk_usage',return_value=type('Usage',(),{'free':1})()):
            with self.assertRaises(b.Refused):self.bootstrap()
        self.assertFalse((self.root/'data/geth').exists())

    def test_fixed_source_urls_refuse_credentials_other_schemes_and_redirect_hosts(self):
        for value in ('http:'+'//github.com/data','https:'+'//github.com.evil.test/data','https://user:password@github.com/data','https://127.0.0.1/data','https://github.com:444/data','https://github.com/data#fragment'):
            with self.assertRaises(b.Refused):b.destination(value)
        self.assertEqual(b.destination('https://github.com/data'),'https://github.com/data')


class Download(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup);self.addCleanup(patch.stopall)
        self.root=Path(folder.name);self.path=self.root/'download';self.body=b'fixture-transfer'
        self.hash=hashlib.sha256(self.body).hexdigest()
        patch.object(b.shutil,'disk_usage',return_value=type('Usage',(),{'free':1_000_000_000_000})()).start()

    def response(self,body,status=200,headers=None):
        stream=io.BytesIO(body);stream.status=status;stream.headers=headers or {'Content-Length':str(len(body))};return stream

    def download(self,response):
        from unittest.mock import Mock
        opener=Mock();opener.open.return_value=response
        with patch.object(b.urllib.request,'build_opener',return_value=opener):
            result=b.download('https://github.com/fixture',self.path,self.hash,'sha256',len(self.body))
        return result,opener

    def test_hash_and_exact_length_gate_atomic_publication(self):
        self.download(self.response(self.body))
        self.assertEqual(self.path.read_bytes(),self.body)
        self.path.unlink()
        with self.assertRaises(b.Refused):self.download(self.response(b'changed-transfer'))
        self.assertFalse(self.path.exists())

    def test_range_resume_checks_offset_and_full_digest(self):
        partial=self.path.with_suffix('.partial');partial.write_bytes(self.body[:4])
        result,opener=self.download(self.response(self.body[4:],206,{'Content-Range':'bytes 4-'+str(len(self.body)-1)+'/'+str(len(self.body))}))
        self.assertEqual(result.read_bytes(),self.body)
        self.assertEqual(opener.open.call_args.args[0].headers['Range'],'bytes=4-')
        self.path.unlink();partial.write_bytes(self.body[:4])
        with self.assertRaises(b.Refused):self.download(self.response(self.body[4:],206,{'Content-Range':'bytes 0-14/15'}))
        self.assertEqual(partial.read_bytes(),self.body[:4])

    def test_ignored_range_restarts_transfer_but_complete_partial_does_not_refetch(self):
        partial=self.path.with_suffix('.partial');partial.write_bytes(self.body[:4])
        self.download(self.response(self.body));self.assertEqual(self.path.read_bytes(),self.body)
        self.path.rename(partial)
        _,opener=self.download(self.response(b'not-used'))
        opener.open.assert_not_called()
        self.assertEqual(self.path.read_bytes(),self.body)

    def test_size_capacity_and_symlink_refusals_leave_target_unpublished(self):
        for response in [self.response(self.body,headers={'Content-Length':str(len(self.body)+1)}),self.response(self.body,headers={'Content-Length':'1'}),self.response(self.body,206,{'Content-Range':'invalid'})]:
            with self.assertRaises(b.Refused):self.download(response)
            self.assertFalse(self.path.exists())
        with patch.object(b.shutil,'disk_usage',return_value=type('Usage',(),{'free':1})()):
            with self.assertRaises(b.Refused):self.download(self.response(self.body))
        self.path.symlink_to(self.root/'outside')
        with self.assertRaises(b.Refused):self.download(self.response(self.body))


if __name__=='__main__':unittest.main()
