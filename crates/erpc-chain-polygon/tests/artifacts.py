# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""In-memory artifact fixtures; no package, client, key or network execution."""
import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('polygon_artifacts_fixture',ROOT/'templates/scripts/artifacts.py')
artifacts=importlib.util.module_from_spec(spec);spec.loader.exec_module(artifacts)


class Response(io.BytesIO):
    def __init__(self,data,headers):
        super().__init__(data);self.headers=headers


class Artifacts(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.data=b'public inert genesis fixture'
        self.pin={'url':'https://github.com/?generation=123','bytes':len(self.data),'sha256':hashlib.sha256(self.data).hexdigest()}
    def test_complete_authenticated_generation_publishes_once_without_retrieval_on_retry(self):
        target=self.root/'genesis.json'
        def opened(*args,**kwargs):return Response(self.data,{'x-goog-generation':'123','Content-Length':str(len(self.data))})
        artifacts.fetch(self.pin,target,opened)
        self.assertEqual(target.read_bytes(),self.data)
        with patch.object(artifacts.urllib.request,'urlopen',side_effect=AssertionError('must not download again')):
            artifacts.fetch(self.pin,target)
        self.assertFalse(list(self.root.glob('*.partial')))
    def test_wrong_generation_length_hash_and_interrupted_stream_never_publish(self):
        target=self.root/'genesis.json'
        for data,headers in [(self.data,{'x-goog-generation':'124','Content-Length':str(len(self.data))}),
            (self.data[:-1],{'x-goog-generation':'123','Content-Length':str(len(self.data))}),
            (b'x'*len(self.data),{'x-goog-generation':'123','Content-Length':str(len(self.data))})]:
            with self.assertRaises(ValueError):artifacts.fetch(self.pin,target,lambda *a,**k:Response(data,headers))
            self.assertFalse(target.exists());self.assertFalse(list(self.root.glob('*.partial')))
        def denied(*args,**kwargs):raise OSError('inert interrupted retrieval')
        with self.assertRaises(OSError):artifacts.fetch(self.pin,target,denied)
        self.assertFalse(target.exists())
    def test_sigstore_refuses_failed_verification_without_an_ignore_policy_or_environment_override(self):
        calls=[]
        def run(args,**kwargs):
            calls.append((args,kwargs));return subprocess.CompletedProcess(args,1)
        original=tempfile.TemporaryDirectory
        with patch.object(artifacts.tempfile,'TemporaryDirectory',side_effect=lambda **kwargs:original(dir=self.root)):
            with self.assertRaises(ValueError):artifacts.signature(Path('cosign'),Path('package'),Path('signature'),Path('certificate'),'reviewed-workflow-identity','e'*40,run)
        args,kwargs=calls[0]
        self.assertIn('--certificate-identity',args)
        self.assertIn('--certificate-github-workflow-sha',args)
        self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG'})
        self.assertFalse(any('ignore' in item or 'insecure' in item for item in args))
    def test_native_version_metadata_matches_source_defined_formats(self):
        native=artifacts.native_version
        def check(*args,**kwargs):
            return native(*args,**kwargs,client_config='keyring-backend = \"memory\"\n',temporary=lambda **_:tempfile.TemporaryDirectory(dir=self.root))
        release={'tag':'v2.10.3','commit':'e'*40}
        def response(text):
            def checked(args,**kwargs):
                self.assertEqual(set(kwargs['env']),{'PATH','HOME','LANG'})
                self.assertTrue(Path(kwargs['env']['HOME']).is_dir())
                if args[0]=='heimdalld':
                    home=Path(args[args.index('--home')+1])
                    self.assertIn('memory',(home/'config/client.toml').read_text())
                return subprocess.CompletedProcess(args,0,text.encode())
            return checked
        check(Path('bor'),'bor',release,'x86_64',response('Version: 2.10.3\nGitCommit: '+'e'*40))
        check(Path('bor'),'bor',release,'aarch64',response('Version: 2.10.3\nGitCommit: '))
        for arch,text in [('x86_64','Version: 2.10.3\nGitCommit: '),('aarch64','Version: 2.10.2\nGitCommit: '),('aarch64','Version: 2.10.3\nGitCommit: '+'f'*40)]:
            with self.assertRaises(ValueError):check(Path('bor'),'bor',release,arch,response(text))
        check(Path('heimdalld'),'heimdall',{'tag':'v0.12.2','commit':'f'*40},'aarch64',response('{"version":"0.12.2","commit":"'+'f'*40+'"}'))
    def test_plaintext_and_cross_host_artifact_redirects_are_rejected(self):
        for url in ('http://127.0.0.1','https://github.com@127.0.0.1','https://github.com:8443','https://github.com'+'.untrusted.invalid'):
            with self.assertRaises(ValueError):artifacts.source(url)
        self.assertEqual(artifacts.source('https://github.com'),'https://github.com')

    def test_extraction_failure_and_post_publication_retry_do_not_run_maintainer_scripts(self):
        package=self.root/'fixture.deb';package.write_bytes(b'inert authenticated package')
        directory=self.root/'release'
        def missing(args,**kwargs):
            self.assertEqual(args[:2],['dpkg-deb','--extract'])
            return subprocess.CompletedProcess(args,0)
        with self.assertRaises(ValueError):artifacts.extract(package,directory,'bor',missing)
        self.assertFalse(directory.exists());self.assertFalse((self.root/'release.pending').exists())
        def extracted(args,**kwargs):
            self.assertEqual(args[:2],['dpkg-deb','--extract'])
            binary=Path(args[-1])/'usr/bin/bor';binary.parent.mkdir(parents=True);binary.write_bytes(b'inert binary')
            return subprocess.CompletedProcess(args,0)
        installed=artifacts.extract(package,directory,'bor',extracted)
        self.assertEqual(installed.read_bytes(),b'inert binary')
        def forbidden(*args,**kwargs):raise AssertionError('retry must not run the extractor')
        self.assertEqual(artifacts.extract(package,directory,'bor',forbidden),installed)
        installed.write_bytes(b'changed binary')
        with self.assertRaises(ValueError):artifacts.extract(package,directory,'bor',forbidden)


if __name__=='__main__':unittest.main()
