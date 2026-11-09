# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Execute actual generated SSH reader code against inert sealed-run fixtures."""
import json
import contextlib
import io
from unittest.mock import patch
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
argv=shlex.split(sys.stdin.read())
assert argv[:5]==['sudo','-n','/usr/bin/python3','-I','-c'] and len(argv) in (7,8)
namespace={'__name__':'reader_fixture'}
exec(compile(argv[5],'<actual-ssh-reader>','exec'),namespace)
RUN=argv[6]
PROFILE=argv[7] if len(argv)==8 else 'arbitrum'
EXPECTED={
 'arbitrum':('validator/ansible/control.yml','validator-public-result.json','erpc-arbitrum-public-result-v1'),
 'robinhood-defensive':('validator/ansible/control.yml','validator-public-result.json','erpc-robinhood-defensive-result-v1'),
 'robinhood-admission':('robinhood-admission/control.yml','robinhood-admission-public-result.json','erpc-robinhood-admission-public-result-v1'),
}
assert namespace['PROFILES']==EXPECTED and PROFILE in EXPECTED
PLAY,FILENAME,SCHEMA=EXPECTED[PROFILE]
class Result(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.directory=self.root/'opt/erpc/runs'/RUN;self.directory.mkdir(parents=True)
        self.public={'schema':SCHEMA,'run':RUN,'bundle_sha256':'a'*64,'helpers_sha256':'b'*64,'request_sha256':'c'*64,'result':{'data_uuid':'00000000-0000-0000-0000-000000000001'}}
        self.write('sealed.json',{'bundle':'a'*64});self.write('result.json',{'status':'ok','exit_code':0,'play':PLAY});self.write(FILENAME,self.public)
    def write(self,name,value):
        path=self.directory/name;path.write_text(json.dumps(value));path.chmod(0o600)
    def read(self):return namespace['result'](RUN,self.root,os.getuid(),profile=PROFILE)
    def test_completed_original_result(self):self.assertEqual(self.read(),self.public)
    def test_missing_failed_or_foreign_run(self):
        for value in [{'status':'failed','exit_code':1,'play':PLAY},{'status':'ok','exit_code':False,'play':PLAY},{'status':'ok','exit_code':0,'play':'other.yml'}]:
            self.write('result.json',value)
            with self.assertRaises(ValueError):self.read()
        (self.directory/'result.json').unlink()
        with self.assertRaises(OSError):self.read()
    def test_result_links(self):
        path=self.directory/FILENAME;saved=self.directory/'saved';path.rename(saved);path.symlink_to(saved)
        with self.assertRaises(OSError):self.read()
        path.unlink();os.link(saved,path)
        with self.assertRaises(ValueError):self.read()
    def test_ancestor_links_and_writable_modes(self):
        runs=self.directory.parent;real=runs.with_name('actual-runs');runs.rename(real);runs.symlink_to(real,target_is_directory=True)
        with self.assertRaises(OSError):self.read()
        runs.unlink();real.rename(runs);runs.chmod(0o777)
        with self.assertRaises(ValueError):self.read()
    def test_wrong_owner_and_writable_files(self):
        with self.assertRaises(ValueError):namespace['result'](RUN,self.root,os.getuid()+1,profile=PROFILE)
        for name in ['sealed.json','result.json',FILENAME]:
            path=self.directory/name;path.chmod(0o666)
            with self.assertRaises(ValueError):self.read()
            path.chmod(0o600)
    def test_bounded_exact_envelope(self):
        for name,value in [('schema','other'),('run','r-other-fixture'),('bundle_sha256','d'*64),('result','not object'),('helpers_sha256','malformed')]:
            public=dict(self.public);public[name]=value;self.write(FILENAME,public)
            with self.assertRaises(ValueError):self.read()
        (self.directory/FILENAME).write_text(' '*262145)
        with self.assertRaises(ValueError):self.read()
    def test_main_uses_the_actual_generated_profile_argument(self):
        original=namespace['result'];calls=[]
        def selected(run,profile='arbitrum'):
            calls.append((run,profile));return original(run,self.root,os.getuid(),profile=profile)
        namespace['result']=selected
        output=io.StringIO()
        try:
            with patch.object(sys,'argv',['reader',*argv[6:]]),patch.object(os,'geteuid',return_value=0),contextlib.redirect_stdout(output):
                namespace['main']()
            self.assertEqual(json.loads(output.getvalue()),self.public)
            self.assertEqual(calls,[(RUN,PROFILE)])
        finally:namespace['result']=original
    def test_other_profile_cannot_read_this_completed_run(self):
        other=next(name for name in EXPECTED if name!=PROFILE)
        with self.assertRaises(ValueError):namespace['result'](RUN,self.root,os.getuid(),profile=other)
        with self.assertRaises(ValueError):namespace['result'](RUN,self.root,os.getuid(),profile='unknown')
unittest.main()
