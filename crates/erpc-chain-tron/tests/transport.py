# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Fixed HTTP destinations and curl configuration isolation without chain traffic."""
import email.message
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.response
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'templates/jinja'))
import observe


class Transport(unittest.TestCase):
    def test_real_urllib_handlers_reject_every_redirect_and_ambient_proxy(self):
        original=observe.urllib.request.build_opener
        for local in (False,True):
            for status in (200,301,302,303,307,308,500):
                seen=[]
                def response(request):
                    seen.append(request.full_url);self.assertFalse(request.has_proxy())
                    headers=email.message.Message()
                    if status!=200:headers['Location']='http://127.0.0.1:8090/redirected-fixture'
                    result=urllib.response.addinfourl(io.BytesIO(b'{"fixture":true}'),headers,request.full_url,status)
                    result.msg='OK' if status==200 else 'error';return result
                class HTTP(observe.urllib.request.HTTPHandler):
                    def http_open(self,request):return response(request)
                class HTTPS(observe.urllib.request.HTTPSHandler):
                    def https_open(self,request):return response(request)
                def build(*handlers):return original(*handlers,HTTP(),HTTPS())
                with patch.object(observe.urllib.request,'build_opener',side_effect=build),patch.dict(os.environ,{'http_proxy':'http://127.0.0.1:1','https_proxy':'http://127.0.0.1:1'}):
                    if status==200:self.assertEqual(observe.request('nile','wallet/getnowblock',local=local),{'fixture':True})
                    else:
                        with self.assertRaises(ValueError):observe.request('nile','wallet/getnowblock',local=local)
                wanted='http://127.0.0.1:8090' if local else observe.ENDPOINTS['nile']
                self.assertEqual(seen,[wanted+'/wallet/getnowblock'])
    def test_json_rpc_uses_the_same_closed_destination_transport(self):
        request=[]
        def opened(value):
            request.append(value)
            return io.BytesIO(json.dumps({'jsonrpc':'2.0','id':1,'result':'0xcccccccc'}).encode())
        with patch.object(observe,'open_fixed',side_effect=opened):self.assertTrue(observe.json_rpc({'genesis':'c'*64}))
        self.assertEqual(request[0].full_url,'http://127.0.0.1:8545/jsonrpc')
        self.assertEqual(json.loads(request[0].data)['method'],'eth_chainId')
    @unittest.skipUnless(Path('/usr/bin/curl').is_file(),'actual inert curl configuration test needs the distribution utility')
    def test_actual_curl_disable_flag_ignores_a_poisoned_home_configuration(self):
        with tempfile.TemporaryDirectory() as home:
            (Path(home)/'.curlrc').write_text('erpc-inert-unsupported-option\n')
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':home,'CURL_HOME':home,'LANG':'C'}
            negative=subprocess.run(['/usr/bin/curl','--version'],capture_output=True,text=True,env=env,check=False)
            self.assertIn('erpc-inert-unsupported-option',negative.stderr)
            positive=subprocess.run(['/usr/bin/curl','--disable','--version'],capture_output=True,text=True,env=env,check=True)
            self.assertNotIn('erpc-inert-unsupported-option',positive.stderr)
            self.assertTrue(positive.stdout.startswith('curl '))

if __name__=='__main__':unittest.main()
