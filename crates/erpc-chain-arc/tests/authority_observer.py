#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Actual bounded local HTTP observer transport; no chain endpoint is contacted."""
import http.server
import json
import os
import pathlib
import sys
import threading
import unittest
from unittest.mock import patch
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'templates/authority'))
import arc_observe as observer
import arc_files as files


class Transport(unittest.TestCase):
    def setUp(self):
        self.reply=b'{"jsonrpc":"2.0","id":1,"result":false}'
        self.code=200;self.requests=[];fixture=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']))
                fixture.requests.append(json.loads(raw))
                self.send_response(fixture.code)
                if fixture.code==302:self.send_header('Location','http://127.0.0.1:1/redirect-target')
                self.end_headers()
                try:self.wfile.write(fixture.reply)
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join()

    def test_exact_read_only_request_ignores_inherited_proxy_configuration(self):
        with patch.dict(os.environ,{'http_proxy':'http://127.0.0.1:1','HTTP_PROXY':'http://127.0.0.1:1','no_proxy':''}):
            self.assertEqual(observer.rpc(self.url,'eth_syncing',[])['result'],False)
        self.assertEqual(self.requests,[{'id':1,'jsonrpc':'2.0','method':'eth_syncing','params':[]}])
        with self.assertRaises(files.Refused):observer.rpc(self.url,'eth_sendRawTransaction',[])
        self.assertEqual(len(self.requests),1)

    def test_actual_redirect_and_non_success_never_follow_or_return_data(self):
        for code in (302,404,500):
            self.code=code
            with self.subTest(code=code),self.assertRaises(Exception):observer.rpc(self.url,'eth_syncing',[])
        self.assertEqual(len(self.requests),3)

    def test_duplicate_wrong_id_unbounded_or_error_payloads_are_refused(self):
        for raw in (b'{"jsonrpc":"2.0","id":true,"result":false}',
                    b'{"jsonrpc":"2.0","id":2,"result":false}',
                    b'{"jsonrpc":"2.0","id":1,"result":false,"result":true}',
                    b'{"jsonrpc":"2.0","id":1,"error":{"message":"inert"}}',
                    b' '*65537):
            self.reply=raw
            with self.subTest(size=len(raw)),self.assertRaises(Exception):observer.rpc(self.url,'eth_syncing',[])


if __name__=='__main__':unittest.main()
