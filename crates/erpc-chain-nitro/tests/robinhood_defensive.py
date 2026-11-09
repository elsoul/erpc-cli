#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Assemble each sealed profile and run isolated inert authority/financial cases."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
for network in ('mainnet','testnet'):
    with tempfile.TemporaryDirectory() as temporary:
        node=Path(temporary)/'node';node.mkdir()
        for source in (ROOT/'templates/validator/node').glob('*.py'):shutil.copyfile(source,node/source.name)
        for source in (ROOT/'templates/robinhood-validator/node').glob('*.py'):shutil.copyfile(source,node/source.name)
        shutil.copyfile(ROOT/'templates/robinhood-validator/scopes'/ (network+'.py'),node/'scope.py')
        shutil.copyfile(ROOT.parent/'erpc-chain-rollup/templates/scripts/upstreams.py',node/'upstreams.py')
        for name in ('robinhood_defensive_cases.py','robinhood_runtime_cases.py'):
            subprocess.run([sys.executable,'-I','-B',str(ROOT/'tests'/name),str(node),network],check=True)
