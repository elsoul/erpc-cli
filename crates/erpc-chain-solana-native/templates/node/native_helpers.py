# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
"""Publish a complete protected helper release under its content identity."""
import hashlib
import os
from pathlib import Path
import re
import secrets
from native_files import atomic, read, require, root_directory, sync_directory, sync_file

SOURCE = Path(__file__).absolute().parent
RELEASES = Path('/usr/local/lib/erpc/solana-native/releases')
BASE_FILES = ('catalog.json', 'native_accounts.py', 'native_build.py', 'native_build_jobs.py',
         'native_contract.py', 'native_custody.py', 'native_entrypoint.py', 'native_files.py',
         'native_helpers.py', 'native_host.py', 'native_mounts.py', 'native_process.py',
         'native_publish.py', 'native_runtime_control.py', 'native_runtime_observer.py',
         'native_runtime_process.py', 'native_runtime_unit.py', 'native_state.py',
         'native_toolchain.py', 'native_trust.py', 'native_tuning.py')
DEPLOY_FILES = BASE_FILES + ('native_deployment.py',)
FIREWALL_FILES = DEPLOY_FILES + ('native_firewall.py',)
GATEWAY_FILES = FIREWALL_FILES + ('native_gateway.py', 'native_gateway_account.py', 'native_gateway_observer.py')
VALIDATOR_FILES = GATEWAY_FILES + ('native_validator.py',)
PROOF_FILES = VALIDATOR_FILES + ('native_proof.py',)
ACTIVATION_FILES = PROOF_FILES + ('native_activation.py',)
OPENING_FILES = ACTIVATION_FILES + ('native_source_floor.py',)
COPY_FILES = OPENING_FILES + ('native_migration_copy.py',)
FENCE_FILES = COPY_FILES + ('native_migration_fence.py',)
PRIVILEGE_FILES = FENCE_FILES + ('native_migration_privileges.py',)
RETIRE_FILES = PRIVILEGE_FILES + ('native_migration_inspect.py','native_migration_retire.py')
TRANSFER_FILES = RETIRE_FILES + ('native_migration_transfer.py',)
PROMOTE_FILES = TRANSFER_FILES + ('native_migration_promote.py',)
SETTINGS_FILES = PROMOTE_FILES + ('native_migration_settings.py',)
KEY_FILES = SETTINGS_FILES + ('native_migration_key.py',)
CUSTODY_FILES = KEY_FILES + ('native_migration_custody.py',)
FILES = CUSTODY_FILES + ('native_migration_bls.py','migration-sources.json','native_platform.py','native_migration_guard.py','native_migration_runs.py','native_migration_cutover.py','native_migration_status.py')
PROFILES = (BASE_FILES, DEPLOY_FILES, FIREWALL_FILES, GATEWAY_FILES, VALIDATOR_FILES, PROOF_FILES, ACTIVATION_FILES, OPENING_FILES, COPY_FILES, FENCE_FILES, PRIVILEGE_FILES, RETIRE_FILES, TRANSFER_FILES, PROMOTE_FILES, SETTINGS_FILES, KEY_FILES, CUSTODY_FILES, FILES)


def contents(directory):
    root_directory(directory)
    names = set(path.name for path in directory.iterdir())
    require(any(names == set(profile) for profile in PROFILES), 'native helper profile is incomplete or contains unknown files')
    return {name: read(directory / name, 1048576) for name in names}


def revision(values):
    require(any(set(values) == set(profile) for profile in PROFILES), 'native helper content set differs')
    digest = hashlib.sha256()
    for name in sorted(values):
        digest.update(name.encode() + b'\0' + hashlib.sha256(values[name]).digest())
    return digest.hexdigest()


def verify(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value), 'invalid native helper revision')
    directory = RELEASES / value
    require(revision(contents(directory)) == value, 'native helper content identity changed')
    return directory


def publish():
    values = contents(SOURCE); value = revision(values)
    require(set(values) == set(FILES), 'publication requires the complete current native helper profile')
    root_directory(RELEASES, create=True)
    # No symlink selector or uncontrolled files are needed in this namespace.
    for path in RELEASES.iterdir():
        require(re.fullmatch(r'(?:[a-f0-9]{64}|\.pending-[a-f0-9]{32})', path.name),
                'native helper namespace contains an unknown entry')
        root_directory(path)
    final = RELEASES / value
    if not final.exists():
        stage = RELEASES / ('.pending-' + secrets.token_hex(16))
        stage.mkdir(mode=0o700)
        for name, raw in values.items(): atomic(stage / name, raw, 0o444)
        require(contents(stage) == values, 'native helper publication readback differs')
        os.chmod(stage, 0o755); sync_directory(stage)
        os.rename(stage, final); sync_directory(RELEASES)
    verify(value)
    # Retry must re-establish the durability of a visible completed rename.
    for name in FILES: sync_file(final / name)
    sync_directory(final); sync_directory(RELEASES)
    return value
