#!/bin/bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# erpc's runner on a node: one run, one play.
#
#   node-run.sh <run dir> <sha256 of bundle.tar.gz> <play inside the bundle>
#
# Started by `systemd-run` as the login user, so it carries on if erpc's
# connection drops. It takes the node's run lock, checks the bundle against
# the digest erpc computed, prepares Ansible from hash-pinned wheels the first
# time (or when the pins change), runs the play against this node, and writes
# result.json, which erpc reads back. Everything it prints goes to the run's
# log, which erpc follows.
set -uo pipefail

run_dir="$1"
want="$2"
play="$3"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

result() {
  # $1 status, $2 exit code, $3 message (no quotes or backslashes in it)
  local finished
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sudo -n /usr/bin/python3 -I "$run_dir/run-files.py" result "$run_dir" \
    "$1" "$2" "$started" "$finished" "$play" "$3"
}

cd "$run_dir" || exit 1
umask 077

# One run at a time on a node. The lock is on /opt/erpc itself, opened for
# reading, so every user erpc logs in as (ubuntu, then solv) shares it
# without needing to write there.
exec 9</opt/erpc
if ! flock -n 9; then
  echo "erpc: another erpc run is in progress on this node"
  result failed 75 "another erpc run is in progress on this node"
  exit 75
fi

got="$(sha256sum bundle.tar.gz | cut -d' ' -f1)"
if [ "$got" != "$want" ]; then
  echo "erpc: the bundle does not match the digest erpc sent; nothing was run"
  result failed 1 "the bundle does not match its digest"
  exit 1
fi
# The CLI sealed and extracted this exact bundle before systemd opened its log.

# The venv is named after its pins, so a new set of pins gets a new venv and
# an existing one is never changed under a run. It is built by root and
# readable by every user, because the first run logs in as ubuntu and later
# ones as solv.
req_sha="$(sha256sum bundle/requirements.txt | cut -d' ' -f1)"
venv="/opt/erpc/venvs/${req_sha:0:16}"
if [ ! -x "$venv/bin/ansible-playbook" ] || [ "$(cat "$venv/.ready" 2>/dev/null)" != "$req_sha" ]; then
  echo "erpc: preparing Ansible on this node from pinned wheels"
  if ! /usr/bin/python3 -I -c 'import ensurepip, venv' 2>/dev/null; then
    echo "erpc: installing python3-venv"
    sudo -n env DEBIAN_FRONTEND=noninteractive apt-get update -qq \
      && sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv \
      || { result failed 1 "python3-venv could not be installed"; exit 1; }
  fi
  sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 /bin/sh -c 'umask 022 && rm -rf "$1" && mkdir -p /opt/erpc/venvs && /usr/bin/python3 -I -m venv "$1" \
      && "$1/bin/python" -I -m pip install --quiet --disable-pip-version-check --no-input \
           --require-hashes --only-binary=:all: -r "$2" \
      && echo "$3" > "$1/.ready"' sh "$venv" "$run_dir/bundle/requirements.txt" "$req_sha" \
    || { result failed 1 "Ansible could not be installed from the pinned wheels"; exit 1; }
fi

export ANSIBLE_PYTHON_INTERPRETER="$run_dir/python-isolated"
export ANSIBLE_CONFIG="$run_dir/bundle/ansible.cfg"
ANSIBLE_LOCAL_TEMP="$(mktemp -d /tmp/erpc-ansible.XXXXXXXXXX)" || { result failed 1 "Ansible temporary directory could not be created"; exit 1; }
export ANSIBLE_LOCAL_TEMP
trap 'rm -rf -- "$ANSIBLE_LOCAL_TEMP"' EXIT
export PYTHONUNBUFFERED=1
"$venv/bin/python" -I -m ansible.cli.playbook -i bundle/inventory.yml "bundle/$play"
code=$?
if [ "$code" -eq 0 ]; then
  result ok 0 ""
else
  result failed "$code" "ansible-playbook exited with $code"
fi
exit "$code"
