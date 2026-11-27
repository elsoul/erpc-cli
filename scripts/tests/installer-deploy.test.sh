#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0
#
# Pins .github/workflows/installer-worker.yml by SHA-256, with CRLF read as
# LF so a Windows checkout hashes the same.
#
# That workflow's `deploy` job holds the Cloudflare token. It is meant to run
# no package install script, and to upload a bundle built by a job that holds
# no secrets. Earlier versions of this test tried to check that from the
# workflow's text and kept missing valid spellings: npm aliases, options
# before the subcommand, line continuations, `toJson(secrets)`, quoted or
# escaped YAML keys, and workflow-wide settings placed after the jobs. So
# this test does not judge the file at all. Any edit to it fails here until
# PINNED below is updated in the same pull request, and whoever updates it
# confirms the checklist printed on failure.
#
# What it does not cover: the scripts and files the workflow uses
# (installer/scripts/select-release.mjs, installer/src, package.json and its
# lockfile, wrangler.toml), other workflow files, and what a pinned action
# does when it runs.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
from hashlib import sha256
from pathlib import Path

PATH = ".github/workflows/installer-worker.yml"
PINNED = "5f43b7efbc1ab11202937b9f95421ca960b9058caf7c4cdb4a752cee2f534ad8"

CHECKLIST = """\
Before updating PINNED, read the whole diff of this workflow and confirm:
  - `deploy` installs only with `npm ci --ignore-scripts`, in any spelling,
    and runs `wrangler deploy --no-bundle` on the downloaded artifact;
  - no job other than `deploy` uses an environment or reads secrets, in any
    YAML or expression form;
  - nothing workflow-wide (env, defaults, run-name, a key placed after
    `jobs:`) changes how `deploy` runs, e.g. BASH_ENV or NODE_OPTIONS;
  - `bundle` still uploads index.js and index.js.map, and no other job
    uploads an artifact with that name."""


def digest(text):
    return sha256(text.replace("\r\n", "\n").encode()).hexdigest()


text = Path(PATH).read_text()
found = digest(text)
if found != PINNED:
    raise SystemExit(f"{PATH} has changed: its SHA-256 is {found}, pinned {PINNED}.\n{CHECKLIST}")

# The pin must react to edits the text checks of earlier versions missed,
# and must not react to line endings alone.
for label, edited in [
    ("a workflow-wide env after the jobs", text + "env:\n  BASH_ENV: x\n"),
    ("a quoted environment key", text.replace("    runs-on: ubuntu-latest\n", '    runs-on: ubuntu-latest\n    "environment": release\n', 1)),
    ("an npm alias", text.replace("npm ci --ignore-scripts", "npm clean-install")),
    ("one changed character", text.replace("retention-days: 7", "retention-days: 8")),
]:
    assert edited != text, f"sample did not change the workflow: {label}"
    assert digest(edited) != PINNED, f"pin accepted: {label}"
assert digest(text.replace("\n", "\r\n")) == PINNED, "CRLF line endings changed the digest"
print("installer deploy workflow: matches its pinned SHA-256")
PY
