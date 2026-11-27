#!/bin/sh
# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

set -eu
IFS= read -r missing < "${0%/*}/scenario"

flag() {
  case "${missing#decoy-}" in
    "$1") printf '%s' security-check-remote ;;
    *) printf '%s' security-check ;;
  esac
}

case "$*" in
  "--help") printf '%s\n' 'Usage: erpc [COMMAND]' ;;
  "ai --help") printf '      --%s  Run a security check\n' "$(flag help)" ;;
  "completions bash")
    printf '    erpc__subcmd__ai)\n      opts="--message --%s --help"\n      ;;\n' "$(flag bash)"
    if [ "$missing" = decoy-bash ]; then
      printf '%s\n' '# Documentation mentions --security-check.' '    erpc__subcmd__resume)' '      opts="--security-check"' '      ;;'
    fi
    ;;
  "completions zsh") printf "(ai)\n'(--message)--%s[Run a security check]'\n;;\n" "$(flag zsh)" ;;
  "completions fish") printf 'complete -c erpc -n "__fish_erpc_using_subcommand ai" -l %s -d "Run a security check"\n' "$(flag fish)" ;;
  "completions powershell")
    candidate=$(flag powershell)
    printf "        'erpc;ai' {\n"
    printf "            [CompletionResult]::new('--%s', '--%s', [CompletionResultType]::ParameterName, 'Read about --security-check')\n" "$candidate" "$candidate"
    printf '        }\n'
    if [ "$missing" = decoy-powershell ]; then
      printf '%s\n' '# Documentation mentions --security-check.' "        'erpc;resume' {" \
        "            [CompletionResult]::new('--security-check', '--security-check', [CompletionResultType]::ParameterName, 'Security check')" '        }'
    fi
    ;;
  "completions elvish") printf "&'erpc;ai'= {\n    cand --%s 'Run a security check'\n}\n" "$(flag elvish)" ;;
  *) exit 2 ;;
esac
