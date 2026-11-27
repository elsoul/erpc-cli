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
      printf '%s\n' '# Documentation mentions --security-check.' '    erpc__subcmd__help__subcmd__ai)' '      opts="--security-check"' '      ;;'
    fi
    ;;
  "completions zsh")
    # Reduced from the pinned generator. Both switches contain an (ai) arm.
    cat <<'ZSH'
    case $state in
    (erpc)
        curcontext="${curcontext%:*:*}:erpc-command-$line[1]:"
        case $line[1] in
(ai)
ZSH
    printf "'(--message)--%s[Run a security check]'\n" "$(flag zsh)"
    cat <<'ZSH'
;;
(help)
    case $state in
    (help)
        curcontext="${curcontext%:*:*}:erpc-help-command-$line[1]:"
        case $line[1] in
(ai)
ZSH
    if [ "$missing" = decoy-zsh ]; then
      printf '%s\n' "'(--message)--security-check[Run a security check]'"
    fi
    cat <<'ZSH'
;;
        esac
    ;;
    esac
;;
        esac
    ;;
    esac
ZSH
    ;;
  "completions fish")
    printf 'complete -c erpc -n "__fish_erpc_using_subcommand ai" -l %s -d "Run a security check"\n' "$(flag fish)"
    if [ "$missing" = decoy-fish ]; then
      printf '%s\n' 'complete -c erpc -n "__fish_erpc_using_subcommand help ai" -l security-check -d "Run a security check"'
    fi
    ;;
  "completions powershell")
    candidate=$(flag powershell)
    printf "        'erpc;ai' {\n"
    printf "            [CompletionResult]::new('--%s', '--%s', [CompletionResultType]::ParameterName, 'Read about --security-check')\n" "$candidate" "$candidate"
    printf '        }\n'
    if [ "$missing" = decoy-powershell ]; then
      printf '%s\n' '# Documentation mentions --security-check.' "        'erpc;help;ai' {" \
        "            [CompletionResult]::new('--security-check', '--security-check', [CompletionResultType]::ParameterName, 'Security check')" '        }'
    fi
    ;;
  "completions elvish")
    printf "&'erpc;ai'= {\n    cand --%s 'Run a security check'\n}\n" "$(flag elvish)"
    if [ "$missing" = decoy-elvish ]; then
      printf "&'erpc;help;ai'= {\n    cand --security-check 'Run a security check'\n}\n"
    fi
    ;;
  *) exit 2 ;;
esac
