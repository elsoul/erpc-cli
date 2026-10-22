---
description: Run the repository's required review gate on the current branch or a given pull request, then report its verdict.
argument-hint: "[PR number or branch; defaults to the current branch]"
allowed-tools: Bash(git status:*), Bash(git log:*), Bash(git diff:*), Bash(gh pr view:*), Bash(gh pr checks:*), Task
---

<!--
SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
SPDX-License-Identifier: Apache-2.0
-->

Review target: $ARGUMENTS

1. Work out what is under review. With no argument, use the current branch
   against `main`. With a number, use that pull request. Record the exact head
   commit SHA.
2. Launch the `oss-review` agent with the Task tool. Give it the target SHA,
   the base, the list of changed files, what the change is for, and anything
   already known to be unverified. Do not give it your own conclusion about
   whether the change is good: it reviews the code, not your opinion of it.
3. Relay its verdict in full, findings most severe first. Do not soften a
   finding or merge it into a summary.
4. On **FAIL**, fix the blocking findings, push, and run this command again
   with the new head. Repeat until there are no blocking findings.
5. On **PASS**, report what remains unverified and what the merge still needs
   (CI green, draft removed, approvals). Merge only when the user says so.

Never merge on a FAIL, never review your own change as the gate, and never
substitute "CI is green" for the gate's verdict.
