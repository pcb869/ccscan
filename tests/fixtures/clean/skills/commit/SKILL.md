---
name: commit
description: Stage and commit current changes
disable-model-invocation: true
allowed-tools:
  - Bash(git add *)
  - Bash(git commit *)
  - Bash(git status *)
---

Stage the changes, write a clear message, verify with `git status`.
Errors from hooks should be reported, not silently ignored. Docs: https://git-scm.com/docs
