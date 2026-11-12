---
name: secret-scan
description: Finds API keys, tokens, private keys and passwords that were ever committed to a Git repository, including ones deleted in a later commit, and reports which are still in the working tree. Use before making a repository public, before open-sourcing or sharing code, after a suspected leak, when the user asks whether they ever committed a key, or as a check before pushing. One standard-library Python script, local only; values are masked in the output.
summary: Before a repo goes public, find every key, token and password ever committed, even ones deleted later. One stdlib Python script, runs locally, never prints a full value, tells you what to rotate first.
version: 1.0.0
tags: [security, secrets, git, api-keys, leak-detection, pre-publish, devops, code-review]
keywords: [leaked api key, secret scanning, git history secrets, before open source, committed password, rotate keys, pre-publish check]
use_cases:
  - Check this repo's whole history for leaked keys before I make it public
  - Did I ever commit an API key or password in this project
  - Scan my working tree for hard-coded credentials before I push
---

# Secret Scan

Deleting a key in a later commit does not remove it: it stays in the history
for anyone who clones the repository. This skill reads the whole history and
the current files, and tells the user what leaked and what to do first.

| Script | Does | Touches |
|---|---|---|
| `scripts/secretscan.py` | scans a history export and/or a folder for known key formats and hard-coded credentials | the files you name; no network code, never runs git |

## Running the script

Needs Python 3.8+ (`python3`, or `python` on Windows) and git. Write the script,
unchanged, to a temporary folder outside the repository. Remove it, and the
history export, when the task is done.

```
git log -p --all > <temp>/history.patch
python secretscan.py <temp>/history.patch --tree .
```

Write `history.patch` **outside** the repository so it is never committed. For
a quick check of the current files only: `python secretscan.py --tree .`

## Reporting

Show findings as a table: type, file, first commit, still in the working tree,
masked value. Put the ones still in the working tree first. Say how many
commits and files were scanned. If the result is clean, say what that means and
what it does not: a pattern scan cannot prove nothing was leaked.

## What to do about a finding, in this order

1. **Rotate or revoke the key now.** Anything ever pushed must be treated as
   leaked. This is the user's action in the provider's console; tell them
   exactly which key (type, file, masked value).
2. **Remove it from the working tree.** Load it from an environment variable or
   a secret store, and add the file to `.gitignore` if it is a config file.
3. **History rewrite is optional.** It is destructive and breaks other clones.
   Do it only if the user asks, explain the consequences first, and never
   force-push without their explicit yes. It is never a substitute for step 1.
4. Run the scan again and report the new result.

## Rules

- Never print, quote or paste a full secret. Use the masked value from the output.
- Never test a found key against its provider to see if it works.
- A false positive is marked by adding `secretscan:ignore` to that line, only
  after the user confirms it is not a real credential.

## Limits

- Pattern-based: it knows common key formats (AWS, GitHub, Stripe, Slack,
  Google, AI providers, private keys, JSON web tokens, passwords in URLs) and
  hard-coded assignments. A secret in an unusual format can be missed.
- Binary files and files over 1 MB are skipped. Submodules and other
  repositories are not scanned.
- It reads what you export. If `git log` was limited to one branch, only that
  branch was checked.
