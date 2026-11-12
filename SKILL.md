---
name: secret-scan
description: Finds API keys, tokens, private keys and passwords that were ever committed to a Git repository, including ones deleted in a later commit, and reports which are still in the working tree. Use before making a repository public, before open-sourcing or sharing code, after a suspected leak, when the user asks whether they ever committed a key, or as a check before pushing. One standard-library Python script, local only; values are masked in the output.
license: MIT
metadata:
  version: "1.1.0"
---

# Secret Scan

Deleting a key in a later commit does not remove it: it stays in the history
for anyone who clones the repository. This skill reads the whole history and
the current files, and tells the user what leaked and what to do first.

| Script | Does | Touches |
|---|---|---|
| `scripts/secretscan.py` | scans a history export and/or a folder for known key formats and hard-coded credentials | the files you name; no network code, never runs git |

## Running the script

Needs Python 3.8+ (`python3`, or `python` on Windows) and git. Nothing to
install and nothing to copy: the script is already on disk at
`scripts/secretscan.py` in this skill's folder, which is the folder that
contains this SKILL.md. Run it in place by giving its path, with the user's
repository as the working directory. Below, `<skill-folder>` is that folder and
`<temp>` is a temporary folder outside the repository.

```
git log -p --all --output=<temp>/history.patch
python <skill-folder>/scripts/secretscan.py <temp>/history.patch --tree .
```

`--output` makes git write the export itself. Do not use `>` in Windows
PowerShell: it saves the file as UTF-16, which the script refuses with an
error. If `scanned.commits` is 0 for a repository that has commits, the file
is not a `git log -p` export and the result is not valid: export again.

Keep `history.patch` **outside** the repository so it is never committed, and
delete it when the task is done: it holds every value in full. For a quick
check of the current files only:
`python <skill-folder>/scripts/secretscan.py --tree .` For the history only,
leave out `--tree .`; `in_working_tree` is then `null`, meaning not checked.

## Output

One JSON object on standard output, and nothing is written to disk: `clean`,
`scanned` (`commits`, `added_lines`, `files`, `unreadable_files`,
`values_marked_ignore`), `found`, `by_type`, `findings` and `next` (or `note`
when clean). If `unreadable_files` is above 0, say that those files (locked,
or no permission) were not checked. Each finding has `type`, `file`, `commit`
(the oldest commit that added the value; empty when the value was not seen in
a history export), `line` (when it is in the working tree), `times_seen`,
`in_working_tree` and the masked `value`: its first 4 characters and its
length. At most 200 findings are listed; `not_shown` counts the rest. An error
is one JSON object on standard error with exit code 1. Exit code 0 means the
scan ran, not that the repository is clean: read `clean`.

## Reporting

Show findings as a table: type, file, first commit, still in the working tree,
masked value. Put the ones still in the working tree first. Say how many
commits and files were scanned. If the result is clean, say what that means and
what it does not: a pattern scan cannot prove nothing was leaked.

A finding with an empty `commit` was not in the exported history. After a scan
of both history and files, check it with `git check-ignore -q <file>` and
`git ls-files <file>`: if git ignores the file and does not track it, report
it apart as local only and not leaked, with no advice to rotate. A key in an
ignored `.env` is where it belongs.

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
- The scan only reads. Editing a file, changing `.gitignore`, rewriting
  history and force-pushing each need the user's explicit yes in this
  conversation first. A history rewrite or force-push cannot be undone for
  other clones: say so, and have the user keep a backup copy of the repository,
  before asking.
- Scan only repositories the user owns or is allowed to audit, and never use a
  found key for anything.
- In a scan that includes `--tree`, the marker on a line of the current files
  also drops that same value from the history findings. A history-only scan
  still reports it.
- If git already tracks a file, adding it to `.gitignore` does not stop that:
  `git rm --cached <file>` does, on the user's yes.

## Limits

- Pattern-based: it knows common key formats (AWS, GitHub, Stripe, Slack,
  Google, AI providers, private keys, JSON web tokens, passwords in URLs) and
  hard-coded assignments. A secret in an unusual format can be missed.
- Binary files, and in the working tree files over 1 MB, are skipped. The
  history of a submodule is not in the export; its files on disk are read as
  part of the folder.
- It reads what you export. If `git log` was limited to one branch, only that
  branch was checked.
- A hard-coded assignment (names such as `db_password`, `clientSecret` or
  `ApiKey`) is found only when the value is in quotes, has 12 or more
  characters and looks random. An unquoted value, as in most `.env` files, is
  found only if it matches a known key format.
- `git log -p` prints no diff for a merge commit, so a value added only while
  resolving a merge is not in the export. Commits that no ref points to, such
  as those of a deleted branch, are not exported either.
- The working-tree scan reads untracked and ignored files too, and skips
  folders named `.git`, `node_modules`, `venv`, `.venv`, `dist`, `build`,
  `__pycache__`, `.next` and `vendor`.
- Private key blocks are matched by their header line, so several keys with
  the same header show as one finding; `times_seen` counts them.
