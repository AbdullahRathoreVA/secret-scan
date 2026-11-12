# Secret Scan

Find every API key, token and password that was ever committed to a Git
repository, including ones deleted in a later commit, before you make the
repository public. A free skill for AI agents (Claude Code, Codex CLI, Cursor
and any agent that reads `SKILL.md`), and a plain command-line tool.

Deleting a key in a later commit does not remove it. It stays in the history
for anyone who clones the repository.

- **Reads the whole history and the current files.**
- **Says which leaks are still in the working tree** and puts those first.
- **Never prints a full value**: only its first 4 characters and its length.
- **Local only.** One standard-library Python script with no network code. It
  never runs git; you export the history and it reads the file.

## Use it

```bash
git log -p --all --output=../history.patch
```

```bash
python scripts/secretscan.py ../history.patch --tree .
```

Write `history.patch` outside the repository so it is never committed, and
delete it afterwards. Use `--output`, not `>`: a Windows PowerShell redirect
saves UTF-16, which the scan refuses with an error. For the current files only:

```bash
python scripts/secretscan.py --tree .
```

Example result on a real repository (27 commits, 108 files):

```json
{ "clean": false,
  "scanned": { "commits": 27, "added_lines": 16612, "files": 108,
               "unreadable_files": 0, "values_marked_ignore": 0 },
  "found": 1, "by_type": { "AI provider key": 1 },
  "findings": [ { "type": "AI provider key", "file": ".env", "commit": "",
                  "in_working_tree": true, "value": "gsk_... (56 chars)" } ] }
```

The history is clean; the one hit is a local `.env` that is gitignored, which
is where a key belongs.

## What it knows

AWS access keys, GitHub tokens, Stripe live keys, Slack tokens, Google API
keys, AI provider keys, private key blocks, JSON web tokens, passwords inside
URLs, and hard-coded assignments such as `db_password = "..."` or
`clientSecret: "..."`. Placeholders (`your_key_here`, `${VAR}`, `example`) are
ignored. Add `secretscan:ignore` to a line to skip a confirmed false positive:
a scan of history and files then leaves that value out of the history findings
too.

It is a pattern scan: it cannot prove nothing was leaked, and a secret in an
unusual format can be missed. Binary files and files over 1 MB are skipped.

## If it finds something

1. **Rotate or revoke the key now.** Anything ever pushed is leaked.
2. Remove it from the working tree and load it from the environment.
3. Rewriting history is optional and destructive, and never a substitute for step 1.

## As an agent skill

With the skills CLI:

```bash
npx skills add AbdullahRathoreVA/secret-scan
```

Or copy this folder into your agent's skills directory. Then ask: "Check this
repo's history for leaked keys before I make it public."

More skills from the same author, including the Aether Engine pack and Agent
Team: <https://www.agensi.io/creators/abdullah-rathore>

## Licence

MIT. See [LICENSE](LICENSE).
