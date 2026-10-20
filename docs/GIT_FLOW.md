# Git flow — WebSecurityCheck SDK

**Status** init · **Owner** Duc Dang

Small team, short project, two moving parts that must not break each other: the
SDK (ours) and the MCP tool server (the partner's). The flow below is the
smallest one that keeps `main` releasable and keeps the tool contract from
drifting silently.

---

## 1. Branch model

Two long-lived branches plus short-lived work branches. `dev` is where the work
integrates; `main` is what a developer outside the team would install.

| Branch | Lives | Rule |
|---|---|---|
| `main` | forever | Release only. Always installable, always green, every commit tagged. Receives merges from `dev` and from `hotfix/*` — nothing else. Never commit to it directly. |
| `dev` | forever | The integration branch. Every work branch starts here and comes back here through a PR. Must stay green: a red `dev` blocks everyone. |
| `feat/*` `fix/*` `docs/*` `chore/*` `test/*` `refactor/*` | hours to ~3 days | Branch from `dev`, merge back into `dev` through a PR. |
| `hotfix/*` | hours | Only for a bug in a released tag. Branch from `main`, merge into `main`, then **merge `main` back into `dev` the same day** so the fix is not lost at the next release. |
| `release/v0.x` | only if a release needs patching while `dev` moves on | Cut from the tag. Not expected in v0.1. |

```
feat/mcp-servers-recon-tools ──┐
feat/policy-scope-guard       ─┤
feat/tools-mcp-client         ─┼──► dev ──(release PR)──► main ──► tag v0.1.0
docs/architecture             ─┘       ▲                     │
                                       └──── hotfix back-merge ┘
```

The L6 recon capability is intentionally kept in one feature branch so its
tools, direct verification runner and contract tests are reviewed together.

**Why `dev` and not plain trunk.** Two people land into the same layers, and
the partner's MCP server moves on its own schedule. `dev` is the place where a
half-finished tool contract and a half-finished policy rule can meet and break
each other without that ever reaching a tagged version.

### dev → main

`main` only moves at a release. The release is itself a PR, `dev` → `main`,
and it is the one PR that is **not** squashed — `main` keeps the individual
commits so a tag can be traced back to the changes it contains.

Conditions to open it: `pytest` and `ruff` green on `dev`, the version bumped
in `pyproject.toml`, release notes drafted, and no contract change left
unconfirmed with the partner.

### Naming

```
<type>/<layer-or-area>-<short-slug>

feat/policy-scope-guard
feat/tools-mcp-allowlist
fix/steering-tls-coverage-aliases
docs/architecture-turn-diagram
chore/ci-ruff-pytest
```

The area is the folder from the architecture map — `checker`, `checks`,
`engine`, `policy`, `tools`, `memory`, `results`, `telemetry`, `skills`,
`mcp-servers`, `docs`, `ci`. The L6 recon branch is an explicit exception:
all ten tools, their direct runner and their tests stay together.

---

## 2. Commits

[Conventional Commits](https://www.conventionalcommits.org). The type is what
the commit does, the scope is the area above.

```
feat(policy): add in_scope() and the BeforeToolCall hook
fix(steering): accept not_after as an alias for the tls expiry topic
test(policy): cover the https -> http downgrade rule
docs(architecture): map the seven turn steps onto modules
chore(deps): pin strands-agents to >=1.58
```

Rules that actually matter here:

- **One logical change per commit.** A reviewer should be able to read the diff
  without a guided tour.
- **A behaviour change ships with its test** in the same commit. A commit that
  changes a policy rule without touching `tests/` gets sent back.
- **`BREAKING CHANGE:` in the footer** for anything that alters the public
  surface (`checker.py`, `results/`) or the tool contract. Those two are
  contracts with people outside this repo.
- Never commit a secret, a `.env`, a real scan report, or a target's content.

---

## 3. Pull requests

Every change lands through a PR, including your own. The PR is where the
reasoning is recorded — the repo outlives the conversation.

**Target branch:** `dev` for everything, except a `hotfix/*` (targets `main`)
and the release PR (`dev` → `main`). Check the base branch before opening —
GitHub defaults to the repository's default branch, so set the default to
`dev` once the repo is pushed.

**A PR must say:**

1. What changed, in one paragraph.
2. Which layer of the architecture map it touches, and whether it crosses the
   public surface or the tool contract.
3. How it was verified — `pytest`, a `probe_target.py` run, a live
   `run_check.py` run, or an explicit "not verified end to end yet".
4. Open questions it leaves behind.

**Merge checklist:**

- [ ] `pytest` passes with no network and no model
- [ ] `ruff check .` clean
- [ ] Docs updated if the change alters a contract in `docs/ARCHITECTURE.md`
- [ ] No secret, `.env`, `*.db` or scan report in the diff
- [ ] Reviewed by the other person, or self-reviewed with a written note on why
      a second pair of eyes was not needed

**Merge style:** squash merge into `dev`. One branch becomes one commit, so the
history reads as a list of changes rather than a list of keystrokes. The PR
title becomes the commit message, so it follows the convention in section 2.
Delete the branch after merging.

The release PR (`dev` → `main`) is the exception: a real merge commit, no
squash. Squashing a release would collapse weeks of history into one commit on
`main` and make a tag impossible to read.

---

## 4. Rules specific to this project

These are the ones worth writing down, because breaking them is cheap and the
damage shows up weeks later.

1. **The tool contract is frozen.** Changing the envelope, the `target`
   argument name, or an `E_*` code is a `BREAKING CHANGE:` PR, labelled
   `contract`, and the partner is tagged on it. It never rides along inside a
   feature PR.
2. **The public surface is `checker.py` and `results/`.** A PR that widens it
   says so in the description. Everything else is internal and free to move.
3. **Never commit a target's content.** No saved `report.json`, no captured
   headers, no cookie values — not even from a site we own. `.gitignore`
   covers the obvious paths; the reviewer covers the rest.
4. **A policy rule change needs a regression test.** `policy/` is the part of
   the SDK that is supposed to be predictable between runs; an untested change
   there is indistinguishable from a bug.
5. **No real network in `tests/`.** Anything that needs a network or a model
   lives in `examples/` and is run by hand.

---

## 5. Releases

Semantic versioning, tagged on `main`, matching `version` in `pyproject.toml`.
A tag never sits on `dev`.

```bash
# 1. bump the version on dev, through a PR like any other change
git switch dev && git pull
git switch -c chore/release-v0.1.0        # edit pyproject.toml, draft notes

# 2. release PR: dev -> main, merge commit, no squash

# 3. tag main
git switch main && git pull
git tag -a v0.1.0 -m "v0.1.0 — four checks, policy layer, MCP tool path"
git push origin v0.1.0

# 4. bring the merge back so dev and main share history
git switch dev && git merge --ff-only main && git push
```

Before `v1.0.0` the minor number carries breaking changes: `0.x` means the
public surface may still move, and `BREAKING CHANGE:` in a commit bumps the
minor rather than the major.

Each tag gets release notes listing, in this order: contract changes, public
API changes, new checks, fixes.

---

## 6. CI (to add in the first week of coding)

One workflow, on every push to `dev` or `main` and on every PR into either:

```
ruff check .
ruff format --check .
pytest
```

No network and no model credentials, so CI runs on a fork and on a PR from the
partner without handing out keys. The live runs stay manual.

---

## 7. Bootstrap

```bash
cd WebSecuritySDK
git init -b main
git add .
git commit -m "chore: init project skeleton and architecture"

git remote add origin <url>
git push -u origin main

# dev branches off the first commit on main and is where all work lands
git switch -c dev
git push -u origin dev
```

On the remote, set `dev` as the **default branch** so PRs target it by
mistake-proof default, and protect both: no direct push to `main` or `dev`,
CI green required to merge.

Then, per piece of work:

```bash
git switch dev && git pull
git switch -c feat/policy-scope-guard
# ... commit ...
git push -u origin feat/policy-scope-guard
# open a PR into dev, squash merge, delete the branch
```

---

## 8. First branches (suggested order)

All of them branch from `dev` and merge back into `dev`. The order follows the
dependency direction of the architecture, so each branch can be tested the
moment it lands.

| # | Branch | Lands |
|---|---|---|
| 1 | `chore/ci-ruff-pytest` | CI green on an empty suite |
| 2 | `feat/results-models` | `Finding`, `ErrorInfo`, `CheckOutput`, `CheckResult` + status rules |
| 3 | `feat/mcp-servers-recon-tools` | all 10 L6 tools, parsers/models, FastMCP registration, direct runner and offline tests |
| 4 | `feat/policy-scope-guard` | `in_scope()` as a pure function + its tests |
| 5 | `feat/tools-mcp-client` | server discovery, allowlist, dead-server handling |
| 6 | `feat/checks-and-engine` | `Check`, the registry, `runner.py`, first live agent run |

Only after #6 does the rest of the policy layer — injection guard, retry,
output validator, steering — have a real run to attach to.
