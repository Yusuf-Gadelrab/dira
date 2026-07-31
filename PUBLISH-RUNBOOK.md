# DIRA publish runbook

> ## 🛑 HELD until written scope confirmation + Yusuf's go
> Nothing below may be executed — no `uv publish` / `twine upload`, no `npm publish`,
> no pre-commit registry PR, no GitHub Marketplace listing, no new account, no tag push —
> until (1) a **written** scope confirmation from counsel is on file, and (2) Yusuf gives an
> explicit go-ahead referencing this file. Build, test, and stage freely — that part is
> always allowed. This banner supersedes any "ready to ship" tone in the rest of this
> document or in `PUBLISH.md`.

Everything in this file is a **command reference**, not an instruction to run now. Treat it
as the exact sequence to execute the day the hold lifts.

Current version: **1.2.0** · PyPI name: `dira-scan` · npm name: `dira-scan` · GitHub:
`Yusuf-Gadelrab/dira` (already public — the source repo itself is not gated, only
publishing to package registries / the Marketplace / creating new accounts is).

---

## Pre-flight checklist (run every time, in order)

1. **Version is consistent.** `pyproject.toml`, `npm/package.json`, and `dira/__init__.py`
   `__version__` must all match. Today they do (all `1.2.0`).
2. **⚠ Known gap right now:** `CHANGELOG.md` has an `## Unreleased — precision pass (ruleset
   1.5.0)` section sitting on top of the `## 1.2.0` entry — real, already-shipped fixes
   (typosquat false-positive fix, placeholder-filter false-negative fix, minified-file
   handling, git-history file attribution) that post-date the 1.2.0 cut. `dira/rules.py`
   already reports `RULESET_VERSION = "1.5.0"` while the package version is still `1.2.0`.
   **Before publishing, resolve this**: either cut a `1.2.1`/`1.3.0` and fold the Unreleased
   notes into a dated entry, or explicitly decide 1.2.0 ships as-is and move the Unreleased
   notes under it. Do not publish with an open "Unreleased" section — it means the changelog
   and the artifact disagree about what's inside it.
3. **Tag matches the version being published.** `git tag -l` currently has `v1`, `v1.1.0`,
   `v1.2.0`. If the version changed in step 2, cut a new annotated tag before publishing —
   do not reuse `v1.2.0` for different bits (PyPI/npm both permanently reject a re-uploaded
   version number).
4. **Tests + build are clean:**
   ```bash
   cd ~/Startups/dira
   uv run --extra dev pytest -q          # expect: 98 passed (verify current count first)
   rm -rf dist && uv build
   uvx twine check dist/*                # expect: PASSED ×2
   ```
5. **Names are still free** (re-check immediately before publishing — names can be claimed
   by anyone, any time):
   ```bash
   curl -s -o /dev/null -w "pypi: %{http_code}\n" https://pypi.org/pypi/dira-scan/json
   curl -s -o /dev/null -w "npm:  %{http_code}\n" https://registry.npmjs.org/dira-scan
   ```
   Expect `404` on both. A `200` means stop and rename (`pyproject.toml`, `npm/package.json`,
   the `PKG` constant in `npm/bin/dira.js`).
6. **Wheel actually runs**, not just imports from source:
   ```bash
   uv venv /tmp/dira-preflight && uv pip install --python /tmp/dira-preflight/bin/python dist/*.whl
   /tmp/dira-preflight/bin/dira --version && /tmp/dira-preflight/bin/dira --help
   ```
7. **Written scope confirmation + go-ahead gate** (see banner above) — the only step that
   isn't a technical check. Confirm in writing before continuing.

---

## Step 1 — PyPI (`dira-scan`)

Do PyPI first — the npm package is a thin launcher that shells out to the Python CLI, so if
npm goes live first, `npx dira-scan` breaks on machines without DIRA already installed.

### Option A — token from your laptop (~3 min)
```bash
cd ~/Startups/dira
# https://pypi.org/manage/account/token/ → Add API token → scope: Entire account
#   (project-scoped tokens can't be created until the project exists)
UV_PUBLISH_TOKEN=pypi-PASTE_YOUR_TOKEN_HERE uv publish
uvx --from dira-scan dira --version --refresh   # expect: dira <version>
```
Then delete the account-scoped token and replace it with one scoped to the `dira-scan`
project only — an account-scoped token in shell history can publish anything under your name.

### Option B — Trusted Publishing / OIDC (~5 min, no token stored)
`.github/workflows/publish.yml` is wired for this already. One manual step is outstanding:
```
https://pypi.org/manage/account/publishing/ → Add a pending publisher
  Project name: dira-scan · Owner: Yusuf-Gadelrab · Repository: dira
  Workflow: publish.yml · Environment: release
```
Then re-run the job (do not cut a new tag for this):
```bash
gh run rerun 30479719498 -R Yusuf-Gadelrab/dira --failed
gh run watch 30479719498 -R Yusuf-Gadelrab/dira
uvx --from dira-scan dira --version --refresh
```

---

## Step 2 — npm (`dira-scan`, only after Step 1 verifies)

```bash
npm login                              # opens a browser, no token to copy
cd ~/Startups/dira/npm
npm publish --access public            # required: scoped/new packages default to restricted
npx -y dira-scan --version             # expect: dira <version>
```
CI alternative: create an **Automation** token at
`https://www.npmjs.com/settings/~/tokens`, store as repo secret `NPM_TOKEN`, set repo
variable `PUBLISH_NPM=true`.

---

## Step 3 — pre-commit hook (discoverability listing)

The hook already works today with **zero registry step**, straight from source —
`.pre-commit-hooks.yaml` lives at the repo root, so anyone can already write:
```yaml
repos:
  - repo: https://github.com/Yusuf-Gadelrab/dira
    rev: v1.2.0
    hooks:
      - id: dira
```
That's the actual distribution mechanism; there is nothing to "publish" for it to function.
The only optional step is **discoverability** on the community index at
pre-commit.com/hooks.html:
```bash
gh repo fork pre-commit/pre-commit.com --clone
cd pre-commit.com
# add a dira-scan entry to hooks.yaml, alphabetically, following the existing format
git checkout -b add-dira-scan
git add hooks.yaml && git commit -m "Add dira-scan"
gh pr create --title "Add dira-scan" --body "Zero-dependency security audit for startup codebases."
```
Low priority — this only adds a listing page, it doesn't change how the hook is consumed.

---

## Step 4 — GitHub Marketplace listing for the Action

Full listing copy (tagline, description, verified inputs/outputs, workflow examples, and a
flagged list of `action.yml` mismatches) is already drafted in
`launch/github-action-marketplace.md` — use that file verbatim for the listing form fields.
Summary of the mechanical steps (there is no `gh` command for this — it's UI-only):

1. Confirm `action.yml` has `name`, `description`, `branding` at the repo root — verified present.
2. Confirm the repo is public and has a README — verified.
3. GitHub repo → **Releases** → edit the release for the tag being published → check
   **Publish this Action to the GitHub Marketplace**.
4. Accept the GitHub Marketplace Developer Agreement (one-time, account-level).
5. Categories: primary **Code quality**, secondary **Security**. Confirm the `shield` /
   `yellow` branding preview, then publish.

Before this step, also apply the two fixes `launch/github-action-marketplace.md` already
flags as required: move the `v1` moving tag off v1.1.0 (`git tag -f v1 v1.2.0 && git push -f
origin v1` — the one deliberate force-push in this whole runbook, left for Yusuf to trigger
by hand), and once PyPI is live, change `action.yml`'s install line from
`git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0` to `pip install --quiet
"dira-scan==1.2.0"`.

---

## Step 5 — flip docs from source-install to registry-install (after Steps 1–2 verify)

```bash
cd ~/Startups/dira
grep -rn "git+https://github.com/Yusuf-Gadelrab/dira" README.md action.yml dira/cli.py
```
Expect no matches after editing. Also update:
`~/Yusuf-Gadelrab.github.io/public/dira.html` — install step + the "PyPI and npm packages are
on the way" line. Then:
```bash
cd ~/Yusuf-Gadelrab.github.io && npm run deploy
```

---

## Rollback

Neither registry allows re-uploading a version number, even after deletion — a broken
release can only be yanked/deprecated, not replaced.
```bash
# PyPI: https://pypi.org/manage/project/dira-scan/releases/ → Options → Yank
# npm, within 72 hours:
npm unpublish dira-scan@<version>
# npm, after 72 hours:
npm deprecate dira-scan@<version> "broken release, use <next-version>"
```

---

## Source of truth for details

This file is the ordered command sequence. For narrative detail, mismatch call-outs, and
verification rationale behind each command, see `PUBLISH.md` (PyPI/npm) and
`launch/github-action-marketplace.md` (Marketplace listing + `action.yml` gaps).
