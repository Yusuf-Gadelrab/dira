# Publishing DIRA — copy-paste sequence

Everything that does not require a secret token is **already done**: the repo is public,
described, and topic-tagged; `main` and `v1.2.0` are pushed; both artifacts build and pass
`twine check`; the names are free on both registries.

What is left needs two tokens only you can create. Each step below has a verification
command — run it before moving to the next one.

Current version: **1.2.0** · PyPI name: `dira-scan` · npm name: `dira-scan`

---

## Step 0 — preflight (30 seconds)

Names can be claimed by anyone at any time. Confirm they are still free, and confirm the
tree still builds clean.

```bash
cd ~/Startups/dira
curl -s -o /dev/null -w "pypi: %{http_code}\n" https://pypi.org/pypi/dira-scan/json
curl -s -o /dev/null -w "npm:  %{http_code}\n" https://registry.npmjs.org/dira-scan
```

**Expect: `404` on both.** 404 means the name is free. A `200` means someone took it — stop
and pick a new name (change it in `pyproject.toml`, `npm/package.json`, and the `PKG`
constant in `npm/bin/dira.js`).

```bash
rm -rf dist && uv build
uvx twine check dist/*
uv run --extra dev pytest -q
```

**Expect:** `Successfully built` ×2, `PASSED` ×2, `42 passed`.

---

## Step 1 — PyPI

Do PyPI **first**. The npm package is a thin launcher that shells out to the Python CLI, so
if npm goes live first, `npx dira-scan` breaks on any machine that does not already have
DIRA installed.

### Option A — token from your laptop (fastest, ~3 minutes)

1. Go to <https://pypi.org/manage/account/token/> → **Add API token**.
2. Token name: `dira-scan-upload`. Scope: **Entire account** — a project-scoped token cannot
   be created until the project exists, so the first upload always needs account scope.
3. Copy the token (starts with `pypi-`). It is shown once.

```bash
cd ~/Startups/dira
UV_PUBLISH_TOKEN=pypi-PASTE_YOUR_TOKEN_HERE uv publish
```

**Verify — this is the real test, not the upload output:**

```bash
uvx --from dira-scan dira --version
```

**Expect: `dira 1.2.0`.** This pulls from PyPI into a throwaway environment, so it proves
the published artifact actually installs and runs. If it prints an older version, you are
seeing a cached local build — add `--refresh`.

Then go back to <https://pypi.org/manage/account/token/>, delete the account-scoped token,
and create a new one scoped to the `dira-scan` project only. An account-scoped token sitting
in your shell history can publish anything under your name.

### Option B — Trusted Publishing (no token ever stored, ~5 minutes)

`.github/workflows/publish.yml` is already wired for OIDC, so GitHub authenticates to PyPI
directly and no secret is ever created or stored.

Pushing the `v1.2.0` tag already fired this workflow. It built the wheel, installed it on a
clean Ubuntu runner, confirmed `dira --version`, and then failed at exactly one step:

```
##[error]Trusted publishing exchange failure:
  sub: repo:Yusuf-Gadelrab/dira:environment:release
```

That is the expected failure — PyPI does not yet know this repo is allowed to publish. The
`release` environment **already exists**, so there is only one thing left to do:

1. <https://pypi.org/manage/account/publishing/> → **Add a pending publisher**:
   - PyPI project name: `dira-scan`
   - Owner: `Yusuf-Gadelrab` · Repository: `dira`
   - Workflow name: `publish.yml` · Environment name: `release`

2. Re-run the job that already failed — do **not** cut a throwaway tag:

```bash
gh run rerun 30479719498 -R Yusuf-Gadelrab/dira --failed
gh run watch 30479719498 -R Yusuf-Gadelrab/dira
```

**Verify:**

```bash
uvx --from dira-scan dira --version    # expect: dira 1.2.0
```

---

## Step 2 — npm (only after Step 1 verifies)

```bash
npm login                    # opens a browser; no token to copy
cd ~/Startups/dira/npm
npm publish --access public
```

`--access public` is required — scoped and new packages default to restricted, and a
restricted package fails for everyone else with a 404.

**Verify:**

```bash
npx -y dira-scan --version
```

**Expect: `dira 1.2.0`.** `-y` skips the install prompt. This runs the real launcher path:
npm fetches the shim, the shim finds a Python runner, and DIRA answers. If it prints the
"no working Python runner found" error, the shim is fine but the test machine has no
Python 3.9+ — that is the documented fallback message, not a publish failure.

CI alternative: create an **Automation** token at <https://www.npmjs.com/settings/~/tokens>,
add it as repo secret `NPM_TOKEN`, and set repo variable `PUBLISH_NPM` to `true`.

---

## Step 3 — flip the docs from source-install to registry-install

Until now every install instruction points at `git+https://…` so the README never promised a
404. Once both registries resolve, switch these four places to the real thing:

- `README.md` — the Install section **and** the "Registry status" blockquote (delete it)
- `action.yml` — the `pip install` line → `pip install --quiet "dira-scan==1.2.0"`
- `dira/cli.py` — the `WORKFLOW` template's install line (what `dira init` writes into
  other people's repos)
- `~/Yusuf-Gadelrab.github.io/public/dira.html` — install step and the cost FAQ answer

```bash
cd ~/Startups/dira
grep -rn "git+https://github.com/Yusuf-Gadelrab/dira" README.md action.yml dira/cli.py
```

**Expect after editing: no matches.** Then commit, and redeploy the site:

```bash
cd ~/Yusuf-Gadelrab.github.io && npm run deploy
```

---

## Step 4 — make the GitHub Action usable (optional, 1 minute)

`README.md` advertises `uses: Yusuf-Gadelrab/dira@v1`, a moving major tag. It currently
points at v1.1.0, so anyone using it gets the version with the false-positive `.env` bug.
Moving it requires a force-push of that one tag:

```bash
cd ~/Startups/dira
git tag -f v1 v1.2.0 && git push -f origin v1
```

This is left for you deliberately — it is the only force-push in the whole sequence.

Heads-up: `publish.yml` triggers on `tags: ['v*']`, so moving `v1` re-runs the publish job.
Once 1.2.0 is on PyPI that re-run fails with "file already exists". Harmless, but if you
want it silent, publish first and expect one red X on the `v1` push.

**Verify:**

```bash
git ls-remote --tags origin | grep -E "refs/tags/v1$" -A0
```

The sha shown should match `git rev-parse v1.2.0^{}`.

---

## Rollback

PyPI and npm both **forbid re-uploading a version number**, even after deleting it. If you
ship a broken 1.2.0 you cannot replace it — you can only yank it and publish 1.2.1.

```bash
# PyPI: yank (hides from resolvers, keeps existing installs working)
#   https://pypi.org/manage/project/dira-scan/releases/  → Options → Yank

# npm: within 72 hours only
npm unpublish dira-scan@1.2.0
# after 72 hours, deprecate instead:
npm deprecate dira-scan@1.2.0 "broken release, use 1.2.1"
```

This is why Step 0's `twine check` and the 42-test run matter more than they look.
