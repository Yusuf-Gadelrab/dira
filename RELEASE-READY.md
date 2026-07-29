# DIRA v1.1.0 — Release Readiness

Local validation pass, 2026-07-29. Everything below was **observed**, not assumed.
Nothing was published, committed, or pushed.

---

## 1. Test suite

```
$ uv run --extra dev pytest -q
..........................................                               [100%]
42 passed in 4.07s
```

**42 passed, 0 failed.** (The brief expected 37; the file actually contains 42 test functions.
An earlier run in this same session reported 38 — a concurrent process was editing
`tests/test_dira.py` mid-session, see §6.)

## 2. Build + packaging

| Check | Command | Result |
|---|---|---|
| Build | `uv build` | sdist + wheel built |
| Metadata / README render | `uvx twine check dist/*` | **PASSED** (both artifacts) |
| npm package | `npm pack --dry-run` | 3 files, 4.1 kB, `dira-scan@1.1.0` |
| Entry points (`dira`, `dira-scan`, `python -m dira`) | clean venv, py3.12 | all print `dira 1.1.0` |
| Python 3.9 floor (`requires-python = ">=3.9"`) | clean venv, py3.9 | full scan + sbom + fix + all 4 report formats OK |

The 3.9 check matters: the source uses `X | None` annotations, which only work on 3.9 because
every module has `from __future__ import annotations`. Verified rather than trusted.

## 3. Issues found and fixed

1. **sdist was missing `CHANGELOG.md` and `SECURITY.md`**, and was accidentally vacuuming in
   `npm/README.md` because the include pattern `README.md` matched at any depth. Rewrote
   `[tool.hatch.build.targets.sdist].include` with root-anchored `/`-prefixed paths.
2. **True positive in DIRA's own repo — `.gitignore` did not cover `.env` or `*.pem`.**
   A security scanner shipping the exact gap it flags. Added `.env`, `.env.*`,
   `!.env.example`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa`, `.pytest_cache/`.
3. **True positive — no automated dependency updates.** Added `.github/dependabot.yml`
   (github-actions + pip). Readiness score went **60% → 68%**.
4. **Overstated README performance claim (corrected).** README said second runs are
   "typically 5–10× faster". Measured on a 117-file repo:
   - full scan: 33.66s cold → 22.88s warm (**~1.2–1.5×**, not 5–10×)
   - file-scan phase only (`--only secrets,config`): 1.56s → 0.05s (**~30×**)

   The cache covers *file* scanning only; uncached git-history scanning dominates a full run
   (22.76s of the 33.66s). Rewrote the bullet with the real numbers and pointed users at
   `--history 0` for the fast inner loop (verified: 22.76s → 0.14s).
5. **Imprecise readiness wording.** "18-point score" → "18-check, 80-point score (reported as
   a percentage)", which is what the code actually does.
6. **README had no sample output.** Added a real terminal block captured from an actual run
   against a demo project, showing genuine redaction (`sk_l************nZaQ`).

## 4. Feature-claim audit — every claim verified against running code

| Claim | Verdict | Evidence |
|---|---|---|
| 20 secret patterns | ✅ | `len(SECRET_RULES) == 20` |
| 34 config/IaC/frontend/LLM/cloud rules | ✅ | `len(CONFIG_RULES) == 34` |
| Dependency CVEs via OSV.dev | ✅ | live run flagged `lodash 4.17.11` CVE-2019-10744 + 6 real axios CVEs, with fixed versions |
| Dependency license risk | ✅ | live run printed `Licenses  MIT ×2` inventory |
| Git-history leaks | ✅ | dedicated scanner + passing tests |
| Live TLS + headers | ✅ | `-t example.com` returned real HSTS/CSP/redirect findings |
| SBOM CycloneDX **1.5** | ✅ | `specVersion: "1.5"`, 12 components |
| SBOM SPDX **2.3** | ✅ | `spdxVersion: "SPDX-2.3"`, 12 packages |
| `dira fix` safe auto-remediation | ✅ | dry-run planned 5 additive fixes + manual checklist; 6th (`security.txt`) is conditional on static sites |
| `--diff` PR gating | ✅ | `--diff HEAD` narrowed 38 files → 1 |
| 18-point readiness score | ✅ | 18 checks, 80 weighted points |
| terminal / HTML / JSON / SARIF / Markdown | ✅ | all 5 render; SARIF is valid 2.1.0 with 27 rules / 41 results |
| Zero dependencies | ✅ | `dependencies = []`, stdlib only |

> Note: the brief said "6 scanners". There are actually **7**:
> `secrets, config, deps, licenses, git, readiness, surface`. The README table already lists all 7.

## 5. Dogfooding results

**DIRA on itself** — Grade **C**, risk 43/100, readiness **68%** (54/80).

- *True positives (fixed):* `.gitignore` missing `.env`/`*.pem`; missing dependabot config.
- *True positives (accepted, documented):* 8× "GitHub Action pinned to a mutable ref" in
  `.github/workflows/*`. Real by DIRA's own rule. Left as-is because pinning first-party
  `actions/*` to SHAs adds maintenance cost; the new dependabot config is what keeps them fresh.
  **Worth a decision before launch** — a security tool violating its own published rule is a
  credibility question, not a technical one.
- *False positives (correctly downgraded, no action):* ~23 findings in `tests/test_dira.py`
  (`NEXT_PUBLIC_STRIPE_SECRET_KEY`, `Principal: "*"`, `dangerouslyAllowBrowser`, JWT `none`,
  `curl | sh`, etc.). These are deliberate test fixtures and DIRA correctly labels each
  "(in test/docs path)" and downgrades severity. **This is the noise-control feature working.**
- *Remaining readiness gaps (not security bugs):* CODEOWNERS, IaC, error tracking, vetted auth —
  all inapplicable-to-mildly-applicable for a zero-dependency CLI.

**DIRA on `/Users/yusuf/Startups`** — Grade **B**, risk 14/100, readiness 21% (17/80), 117 files.
No secrets, no CVEs, no critical/high findings. Findings were 2× mutable action refs plus
process gaps (no dependabot, no secret scanning in CI, no SECURITY.md, no CODEOWNERS).
**No leaked credentials anywhere in the monorepo** — the meaningful result.

## 6. ⚠️ Honest caveats

- **A concurrent process edited this repo during validation.** `dira/engine.py`, `rules.py`,
  `scanners/{config,deps,gitrepo}.py` and `tests/test_dira.py` all changed at 11:11–11:13
  while this pass was running (test count moved 38 → 42). The tree was confirmed settled
  (identical md5s over 45s) and everything above was **re-run and re-built afterward**, so the
  results reflect the final tree. But `git status` shows 9 modified files that are **not all
  mine** — review the full diff before committing.
  - Mine: `.gitignore`, `README.md`, `pyproject.toml`, `.github/dependabot.yml` (new), `RELEASE-READY.md` (new).
  - Not mine: `dira/engine.py`, `dira/rules.py`, `dira/scanners/config.py`, `dira/scanners/deps.py`, `dira/scanners/gitrepo.py`, `tests/test_dira.py`.
- **`dist/` is built from the working tree, not from a clean git checkout.** Rebuild after committing.
- Nothing was committed, tagged, pushed, or published.

## 7. Registry name availability — checked 2026-07-29

```
$ curl -s -o /dev/null -w "%{http_code}" https://pypi.org/pypi/dira-scan/json      → 404
$ curl -s -o /dev/null -w "%{http_code}" https://registry.npmjs.org/dira-scan      → 404
```

**404 on both = the name `dira-scan` is FREE on PyPI and npm.** Re-check right before publishing;
names can be taken at any time.

Re-run the check yourself:

```bash
curl -s -o /dev/null -w "pypi: %{http_code}\n" https://pypi.org/pypi/dira-scan/json
curl -s -o /dev/null -w "npm:  %{http_code}\n" https://registry.npmjs.org/dira-scan
```

## 8. Publish — exact ordered commands (run these yourself)

### Step 0 — commit first

```bash
cd ~/Startups/dira
git diff                      # REVIEW: not every modified file is from this pass (see §6)
git add -A
git commit -m "chore: release prep — sdist metadata, gitignore hardening, honest perf claims"
```

### Step 1 — re-check the names are still free

```bash
curl -s -o /dev/null -w "pypi: %{http_code}\n" https://pypi.org/pypi/dira-scan/json
curl -s -o /dev/null -w "npm:  %{http_code}\n" https://registry.npmjs.org/dira-scan
# both must be 404
```

### Step 2 — clean rebuild and validate

```bash
cd ~/Startups/dira
rm -rf dist && uv build
uvx twine check dist/*        # must print PASSED twice
uv run --extra dev pytest -q  # must print 42 passed
```

### Step 3 — PyPI

**Preferred — Trusted Publishing (no token ever stored).** `.github/workflows/publish.yml`
is already wired for OIDC.

1. Log in at <https://pypi.org/manage/account/publishing/> → **Add a pending publisher**:
   - PyPI project name: `dira-scan`
   - Owner: `Yusuf-Gadelrab` · Repository: `dira`
   - Workflow name: `publish.yml` · Environment name: `release`
2. GitHub repo → Settings → Environments → **New environment** → name it `release`.
3. Tag and push — it publishes itself:

```bash
cd ~/Startups/dira
git tag v1.1.0 && git push origin v1.1.0
```

**Fallback — publish from this machine.** Token: <https://pypi.org/manage/account/token/>
(scope "entire account" for the first upload, then narrow it to the `dira-scan` project).

```bash
cd ~/Startups/dira
UV_PUBLISH_TOKEN=pypi-xxxxx uv publish
```

### Step 4 — npm (do this AFTER PyPI)

The npm package is a thin launcher that shells out to the Python CLI, so PyPI must resolve
first or `npx dira-scan` breaks on a clean machine.

```bash
npm login                     # opens a browser
cd ~/Startups/dira/npm
npm publish --access public
```

CI alternative: create an **Automation** token at <https://www.npmjs.com/settings/~/tokens>,
add it as repo secret `NPM_TOKEN`, and set repo variable `PUBLISH_NPM` to `true`.

### Step 5 — verify the published packages actually work

```bash
uvx --from dira-scan dira --version     # expect: dira 1.1.0
npx -y dira-scan --version              # expect: dira 1.1.0
```

### Step 6 — flip the docs from source-install to registry-install

These four places currently point at `git+https://...` so the README never promised a 404.
After both registries are live, switch them to `pip install dira-scan` / `dira-scan==1.1.0`:

- `README.md` — Install section **and** the "Registry status" blockquote (delete it)
- `action.yml` — the `pip install` line
- `dira/cli.py` — the `WORKFLOW` template's install line
- `~/Yusuf-Gadelrab.github.io/public/dira.html` — install step + cost FAQ answer

Then bump the version in `pyproject.toml`, `npm/package.json`, `npm/bin/dira.js` (`PKG`), and
`dira/__init__.py`, and tag again.

### Step 7 — GitHub Action marketplace (optional)

Push a moving `v1` tag so `uses: Yusuf-Gadelrab/dira@v1` keeps working:

```bash
git tag -f v1 && git push -f origin v1
```
