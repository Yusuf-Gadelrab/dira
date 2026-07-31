# Changelog

## Unreleased — precision pass (ruleset 1.5.0)

Measured by running the scanner over four real repositories and a hostile fixture tree,
then hand-triaging every finding. Findings on those repositories dropped from 169 to 84
with no loss of true positives, and two silent false negatives were recovered.

Fixed
- **`deps/possible-typosquat` had a 100% false-positive rate.** It ran edit-distance ≤ 2
  over the entire resolved lockfile, so every legitimate transitive package that rhymed
  with a famous one was flagged (`defu`~`debug`, `jiti`~`vite`, `numba`~`numpy`,
  `pyotp`~`pytz`, `jsesc`~`jest` — 17 hits, 17 wrong). A typosquat is delivered by *your*
  typo, so it can only appear in a manifest a human wrote. Now restricted to declared
  dependencies, edit distance exactly 1, with an allowlist of known-legitimate near
  misses. Skips silently rather than falling back to the lockfile when the declared set
  is unavailable.
- **False negative: real credentials containing common words were silently discarded.**
  The placeholder filter matched `password`, `secret`, `test`, `foo`, and `bar` as
  substrings anywhere in the value, so `ThisIsALongRealLookingSecret123`,
  `MyFastestTokenValue99`, and `barbaraDbPassword1` were dropped without ever being
  reported. Those words now only mean "placeholder" when they are essentially the whole
  value; unambiguous markers (`changeme`, `your_`, `example`, `xxx`) still match anywhere.
- **False positives across minified and generated bundles.** A minified file is
  wall-to-wall high-entropy mangled identifiers, so the entropy-gated generic rule fired
  on nearly every one, and code rules reported `innerHTML` inside vendored libraries the
  user cannot fix. Minified/generated artifacts are now detected by name and by line
  geometry; entropy and code rules skip them. **Precise provider rules still run** — a
  build-time key compiled into a bundle is exactly the leak worth catching.
- **One dependency reported up to 12 times.** A package published as per-platform
  binaries (`@img/sharp-libvips-linux-x64`, `-darwin-arm64`, …) produced one license
  finding per artifact, burying real issues and inflating the risk score. Platform
  variants of one dependency now collapse into a single grouped finding.
- **`.gitignore` `*.pem` gap was reported on repos with no key material.** Now raised
  only when the repository actually contains certificate or key files, via a bounded
  walk that skips vendor trees.

Changed
- **Dev-only dependencies are ranked one level lower and labelled `(dev-only)`.** A
  prototype-pollution CVE in a bundler plugin and the same CVE in a live request path
  are not the same finding, and grading a repo `F` on build-tooling advisories is how a
  scanner gets switched off. Resolved from the npm lockfile `dev` flag, `Pipfile.lock`
  `develop`, and — since bun.lock carries no flag — graph reachability from the
  workspace's runtime dependencies. Still reported, with the caveat that a compromised
  CI build is a real threat model.
- **GitHub Action pin severity is now tiered.** `actions/checkout@v4` (GitHub-owned) is
  `low`; a third-party action on a mutable tag stays `medium` and now names the owner and
  suggests the exact SHA-pinned replacement.
- `action.yml`: added `diff`, `only`, `skip`, and `offline` passthrough inputs. `--diff`
  was documented as the PR gate but was not reachable from the action.
- `action.yml`: inputs are now passed via `env:` instead of being interpolated into the
  shell body — the exact script-injection class this project's own `ci-script-injection`
  rule exists to flag.
- README rule counts corrected (24 secret rules, 38 config rules).

Added
- Hardening tests for hostile input: files over the size cap, huge single-line files,
  binaries with text extensions, invalid UTF-8, BOMs, unicode paths, malformed
  lockfiles, unterminated string literals, 40-level nesting, symlink loops, dangling
  symlinks, unreadable files, empty directories, and non-git targets. Test count 53 → 68.
- `dira/licensing.py` and `dira/policy.py` — offline, no-telemetry entitlement scaffolding
  for a future paid tier. Every capability through v1.2.0 stays free forever
  (`COMMUNITY_FEATURES` in `licensing.py`); the only gated feature so far is
  `policy` (per-rule severity overrides and gates via a `--policy` JSON file). Verification
  is a local HMAC check with no activation server and no call-home — see the module
  docstring for the honest threat-model writeup. `tests/test_licensing.py` — 30 tests.
  Suite total 68 → **98 passing**.
- `VIABILITY.md` — competitive and business assessment.
- `service/` — the audit-engagement kit (intake, scope skeleton, runbook, remediation
  library, pricing, and a client-report generator that renders DIRA JSON to HTML).
- `GO-LIVE.md` and an expanded `launch/` — staged publication runbook and launch copy.

## 1.2.0 — 2026-07-29

Fixed
- **False positive: an uncommitted `.env` was reported as a critical breach.** The config
  scanner matched dangerous filenames on disk and never consulted git, so the ordinary
  developer habit of keeping a local `.env` produced `config/committed-secret-file` at
  CRITICAL — a finding whose title ("committed to the repo") was simply untrue. It graded a
  clean repo **F**. The scanner now takes git's index into account: a tracked file still
  reports critical, while an untracked one reports the honest, actionable
  `config/untracked-secret-file` at medium ("present and not ignored — one `git add` from
  being committed"). Targets that are not git repos are unchanged, since there is no index
  to check against.
- **False negative: manifests without a lockfile were silently skipped.** Only lockfiles were
  parsed, so a `package.json` with no `package-lock.json` produced `0 deps` and a clean CVE
  result — "not checked" was indistinguishable from "checked and safe". New
  `deps/unresolved-manifest` finding names the manifest, counts its declared dependencies,
  and states which ecosystem went unscanned. Covers `package.json`, `pyproject.toml`,
  `Gemfile`, and `Cargo.toml`; silent once a lockfile is present.
- `config/committed-secret-file` now reports at line 0, so it deduplicates against the git
  scanner's `git/tracked-secret-file` instead of double-reporting the same file.
- `.pre-commit-config.yaml` referenced `rev: v1.0.0`, a tag that was never created.

## 1.1.0 — 2026-07-29

Added
- **Frontend rule pack**: secrets leaked through `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` build vars,
  auth tokens in localStorage, `dangerouslySetInnerHTML`, innerHTML sinks, wildcard `postMessage`,
  JWT `none` algorithm.
- **LLM/AI rule pack**: provider keys shipped to the browser (`dangerouslyAllowBrowser`),
  untrusted input concatenated into prompts, model output passed to an executor.
- **Cloud rule pack**: public Firebase rules, `"Principal": "*"` IAM policies, `*` action on `*`
  resource, GCP `allUsers` bindings, `curl | sh` installers.
- **`licenses` scanner**: per-dependency license resolution with copyleft classification and a
  license inventory in the terminal and HTML reports.
- **`dira sbom`**: CycloneDX 1.5 and SPDX 2.3 output.
- **`dira fix`**: safe, additive auto-remediation (dry-run by default) plus a manual checklist for
  everything a tool must not do for you.
- **`--diff REF`**: scan only files changed since a git ref — fast PR gating.
- `dira init` now generates a workflow that diffs on PRs, full-scans on push, uploads SARIF, and
  publishes an SBOM artifact.

Fixed
- **Git-history findings now carry real file attribution** (`prod.py @ 8f21ac3` instead of a mangled
  commit label) and are downgraded in test/fixture paths like every other scanner.
- **Config findings in test/fixture paths are now downgraded** the way secret findings already
  were — a deliberately-vulnerable test fixture is not a production incident.
- **`gcp-allusers` matched a bare substring**, so any file merely mentioning `allUsers` was flagged
  critical (including this scanner's own rule table). It now requires real IAM binding context.
- **Walker dropped root-level dotfiles.** `lstrip("./")` turned `.env` into `env`, which the default
  exclude list then swallowed — a committed `.env` was invisible to the file scanners. Regression
  test added.
- `LGPL-2.1` was classified as full GPL because it contains the substring `GPL-2`.
- Risk score now uses diminishing returns per severity and excludes process-maturity findings, and
  the grade is capped by the worst live severity (any critical ⇒ F, any high ⇒ at best C).

## 1.0.0 — 2026-07-29

Initial release.

- Secret scanning: 20 provider patterns plus an entropy-gated generic rule, single-pass regex.
- Config/IaC scanning: Docker, docker-compose, Kubernetes, Terraform, GitHub Actions, and code-level
  rules (SQLi, shell injection, wildcard CORS, disabled TLS verification, eval/pickle, weak hashing).
- Dependency CVEs via OSV.dev for npm, PyPI, Go, crates.io, and RubyGems lockfiles.
- Git hygiene: history secret scanning, tracked credential files, remote-URL credentials.
- Live surface: TLS validity/expiry, security headers, cookie flags, HTTPS redirect, exposed paths.
- Startup security-readiness score across 18 weighted checks.
- Reports: terminal, HTML, JSON, SARIF 2.1.0, Markdown. Baselines with stable fingerprints.
- Packaging: PyPI (`dira-scan`), npm launcher (`npx dira-scan`), pre-commit hook, GitHub Action.
