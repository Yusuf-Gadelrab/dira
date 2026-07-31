# npm package copy — `dira-scan`

Two artifacts here: the one-line `description` field in `npm/package.json`, and the README
body that npm renders on the package page (`npm/README.md`).

---

## `description` field (currently in npm/package.json)

```
DIRA — zero-dependency security audit for startup codebases: secrets, dependency CVEs, misconfigurations, git-history leaks, live surface checks, and a startup security-readiness score.
```

Keep it. It is accurate and it matches the PyPI description, which is what you want for
search parity across registries.

---

## README body for the npm package page

> Paste everything below the rule into `npm/README.md`, replacing the current file.

---

# dira-scan

**Security audit for startup codebases. One command.**

```bash
npx dira-scan .
```

Secrets, dependency CVEs via OSV.dev, config and IaC misconfigurations, license risk,
git-history leaks, and live TLS and header checks — one run, one graded report, with the
exact fix for everything it finds.

## Requirements — read this first

**This package requires Python 3.9 or newer on your machine.**

`dira-scan` on npm is a thin launcher. DIRA itself is a zero-dependency Python tool; the npm
package is a small Node shim that finds a working Python runner and hands off to it. That is
deliberate — it means `npx dira-scan` works in a JavaScript repo without you adopting a
Python toolchain, but it does mean Python has to exist.

The shim tries, in order:

1. `python3 -m dira` (DIRA already installed)
2. `python -m dira`
3. `dira` on your `PATH`
4. `uvx --from dira-scan dira` (uses [uv](https://docs.astral.sh/uv/), no install)
5. `pipx run --spec dira-scan dira`

If none of those work you get an explicit error, not a stack trace:

```
dira: no working Python runner found (needs Python 3.9+).
  fastest:  brew install uv        # then re-run: npx dira-scan .
  or:       pipx install dira-scan
  or:       pip install dira-scan
```

macOS and most Linux distributions already ship Python 3. On Windows, install Python from
python.org or the Microsoft Store, or install `uv`. If you would rather skip the shim
entirely, `pipx install dira-scan` gives you the same binary directly.

## Usage

```bash
npx dira-scan .                          # human report
npx dira-scan . --only secrets,config    # fast pass, skips git history
npx dira-scan . --diff origin/main       # only files this branch touched
npx dira-scan . --offline                # no network at all
npx dira-scan . -t yourapp.com           # also audit the live domain
npx dira-scan . -f sarif -o dira.sarif   # GitHub code scanning
npx dira-scan . -f html -o report.html --open
```

Exit code is `1` when anything at or above `--fail-on` (default `high`) is found, so it drops
straight into CI. `--fail-on never` always exits `0`.

Both `dira` and `dira-scan` are installed as binaries, so `npx dira-scan` and a local
`node_modules/.bin/dira` both work.

## What it checks

| Scanner | What it finds |
|---|---|
| `secrets` | Provider credential patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, GCP, Slack, npm, DSNs, private keys) plus an entropy-gated generic rule. Values are redacted in every report. |
| `config` | Docker, compose, Kubernetes, Terraform, GitHub Actions, cloud IAM, frontend (`NEXT_PUBLIC_*` secrets, tokens in localStorage, innerHTML sinks, wildcard `postMessage`, JWT `none`), LLM apps, and server code (SQL by concatenation, `shell=True`, wildcard CORS, disabled TLS verification). |
| `deps` | Lockfile packages resolved against OSV.dev — npm, PyPI, Go, crates.io, RubyGems. No API key. |
| `git` | Secrets in commit history, tracked `.env`/`.pem`, credentials in the remote URL. |
| `surface` | TLS validity and expiry, security headers, cookie flags, publicly served `/.env` and `/.git/config`. |
| `licenses` | Per-dependency license resolution with copyleft classification. |
| `readiness` | An 18-check, 80-point startup security-readiness score. |

Plus `dira sbom` (CycloneDX 1.5 / SPDX 2.3) and `dira fix` (safe, additive remediations,
dry-run by default).

## Node-specific notes

- `engines`: Node 16 or newer.
- The launcher adds **zero npm dependencies**. It is one file using `node:child_process`.
- First `npx` run through the `uvx` or `pipx` fallback path downloads the Python package, so
  it takes a few seconds. Subsequent runs are cached by uv or pipx.
- In CI, prefer `pipx install dira-scan` or the GitHub Action
  (`uses: Yusuf-Gadelrab/dira@v1`) over `npx` — one less resolution layer to fail.

## Limitations

Pattern analysis, not a pentest. No dataflow or taint analysis, so anything routed through an
intermediate variable is missed — Semgrep is the right tool if you need that. Regex secret
detection has an irreducible error rate; entropy gating and path downgrading reduce noise but
do not eliminate it. Live surface checks are a handful of unauthenticated GETs, not a DAST
scan. The readiness score verifies that controls are present, not that they work.

A clean run means "no known bad patterns in this repo", not "secure".

Only scan domains you own or have written permission to test.

## License

MIT © Yusuf Gadelrab · <https://github.com/Yusuf-Gadelrab/dira>
