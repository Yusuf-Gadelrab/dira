# GitHub Marketplace listing — DIRA security scan

Everything below is verified against the real `action.yml` at the repo root as of v1.2.0.
Mismatches between the marketing copy and the actual action are flagged in the last section
rather than papered over.

---

## Listing fields

**Name**
```
DIRA security scan
```
(Must match the `name:` in `action.yml`. It does.)

**Tagline** (under 125 chars)
```
Secrets, dependency CVEs, misconfigurations, and a startup security-readiness score. One step, zero dependencies.
```

**Primary category:** Code quality
**Secondary category:** Security

**Branding** (already set in `action.yml`, do not change without re-verifying):
```yaml
branding:
  icon: shield
  color: yellow
```
`shield` is a valid Feather icon and `yellow` is a valid Marketplace color, so the listing
form will accept this as-is. The icon and color are what render on the Marketplace card, so
changing them changes the card art.

---

## Description

Run one step and get an answer to the question every enterprise buyer asks: is this codebase
safe enough to ship to us?

DIRA scans your repository for hardcoded secrets, dependency CVEs resolved against OSV.dev,
config and IaC misconfigurations across Docker, Kubernetes, Terraform, GitHub Actions, and
cloud IAM, frontend and LLM-application patterns, dependency license risk, and secrets buried
in git history — then grades the result and scores it against an 18-check startup security
readiness model.

It has no runtime dependencies. DIRA is pure Python standard library, which keeps the
supply-chain surface of your security step near zero and keeps the step fast.

Output is SARIF by default, so findings land in your repository's Security tab through
`github/codeql-action/upload-sarif` with no glue code. Markdown, JSON, HTML, and terminal
formats are also available. Every finding carries a severity, a location, redacted evidence,
a concrete remediation, and a CWE or OSV reference — credentials are always masked, so the
report is safe to attach to a ticket or share with a customer.

DIRA is a fast, honest first pass. It is not a penetration test and not a replacement for
dataflow-aware SAST like Semgrep. A clean run means "no known bad patterns in this repo".

---

## Inputs

Pulled directly from `action.yml`. These six are the complete set — there are no others.

| Input | Required | Default | Description |
|---|---|---|---|
| `path` | no | `.` | Directory to scan. |
| `target` | no | `''` | Optional live domain to audit (headers, TLS, exposed paths). Only point this at infrastructure you own. |
| `fail-on` | no | `high` | Fail the job at or above this severity: `critical`, `high`, `medium`, `low`, `info`, `never`. |
| `format` | no | `sarif` | Report format: `sarif`, `json`, `markdown`, `html`, `terminal`. |
| `output` | no | `dira.sarif` | Report output path. |
| `baseline` | no | `''` | Path to a DIRA baseline file, so the job fails only on findings newer than the baseline. |

## Outputs

| Output | Description |
|---|---|
| `report` | Path to the generated report. Echoes the `output` input. |

## Runs

Composite action. It `pip install`s DIRA on the runner and invokes `dira scan`. The runner
therefore needs Python 3.9+ with `pip` on `PATH` — true by default on all GitHub-hosted
runners. On self-hosted or minimal runners, add `actions/setup-python@v5` before this step.

---

## Copy-pasteable workflow

Full example: PR runs a fast diff gate, pushes to the default branch run a full scan and
upload SARIF to code scanning, and a weekly schedule catches newly disclosed CVEs in code
nobody touched.

```yaml
name: security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 13 * * 1'   # Mondays, catches newly published advisories

permissions:
  contents: read
  security-events: write   # required for upload-sarif

jobs:
  dira:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # DIRA scans git history and --diff needs the base ref

      - name: DIRA security scan
        uses: Yusuf-Gadelrab/dira@v1
        with:
          fail-on: high
          format: sarif
          output: dira.sarif

      - name: Upload to GitHub code scanning
        if: always()       # upload findings even when the scan fails the job
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dira.sarif
          category: dira

      - name: Keep the report as an artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: dira-report
          path: dira.sarif
```

Two details that matter:

- `fetch-depth: 0`. The default shallow checkout gives DIRA one commit of history, so the
  git-history scanner finds nothing and `--diff` has no base to compare against.
- `if: always()` on the upload step. Without it, a failing scan skips the upload and you lose
  exactly the findings you wanted to see.

### PR gate on changed files only

`--diff` scans only what the branch touched, which finishes in seconds. **The action does not
expose a `diff` input** (see mismatches below), so run the CLI directly for this job:

```yaml
  dira-pr-gate:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - run: pip install --quiet dira-scan==1.2.0

      - name: Scan only what this PR changed
        run: |
          dira scan . \
            --diff "origin/${{ github.base_ref }}" \
            --fail-on high \
            --format markdown \
            --output dira-pr.md

      - name: Comment the report on the PR
        if: always()
        run: gh pr comment "${{ github.event.number }}" --body-file dira-pr.md
        env:
          GH_TOKEN: ${{ github.token }}
```

That job needs `pull-requests: write` in `permissions` for the comment step.

### Live domain audit

```yaml
      - uses: Yusuf-Gadelrab/dira@v1
        with:
          target: yourapp.com
          fail-on: critical
```

Only against a domain you own. `target` performs unauthenticated GETs against well-known
paths, and pointing that at infrastructure you do not control may be unlawful.

### Baseline mode for an existing codebase

Adopting a scanner on a mature repo produces a wall of pre-existing findings. Generate a
baseline once, commit it, and fail only on new issues:

```bash
pipx install dira-scan
dira baseline .                 # writes .dira-baseline.json
git add .dira-baseline.json && git commit -m "chore: dira baseline"
```

```yaml
      - uses: Yusuf-Gadelrab/dira@v1
        with:
          baseline: .dira-baseline.json
          fail-on: high
```

---

## Publishing the listing

The Marketplace listing is published from the **release UI**, not from a command:

1. `action.yml` must be at the repository root with `name`, `description`, and `branding`.
   Verified present.
2. The repository must be public and must contain a README. Verified.
3. Go to the repository → **Releases** → draft or edit the release for the tag → check
   **Publish this Action to the GitHub Marketplace**.
4. Accept the GitHub Marketplace Developer Agreement (one-time, account-level).
5. Pick the two categories above, confirm the icon and color preview, publish the release.

There is no `gh` command for this step. It is a manual UI action, once.

---

## Mismatches found against the real `action.yml`

Flagging rather than inventing. None of these are blocking, but the copy above is written to
be true today.

1. **No `diff` input.** The README and the marketing copy both promote `--diff` as a PR gate,
   but `action.yml` exposes only `path`, `target`, `fail-on`, `format`, `output`, `baseline`.
   There is no way to run a diff-scoped scan through the action. The workflow above works
   around it by invoking the CLI directly. Worth adding `diff`, `only`, `skip`, and `offline`
   inputs in 1.3.0 — each is a one-line passthrough in the same style as `baseline`.

2. **The action installs from git, not from PyPI.** Line 34 is
   `pip install --quiet "git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0"`. That is correct
   today because the package is unpublished, but it makes every CI run clone the repo. Once
   `dira-scan` is on PyPI this must become `pip install --quiet "dira-scan==1.2.0"` — it is
   already in the go-live checklist as a required edit.

3. **The version is pinned inside the action.** `action.yml` hardcodes `@v1.2.0` in its own
   install line, so cutting a `v1.3.0` tag without editing that line ships an action that
   silently installs 1.2.0. Add it to the release checklist.

4. **The `v1` moving tag currently points at v1.1.0.** The README advertises
   `uses: Yusuf-Gadelrab/dira@v1`, so anyone using the documented form gets the release with
   the `.env` false-positive bug fixed in 1.2.0. Moving the tag is in the go-live checklist.

5. **No `actions/setup-python` in the composite action.** It relies on the runner's ambient
   Python. Fine on GitHub-hosted runners, a silent failure on minimal self-hosted ones. The
   description above says so explicitly rather than hiding it.

6. **Checked and clean:** the `[ -n "..." ] && args+=(...)` lines in the composite step do
   *not* abort the step under `bash -eo pipefail` when the input is empty. Bash suppresses
   `set -e` for a non-final command in an AND list, and the `dira scan` line that follows
   still runs. Verified by execution, not by reading.
