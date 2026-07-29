# Changelog

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
