PRODUCT NAME:
DIRA

TAGLINE (59 chars):
Zero-dependency security audit for startup codebases

DESCRIPTION:

DIRA is a single-command security scanner for startup codebases. It checks for
hardcoded secrets, dependency CVEs (via OSV.dev), config/IaC misconfigurations
across Docker, Terraform, GitHub Actions, cloud IAM, and frontend/LLM-app
code, dependency license risk, secrets buried in git history, and live TLS +
security-header issues on a domain — then prints a graded report, an 18-point
startup security-readiness score, and a CycloneDX/SPDX SBOM.

It's pure Python standard library — no runtime dependencies — so install is a
single `pipx install` with no dependency tree to resolve. Built for the gap
between "$2k/mo enterprise security platform" and "five separate CLIs you have
to individually wire into CI." A clean run means "no known bad patterns
found" — it's a fast first pass, not a replacement for a real pentest, threat
model, or tools like Semgrep/Snyk/gitleaks, and the README says so directly.

MIT licensed, Python 3.9+, 98 tests passing. PyPI (`dira-scan`) and npm
(`dira-scan`) packages are built and ready but not published yet — install
from source or the GitHub release wheel for now.

FEATURES:
- Seven scanners in one run: secrets, dependency CVEs, config/IaC misconfig, license risk, git-history leaks, live TLS/header checks, startup-readiness score
- Zero runtime dependencies — pure Python stdlib, installs with pipx and nothing else
- Reports in terminal, JSON, SARIF 2.1.0 (GitHub code scanning), and Markdown (PR comments)
- CycloneDX 1.5 / SPDX 2.3 SBOM generation from the same lockfile parse
- `dira fix` applies safe, additive remediations only — dry-run by default, --apply to write
- `--diff <ref>` and a baseline mode make it fast enough for PR gating, not just full scans
- Ships a GitHub Action and pre-commit hook via `dira init`

MAKER COMMENT (first comment):

Hey — I'm Yusuf, CS undergrad at SJSU, built DIRA solo. I kept running into the same problem on
small projects: "is this safe enough to show a customer/auditor" has no cheap fast answer, just
either an expensive platform or a pile of individual CLIs nobody has time to wire together on a
weekend project. DIRA is my attempt at the fast, honest version of that — one command, redacted
findings so the report is shareable as-is, and a README that's upfront about what it does not catch
(no dataflow analysis, regex-based secret detection has real false positives, live-surface checks
are a handful of GETs not a real DAST scan). Not trying to replace Semgrep or Snyk — trying to be
the thing you run before you'd ever justify paying for either. Would love feedback, especially on
where the config/IaC rule pack (shipped this week) has gaps.

SUGGESTED TOPICS/TAGS:
Developer Tools, Security, Open Source, Python, DevOps, SaaS Tools, GitHub
