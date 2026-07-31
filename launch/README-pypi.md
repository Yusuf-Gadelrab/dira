# DIRA

**Security audit for startup codebases. One command, zero dependencies.**

`secrets` · `dependency CVEs` · `misconfigurations` · `licenses` · `git-history leaks` · `live surface` · `SBOM` · `readiness score`

---

## The problem

A founder gets one question from every enterprise buyer, every diligence call, and every
security questionnaire: *is this codebase safe enough to sell to us?*

The honest answers available today are a $2k/month platform you cannot justify at seed stage,
or five separate CLIs — gitleaks, Semgrep, an SCA tool, a TLS checker, an SBOM generator —
that you have to install, configure, and wire into CI before any of them tell you anything.
Most teams do neither, and find out what was in the repo when someone else finds it first.

DIRA is the fast first pass. One command, no account, no API key, no dependency tree.

## One command

```bash
pipx install dira-scan
dira scan .
```

That is the whole demo. It reads the repo, resolves your lockfiles against OSV.dev, walks
your git history, and prints a graded report with the exact fix for everything it finds.

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                   DIRA                                   ║
║                    درع · security audit for startups                     ║
╚══════════════════════════════════════════════════════════════════════════╝

  Target  /tmp/demo

  SECURITY GRADE   F   risk 100/100
  STARTUP READINESS 18%  Pre-security  (14/80 pts)

  CRITICAL 2  HIGH 5  MEDIUM 8  LOW 9  INFO 5

  ─── CRITICAL ──────────────────────────────────────────────────────────
  ● lodash 4.17.11 — CVE-2019-10744: Prototype Pollution in lodash
      package-lock.json  npm:lodash@4.17.11
      → Upgrade lodash to 4.17.12 or later.

  ● Stripe secret/restricted key
      src/app.py:2  sk_l************nZaQ
      → Revoke the key at the provider, issue a new one, move it to a secret
        manager, and purge it from git history (git filter-repo / BFG).

  ─── HIGH ──────────────────────────────────────────────────────────────
  ● SQL built by string concatenation
      src/app.py:4  execute("SELECT * FROM users WHERE id = " +
      → Use parameterized queries / bound placeholders.

  16 files · 1 deps · 1.8s
```

Note the redaction — `sk_l************nZaQ`. DIRA never writes a full credential into a
report, so the HTML and SARIF output are safe to attach to a ticket or hand to a customer.

## What it checks

| Scanner | What it finds |
|---|---|
| `secrets` | Provider-specific credential patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, GCP, Slack, npm, database DSNs, private keys) plus an entropy-gated generic rule. Values are redacted in every report. |
| `config` | Rules across Docker (root user, `:latest`, build-ARG secrets), compose and Kubernetes (`privileged`, hostPath), Terraform (`0.0.0.0/0`, public buckets, unencrypted storage), GitHub Actions (`pull_request_target`, mutable action refs, script injection), cloud IAM (public Firebase rules, `"Principal": "*"`, GCP `allUsers`), frontend (`NEXT_PUBLIC_*` secrets, tokens in localStorage, innerHTML sinks, wildcard `postMessage`, JWT `none`), LLM apps (`dangerouslyAllowBrowser`, prompt concatenation, model output piped to an executor), and server code (SQL by concatenation, `shell=True`, wildcard CORS, disabled TLS verification, `eval`/`pickle`, weak password hashing, debug mode on). |
| `deps` | Every package in your lockfiles resolved against **OSV.dev** — npm, PyPI, Go, crates.io, RubyGems. Batched, free, no API key, with severity and the exact fixed version. |
| `git` | Secrets buried in commit history (deleting the file does not rotate the key), tracked `.env`/`.pem`/keystores, credentials in the remote URL, `.gitignore` gaps. |
| `surface` | Live domain: TLS validity and expiry, HSTS/CSP/nosniff/frame-options, cookie flags, HTTP→HTTPS redirect, version-disclosure headers, and publicly served `/.env`, `/.git/config`, `/actuator/env`. |
| `licenses` | Every dependency's license resolved from npm and PyPI, classified into permissive, file-level copyleft (MPL/LGPL), strong copyleft (GPL), and network copyleft (AGPL/SSPL), with an inventory for your diligence folder. |
| `readiness` | An 18-check, 80-point startup security-readiness score modelled on what SOC 2 auditors and enterprise questionnaires actually ask for — lockfiles, Dependabot, CI, tests, secret scanning, SAST, CODEOWNERS, SECURITY.md, IaC, observability, incident response, backups, privacy. |

Every finding carries a severity, a location, redacted evidence, a concrete remediation, and
a CWE or OSV reference.

## Install

```bash
pipx install dira-scan          # isolated, recommended
uvx dira-scan scan .            # no install at all
pip install dira-scan           # into the current environment
npx dira-scan .                 # Node shim; still needs Python 3.9+
```

Requires Python 3.9 or newer. Nothing else — DIRA has no runtime dependencies and imports
only the standard library, which is a deliberate choice for a tool whose job is reducing
your supply-chain surface.

## Use it

```bash
dira scan .                        # human report
dira scan . --verbose              # every occurrence + the readiness checklist
dira scan . --only secrets,config  # fast pre-commit-grade pass
dira scan . --diff origin/main     # only files this branch touched (PR gate)
dira scan . --offline              # air-gapped: no OSV, no live checks
dira scan . -t yourapp.com         # also audit the live domain
dira scan . -f sarif -o dira.sarif # GitHub code scanning
dira scan . -f markdown            # paste into a PR
dira scan . -f html -o report.html --open   # client-shareable audit
dira baseline .                    # accept today's debt, fail only on new issues
dira rules                         # every rule, printed
dira init                          # install CI workflow + pre-commit hook
dira sbom . -f cyclonedx -o sbom.json       # CycloneDX 1.5 (or -f spdx)
dira fix .                         # preview the safe remediations
```

Exit code is `1` when anything at or above `--fail-on` (default `high`) is found, so it drops
straight into CI. `--fail-on never` always exits `0`.

### In CI

```yaml
- uses: Yusuf-Gadelrab/dira@v1
  with:
    fail-on: high
    format: sarif
    output: dira.sarif
```

### As a pre-commit hook

```yaml
repos:
  - repo: https://github.com/Yusuf-Gadelrab/dira
    rev: v1.2.0
    hooks:
      - id: dira
```

### As a library

```python
from pathlib import Path
from dira import scan

result = scan(Path("."), offline=True)
print(result.grade(), result.risk_score(), result.readiness["score"])
for f in result.findings:
    print(f.severity, f.path, f.title, f.remediation)
```

## Why it is fast

- **One walk, one alternation.** The provider secret patterns compile into a single regex
  alternation, so each file is read once rather than matched once per rule. A second pass
  over the provider-specific patterns runs alongside it, because alternation is
  leftmost-first and would otherwise let the broad generic rule shadow a specific one on the
  same line — `API_KEY = "sk_live_…"` must report as a Stripe key, not a generic credential.
- **Incremental cache.** `.dira-cache.json` keys results on `(size, mtime, ruleset version)`;
  an unchanged file is never re-read. On a 117-file repo the file-scanning phase drops from
  1.56s to 0.05s on the second run. This caches file scanning only — git-history scanning is
  not cached and dominates a full run on a repo with deep history, so use
  `--only secrets,config` or `--history 0` for the fast inner-loop pass.
- **Parallel by default.** File scanning and OSV detail lookups run on a thread pool sized to
  your CPU.
- **Batched network.** Up to 900 packages per OSV request, advisory details fetched
  concurrently and capped.
- **Cheap skips.** Vendor and build directories, `.gitignore` entries, binaries, and files
  over 2 MB are excluded before any I/O.

## Noise control

False positives are why security tools get uninstalled, so DIRA:

- ignores placeholders, `os.environ[...]`, `${VAR}`, `changeme`, `xxxx`, and low-entropy values;
- gates the generic credential rule on Shannon entropy;
- downgrades rather than hides hits inside `tests/`, `fixtures/`, docs, and `.env.example`;
- deduplicates overlapping rules on the same line, so a provider-specific hit suppresses the
  generic catch-all instead of double-reporting;
- supports `.diraignore` (same syntax as `.gitignore`) and stable per-finding fingerprints,
  so `dira baseline` suppresses today's debt without hiding tomorrow's regressions.

The rule set is tuned against real repositories rather than synthetic fixtures, and every
release that changes precision says so in the changelog.

## Limitations — read these

DIRA is automated pattern analysis. It does **not** replace a penetration test, a threat
model, or a SOC 2 audit.

- **No dataflow analysis.** Rules are pattern-based, not taint-tracking or CFG-based. Anything
  routed through an intermediate variable or a helper function will be missed. If you need
  dataflow-aware SAST, use Semgrep — DIRA is not a substitute for it.
- **Regex secret detection has an irreducible error rate.** Entropy gating and path
  downgrading reduce noise; they do not eliminate it.
- **Severity for dependency findings is derived from the source advisory**, so its accuracy is
  bounded by how complete that OSV record is.
- **Live surface checks are a handful of unauthenticated GETs**, not a DAST scan or a crawl.
- **The readiness score is a checklist proxy.** It verifies that controls are present, not
  that they work. Cloud IAM, MFA posture, and access reviews are listed as manual
  attestations, because a static scanner cannot see them.
- Scanning a domain you do not own or have written permission to test may be unlawful.
  Point `--target` at your own infrastructure only.

A clean DIRA run means "no known bad patterns in this repo". It does not mean "secure".

## License

MIT © Yusuf Gadelrab

- Repository: <https://github.com/Yusuf-Gadelrab/dira>
- Issues: <https://github.com/Yusuf-Gadelrab/dira/issues>
- Project page: <https://yusuf-gadelrab.github.io/dira.html>
