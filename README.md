<div align="center">

# DIRA · درع

**Security audit for startup codebases.** One command, zero dependencies.

`secrets` · `dependency CVEs` · `misconfigurations` · `licenses` · `git-history leaks` · `live surface` · `SBOM` · `readiness score`

[![CI](https://github.com/Yusuf-Gadelrab/dira/actions/workflows/tests.yml/badge.svg)](https://github.com/Yusuf-Gadelrab/dira/actions/workflows/tests.yml)
[![Tests](https://img.shields.io/badge/tests-98%20passing-d4af37)](tests/)
[![License: MIT](https://img.shields.io/badge/license-MIT-d4af37)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-d4af37)](pyproject.toml)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0-d4af37)](pyproject.toml)

</div>

---

DIRA is a zero-dependency Python security scanner for startup codebases that finds hardcoded
secrets, dependency CVEs, misconfigurations, license risk, and git-history leaks in one command,
then prints a security-readiness score, an SBOM, and the exact fix for everything it finds.

Most startup security tooling is either a $2k/mo platform or five separate CLIs you never wire up.
DIRA answers the question a founder actually gets asked — *"is this codebase safe enough to sell to
an enterprise?"* — with a single command and no install footprint.

```bash
pipx install git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0
dira scan .                        # scan the current project
dira scan . -t yourapp.com         # + audit the live domain
dira scan . -f html -o report.html --open
```

## What it checks

| Scanner | What it finds |
|---|---|
| `secrets` | 24 credential patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, GCP, Slack, npm, DSNs, private keys) plus an entropy-gated generic rule. Values are **redacted** in every report. |
| `config` | 38 rules across Docker (root user, `:latest`, build-ARG secrets), compose/k8s (`privileged`, hostPath), Terraform (`0.0.0.0/0`, public buckets, unencrypted storage), GitHub Actions (`pull_request_target`, mutable action refs, script injection), cloud (public Firebase rules, `"Principal": "*"`, GCP `allUsers`, `curl \| sh`), frontend (`NEXT_PUBLIC_*` secrets, tokens in localStorage, innerHTML/`dangerouslySetInnerHTML`, wildcard `postMessage`, JWT `none`), LLM apps (`dangerouslyAllowBrowser`, prompt concatenation, model output piped to an executor), and server code (SQLi by concatenation, `shell=True`, wildcard CORS, disabled TLS verification, `eval`/`pickle`, weak password hashing, debug mode on). |
| `deps` | Every package in your lockfiles resolved against **OSV.dev** — npm, PyPI, Go, crates.io, RubyGems. Batched, free, no API key, with CVSS-estimated severity and the exact fixed version. |
| `git` | Secrets buried in commit history (deleting the file does not rotate the key), tracked `.env`/`.pem`/keystores, credentials in the remote URL, `.gitignore` gaps. |
| `surface` | Live domain: TLS validity + expiry, HSTS/CSP/nosniff/frame-options, cookie flags, HTTP→HTTPS redirect, version-disclosure headers, and publicly served `/.env`, `/.git/config`, `/actuator/env`. |
| `licenses` | Every dependency's license resolved from npm/PyPI, classified into permissive, file-level copyleft (MPL/LGPL), strong copyleft (GPL), and network copyleft (AGPL/SSPL) — with a license inventory for your diligence folder. |
| `readiness` | An 18-check, 80-point **startup security-readiness score** (reported as a percentage) modelled on what SOC 2 auditors and enterprise security questionnaires actually ask for — lockfiles, Dependabot, CI, tests, secret scanning, SAST, CODEOWNERS, SECURITY.md, IaC, observability, incident response, backups, privacy. |

Every finding carries a severity, a location, redacted evidence, a concrete remediation, and a CWE/OSV reference.

## How this compares

DIRA does five things in one command. Each one has a dedicated tool that does that specific thing
better. Use both — DIRA isn't trying to replace any of these, and says so on purpose:

| | DIRA | gitleaks | trufflehog | semgrep |
|---|---|---|---|---|
| Secret detection | Pattern + entropy, redacted | Pattern-based, more mature ruleset | Pattern **+ live verification** against the provider | Not its focus |
| Dependency CVEs (OSV.dev) | Yes, 5 ecosystems | No | No | No (Semgrep Supply Chain is a separate paid product) |
| Config/IaC misconfig | Yes, 38 rules | No | No | Yes — with real dataflow analysis DIRA does not have |
| Git-history leak scanning | Yes | Yes — this is its whole job, more mature | Yes | No |
| License risk / SBOM | Yes (CycloneDX + SPDX) | No | No | No |
| Dataflow / taint analysis | **No** — pattern matching only | No | No | **Yes** — this is semgrep's core strength |
| Verified (not just matched) secrets | **No** | No | **Yes** | No |
| Startup-readiness score | Yes, 18 checks / 80 pts | No | No | No |
| Install | pipx/uvx, **zero dependencies** | single Go binary | single Go binary | pip/brew, has dependencies |

**Honest read:** if secrets are your only concern, gitleaks and trufflehog are more mature at
exactly that, and trufflehog verifies a key against the live provider — DIRA does not. If you need
real dataflow analysis, semgrep is a different and deeper tool; DIRA finds *sinks*
(`innerHTML =`, SQL built by concatenation, `shell=True`), not proven, traced vulnerabilities. What
DIRA has that none of the three above do: dependency-license risk, an SBOM, and a readiness score
modeled on what an enterprise security questionnaire actually asks — because most of the time the
question isn't "what's broken in this file," it's "can we pass procurement."

## Sample output

A real run against a small demo project with a hardcoded Stripe key, string-concatenated SQL,
disabled TLS verification, a root Docker user, and an outdated `lodash`:

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
      → Revoke the key at the provider, issue a new one, move it to a secret manager, and purge it from git history (git filter-repo / BFG).

  ─── HIGH ──────────────────────────────────────────────────────────────
  ● SQL built by string concatenation
      src/app.py:4  execute("SELECT * FROM users WHERE id = " +
      → Use parameterized queries / bound placeholders.

  ● TLS verification disabled
      src/app.py:5  verify=False
      → Never disable certificate verification; pin a CA bundle instead.

  ─── MEDIUM ────────────────────────────────────────────────────────────
  ● GitHub Action pinned to a mutable ref
      .github/workflows/ci.yml:6  - uses: actions/checkout@v4
      → Pin third-party actions to a full commit SHA — tags are mutable and are a live supply-chain risk.

  ● Container runs as root
      Dockerfile:1  no non-root USER directive
      → Create an unprivileged user and add `USER app` before CMD/ENTRYPOINT.

  16 files · 1 deps · 1.8s
```

Note the redaction — `sk_l************nZaQ`. DIRA never writes a full credential into a report,
so the HTML and SARIF output are safe to share with a customer or attach to a ticket.

## Install

```bash
# from source (available now)
pipx install git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0
uvx --from git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0 dira scan .
pip install git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0

# or grab the wheel from the release
pipx install https://github.com/Yusuf-Gadelrab/dira/releases/download/v1.2.0/dira_scan-1.2.0-py3-none-any.whl
```

> **Registry status:** the PyPI (`dira-scan`) and npm (`npx dira-scan`) packages are built and
> ready but not published yet. Until they are, install from source or the release wheel above.

## Use it

```bash
dira scan .                        # human report
dira scan . --verbose              # every occurrence + the readiness checklist
dira scan . --only secrets,config  # fast pre-commit-grade pass
dira scan . --diff origin/main     # only files changed on this branch (PR gate)
dira scan . --offline              # air-gapped: no OSV, no live checks
dira scan . -f sarif -o dira.sarif # GitHub code scanning
dira scan . -f markdown            # paste into a PR
dira scan . -f html -o report.html --open   # client-shareable audit
dira baseline .                    # accept today's debt, fail only on new issues
dira rules                         # every rule, printed
dira init                          # install CI workflow + pre-commit hook
dira sbom . -f cyclonedx -o sbom.json   # CycloneDX 1.5 (or -f spdx for SPDX 2.3)
dira fix .                         # preview the safe remediations
dira fix . --apply --contact you@yourdomain.com
```

Exit code is `1` when anything at or above `--fail-on` (default `high`) is found, so it drops
straight into CI. `--fail-on never` always exits `0`.

### GitHub Actions

```yaml
- uses: Yusuf-Gadelrab/dira@v1.2.0   # or @v1 — a moving major tag
  with:
    fail-on: high
    target: yourapp.com
```

Or use the SARIF path so findings land in the Security tab — `dira init` writes that workflow for you.

### pre-commit

```yaml
repos:
  - repo: https://github.com/Yusuf-Gadelrab/dira
    rev: v1.2.0
    hooks:
      - id: dira
```

### `dira fix` — the boring 80%

Additive, reversible changes only:

- appends the secret patterns your `.gitignore` is missing;
- writes `SECURITY.md` with a real disclosure SLA;
- writes `.github/dependabot.yml` for every ecosystem it detects;
- derives `.env.example` from your `.env` — **names only, values never copied**;
- writes `docs/INCIDENT-RESPONSE.md` (severities, first 30 minutes, 72-hour notification);
- publishes `/.well-known/security.txt` for static sites.

It never touches application code, never rewrites git history, and never rotates a key —
those are printed as a checklist, because a tool that silently "fixes" a leaked credential
is lying to you. Dry-run by default; `--apply` writes.

### `dira sbom` — because enterprise buyers ask

CycloneDX 1.5 or SPDX 2.3, generated from the same lockfile parse the CVE scan already did,
with correct package URLs (`pkg:npm/%40scope/pkg@1.0.0`). Costs one extra second.

### As a library

```python
from dira import scan

result = scan(Path("."), offline=True)
print(result.grade(), result.risk_score(), result.readiness["score"])
for f in result.findings:
    print(f.severity, f.path, f.title, f.remediation)
```

## Why it's fast

- **One walk, two regexes.** The 24 secret patterns compile into a single alternation, so each file is read once rather than matched once per rule. A second pass over the 23 provider-specific patterns runs alongside it, because regex alternation is leftmost-first and would otherwise let the broad generic rule shadow a specific one on the same line (`API_KEY = "sk_live_…"` must report as a Stripe key, not as a generic credential).
- **Incremental cache.** `.dira-cache.json` keys results on `(size, mtime, ruleset version)`; an unchanged file is never re-read. Measured on a 117-file repo, the file-scanning phase drops from 1.56s to 0.05s on the second run. Note this caches *file* scanning only — git-history scanning is not cached and dominates a full run on a repo with deep history, so use `--only secrets,config` (or `--history 0`) for the fast inner-loop pass.
- **Parallel by default.** File scanning and OSV detail lookups run on a thread pool sized to your CPU.
- **Batched network.** Up to 900 packages per OSV request, advisory details fetched concurrently and capped.
- **Cheap skips.** Vendor/build directories, `.gitignore` entries, binaries, and files >2 MB are excluded before any I/O.
- **Diff mode.** `--diff origin/main` scans only what the branch touched — a PR gate that finishes before the test job starts.

## Noise control

False positives are the reason security tools get uninstalled, so DIRA:

- ignores placeholders, `os.environ[...]`, `${VAR}`, `changeme`, `xxxx`, and low-entropy values;
- gates the generic credential rule on Shannon entropy ≥ 3.4;
- **downgrades** — rather than hides — hits inside `tests/`, `fixtures/`, docs, and `.env.example`;
- deduplicates overlapping rules on the same line — when a provider-specific rule names a credential, the generic catch-all is suppressed rather than reported twice;
- supports `.diraignore` (same syntax as `.gitignore`) and stable per-finding fingerprints, so `dira baseline` suppresses today's debt without hiding tomorrow's regressions.

## Limits — read these

Automated pattern analysis. It does **not** replace a penetration test, a threat model, or a real
SOC 2 audit, and it cannot see your cloud IAM, your MFA posture, or your access reviews (those are
listed as manual attestations in the report). A clean DIRA run means "no known bad patterns in this
repo", not "secure".

Scanning a domain you do not own or have permission to test may be unlawful. `--target` performs
unauthenticated GETs on a handful of well-known paths — point it at your own infrastructure only.

## Contributing

False positives and false negatives on real repositories are the single most useful thing you can
report — open an issue with the file/line (redact any real value first). See `CONTRIBUTING.md` for
the dev setup and ground rules (zero runtime dependencies, no compliance-claim copy, every rule
needs a false-positive test alongside it), `SECURITY.md` to report a vulnerability in DIRA itself
(not a public issue), and `CODE_OF_CONDUCT.md` for how the project is run.

## License

MIT © Yusuf Gadelrab

---

## About the author

Built by **Yusuf Gadelrab** — computer science student at San José State University (BS Computer Science, expected May 2028), AI/ML builder, and co-author of two peer-reviewed SIGCSE Technical Symposium 2026 papers on computer science education ([DOI 10.1145/3770761.3777339](https://doi.org/10.1145/3770761.3777339)).

- Portfolio: <https://yusuf-gadelrab.github.io/>
- About / FAQ: <https://yusuf-gadelrab.github.io/about.html>
- Guides: <https://yusuf-gadelrab.github.io/guides.html>
- Contact: yusuf.gadelrab06@gmail.com
