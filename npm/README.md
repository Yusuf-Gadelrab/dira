<div align="center">

# DIRA · درع

**Security audit for startup codebases.** One command, zero dependencies.

`secrets` · `dependency CVEs` · `misconfigurations` · `git-history leaks` · `live surface` · `readiness score`

</div>

---

Most startup security tooling is either a $2k/mo platform or five separate CLIs you never wire up.
DIRA is one binary-free Python command that answers the question a founder actually gets asked —
*"is this codebase safe enough to sell to an enterprise?"* — and prints the exact fix for everything
it finds.

```bash
uvx dira-scan .                       # scan the current project
uvx dira-scan . -t yourapp.com        # + audit the live domain
uvx dira-scan . -f html -o report.html --open
```

## What it checks

| Scanner | What it finds |
|---|---|
| `secrets` | 20 credential patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, GCP, Slack, npm, DSNs, private keys) plus an entropy-gated generic rule. Values are **redacted** in every report. |
| `config` | Docker (root user, `:latest`, build-ARG secrets), compose/k8s (`privileged`, hostPath), Terraform (`0.0.0.0/0`, public buckets, unencrypted storage), GitHub Actions (`pull_request_target`, mutable action refs, script injection), and code-level issues (SQLi by concatenation, `shell=True`, wildcard CORS, disabled TLS verification, `eval`/`pickle`, weak password hashing, debug mode on). |
| `deps` | Every package in your lockfiles resolved against **OSV.dev** — npm, PyPI, Go, crates.io, RubyGems. Batched, free, no API key, with CVSS-estimated severity and the exact fixed version. |
| `git` | Secrets buried in commit history (deleting the file does not rotate the key), tracked `.env`/`.pem`/keystores, credentials in the remote URL, `.gitignore` gaps. |
| `surface` | Live domain: TLS validity + expiry, HSTS/CSP/nosniff/frame-options, cookie flags, HTTP→HTTPS redirect, version-disclosure headers, and publicly served `/.env`, `/.git/config`, `/actuator/env`. |
| `readiness` | An 18-point **startup security-readiness score** modelled on what SOC 2 auditors and enterprise security questionnaires actually ask for — lockfiles, Dependabot, CI, tests, secret scanning, SAST, CODEOWNERS, SECURITY.md, IaC, observability, incident response, backups, privacy. |

Every finding carries a severity, a location, redacted evidence, a concrete remediation, and a CWE/OSV reference.

## Install

```bash
uvx dira-scan .                    # no install (recommended)
pipx install dira-scan             # isolated
pip install dira-scan              # into the current env
npx dira-scan .                    # from Node projects
```

## Use it

```bash
dira scan .                        # human report
dira scan . --verbose              # every occurrence + the readiness checklist
dira scan . --only secrets,config  # fast pre-commit-grade pass
dira scan . --offline              # air-gapped: no OSV, no live checks
dira scan . -f sarif -o dira.sarif # GitHub code scanning
dira scan . -f markdown            # paste into a PR
dira scan . -f html -o report.html --open   # client-shareable audit
dira baseline .                    # accept today's debt, fail only on new issues
dira rules                         # every rule, printed
dira init                          # install CI workflow + pre-commit hook
```

Exit code is `1` when anything at or above `--fail-on` (default `high`) is found, so it drops
straight into CI. `--fail-on never` always exits `0`.

### GitHub Actions

```yaml
- uses: Yusuf-Gadelrab/dira@v1
  with:
    fail-on: high
    target: yourapp.com
```

Or use the SARIF path so findings land in the Security tab — `dira init` writes that workflow for you.

### pre-commit

```yaml
repos:
  - repo: https://github.com/Yusuf-Gadelrab/dira
    rev: v1.0.0
    hooks:
      - id: dira
```

### As a library

```python
from dira import scan

result = scan(Path("."), offline=True)
print(result.grade(), result.risk_score(), result.readiness["score"])
for f in result.findings:
    print(f.severity, f.path, f.title, f.remediation)
```

## Why it's fast

- **One walk, one regex.** All 20 secret patterns compile into a single alternation, so each file is read once and matched once — not once per rule.
- **Incremental cache.** `.dira-cache.json` keys results on `(size, mtime, ruleset version)`; an unchanged file is never re-read. Second runs on a large repo are typically 5–10× faster.
- **Parallel by default.** File scanning and OSV detail lookups run on a thread pool sized to your CPU.
- **Batched network.** Up to 900 packages per OSV request, advisory details fetched concurrently and capped.
- **Cheap skips.** Vendor/build directories, `.gitignore` entries, binaries, and files >2 MB are excluded before any I/O.

## Noise control

False positives are the reason security tools get uninstalled, so DIRA:

- ignores placeholders, `os.environ[...]`, `${VAR}`, `changeme`, `xxxx`, and low-entropy values;
- gates the generic credential rule on Shannon entropy ≥ 3.4;
- **downgrades** — rather than hides — hits inside `tests/`, `fixtures/`, docs, and `.env.example`;
- deduplicates overlapping rules on the same line, keeping the highest severity;
- supports `.diraignore` (same syntax as `.gitignore`) and stable per-finding fingerprints, so `dira baseline` suppresses today's debt without hiding tomorrow's regressions.

## Limits — read these

Automated pattern analysis. It does **not** replace a penetration test, a threat model, or a real
SOC 2 audit, and it cannot see your cloud IAM, your MFA posture, or your access reviews (those are
listed as manual attestations in the report). A clean DIRA run means "no known bad patterns in this
repo", not "secure".

Scanning a domain you do not own or have permission to test may be unlawful. `--target` performs
unauthenticated GETs on a handful of well-known paths — point it at your own infrastructure only.

## License

MIT © Yusuf Gadelrab
