<div align="center">

# DIRA · درع

**Security audit for startup codebases.** One command, zero dependencies.

`secrets` · `dependency CVEs` · `misconfigurations` · `licenses` · `git-history leaks` · `live surface` · `SBOM` · `readiness score`

</div>

---

Most startup security tooling is either a $2k/mo platform or five separate CLIs you never wire up.
DIRA is one binary-free Python command that answers the question a founder actually gets asked —
*"is this codebase safe enough to sell to an enterprise?"* — and prints the exact fix for everything
it finds.

```bash
pipx install git+https://github.com/Yusuf-Gadelrab/dira@v1.1.0
dira scan .                        # scan the current project
dira scan . -t yourapp.com         # + audit the live domain
dira scan . -f html -o report.html --open
```

## What it checks

| Scanner | What it finds |
|---|---|
| `secrets` | 20 credential patterns (AWS, Stripe, OpenAI, Anthropic, GitHub, GCP, Slack, npm, DSNs, private keys) plus an entropy-gated generic rule. Values are **redacted** in every report. |
| `config` | 34 rules across Docker (root user, `:latest`, build-ARG secrets), compose/k8s (`privileged`, hostPath), Terraform (`0.0.0.0/0`, public buckets, unencrypted storage), GitHub Actions (`pull_request_target`, mutable action refs, script injection), cloud (public Firebase rules, `"Principal": "*"`, GCP `allUsers`, `curl \| sh`), frontend (`NEXT_PUBLIC_*` secrets, tokens in localStorage, innerHTML/`dangerouslySetInnerHTML`, wildcard `postMessage`, JWT `none`), LLM apps (`dangerouslyAllowBrowser`, prompt concatenation, model output piped to an executor), and server code (SQLi by concatenation, `shell=True`, wildcard CORS, disabled TLS verification, `eval`/`pickle`, weak password hashing, debug mode on). |
| `deps` | Every package in your lockfiles resolved against **OSV.dev** — npm, PyPI, Go, crates.io, RubyGems. Batched, free, no API key, with CVSS-estimated severity and the exact fixed version. |
| `git` | Secrets buried in commit history (deleting the file does not rotate the key), tracked `.env`/`.pem`/keystores, credentials in the remote URL, `.gitignore` gaps. |
| `surface` | Live domain: TLS validity + expiry, HSTS/CSP/nosniff/frame-options, cookie flags, HTTP→HTTPS redirect, version-disclosure headers, and publicly served `/.env`, `/.git/config`, `/actuator/env`. |
| `licenses` | Every dependency's license resolved from npm/PyPI, classified into permissive, file-level copyleft (MPL/LGPL), strong copyleft (GPL), and network copyleft (AGPL/SSPL) — with a license inventory for your diligence folder. |
| `readiness` | An 18-point **startup security-readiness score** modelled on what SOC 2 auditors and enterprise security questionnaires actually ask for — lockfiles, Dependabot, CI, tests, secret scanning, SAST, CODEOWNERS, SECURITY.md, IaC, observability, incident response, backups, privacy. |

Every finding carries a severity, a location, redacted evidence, a concrete remediation, and a CWE/OSV reference.

## Install

```bash
# from source (available now)
pipx install git+https://github.com/Yusuf-Gadelrab/dira@v1.1.0
uvx --from git+https://github.com/Yusuf-Gadelrab/dira@v1.1.0 dira scan .
pip install git+https://github.com/Yusuf-Gadelrab/dira@v1.1.0

# or grab the wheel from the release
pipx install https://github.com/Yusuf-Gadelrab/dira/releases/download/v1.1.0/dira_scan-1.1.0-py3-none-any.whl
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
    rev: v1.1.0
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

- **One walk, one regex.** All 20 secret patterns compile into a single alternation, so each file is read once and matched once — not once per rule.
- **Incremental cache.** `.dira-cache.json` keys results on `(size, mtime, ruleset version)`; an unchanged file is never re-read. Second runs on a large repo are typically 5–10× faster.
- **Parallel by default.** File scanning and OSV detail lookups run on a thread pool sized to your CPU.
- **Batched network.** Up to 900 packages per OSV request, advisory details fetched concurrently and capped.
- **Cheap skips.** Vendor/build directories, `.gitignore` entries, binaries, and files >2 MB are excluded before any I/O.
- **Diff mode.** `--diff origin/main` scans only what the branch touched — a PR gate that finishes before the test job starts.

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
