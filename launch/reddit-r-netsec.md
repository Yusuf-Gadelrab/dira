# Reddit — r/netsec and alternates

**Status: DRAFT — not yet posted.**

---

## Read this before posting to r/netsec

r/netsec is moderated hard and most tool-release posts are removed. The rules that matter:

- **Content must be technical.** A release announcement is not technical content. A writeup
  of a detection technique that happens to reference your tool is.
- **Self-promotion is capped.** The sub's guidance is roughly one self-authored link per ten
  contributions. If the account has no history in the sub, expect removal regardless of
  quality. **Check the account's history before posting** — if it is thin, post to
  r/devsecops first and come back to r/netsec later.
- **No "I built a tool" framing anywhere in the title.** Lead with the finding, not the
  product.
- Posting a GitHub link as the submission URL is common and accepted when the content is
  substantive. A landing page as the URL will be removed as an ad.

The version below is written to survive that filter: it opens with the regex-shadowing bug,
which is a genuinely reusable finding for anyone writing a multi-pattern scanner, and treats
the tool as the artifact rather than the subject.

---

## Title

```
Regex alternation is leftmost-first, so your broad secret rule silently shadows your specific ones — the two-pass fix, plus entropy gating and OSV batching notes
```

Too long for Reddit's 300-char limit? It is not, but shorter usually does better:

```
Multi-pattern secret scanning: how a single-alternation pass silently shadows provider-specific rules, and the two-pass fix
```

## Submission URL

```
https://github.com/Yusuf-Gadelrab/dira
```

---

## Body

```
Author disclosure up front: this is my tool (MIT, stdlib-only Python). Posting
for the detection writeup and for critique of the rule set, not as a release
announcement. Mods, remove if that is still over the line.

## The bug worth sharing

If you compile N secret patterns into one alternation for a single-pass scan —
which you want to do, because per-rule passes mean N reads or N matches per file
— you inherit Python's regex semantics: alternation is leftmost-first, not
longest-match. The first branch that can match at the earliest position wins.

That means a broad generic-credential rule of the general shape

    (?i)(api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9/+_-]{20,})["']

placed anywhere in the alternation will beat a specific provider rule on the
same line, because the generic rule matches earlier in the string (it starts at
the identifier) while the Stripe rule starts at `sk_live_`. So

    API_KEY = "sk_live_51H..."

reports as "generic credential, medium" instead of "Stripe secret key,
critical". You lose the severity, you lose the provider-specific remediation
("revoke at Stripe" vs "rotate this, whatever it is"), and — worse — it happens
silently. Everything still gets flagged, so no test fails and no user
complains. You just quietly grade real incidents as medium.

Ordering the alternation does not fix it, because the position of the match in
the subject dominates branch order.

The fix I landed on: two passes over the same read. Pass one is the single
combined alternation over all patterns for cheap coverage. Pass two runs only
the provider-specific patterns. Then dedupe by (file, line), and when both a
specific and a generic finding land on the same line, the specific one wins and
the generic one is dropped rather than reported alongside it. Cost is one extra
match pass over an already-in-memory buffer, which is negligible next to the
read. Now a provider hit always outranks the catch-all, and a line with a real
provider key never double-reports.

The general lesson: if you are collapsing rules into one regex for speed, your
rule *precedence* no longer lives in your rule table, it lives in the regex
engine's matching semantics. Those are not the same thing and the difference
does not show up as a failure.

## Entropy gating on the generic rule

The generic credential rule is unusable without a gate. Gating on Shannon
entropy over the captured value is what makes it survivable: it drops git SHAs,
short base64 config blobs, UUID-shaped identifiers, and repeated placeholder
strings, while keeping real high-entropy tokens. Entropy alone is not enough —
a long lorem-ipsum-ish string can clear the bar — so it is combined with a
placeholder denylist (`changeme`, `xxxx`, `${VAR}`, `os.environ[...]`, and
friends) and with path-based severity downgrading.

Downgrading, not suppression, is the part I would defend most. A hardcoded key
in `tests/fixtures/` is not a production incident and should not be critical,
but it is also not nothing, and a scanner that silently drops findings under
paths matching `test` is a scanner that misses the one real key someone parked
in a test helper. So those findings stay in the report at reduced severity.

## OSV batching

Dependency CVEs go to OSV.dev's batch endpoint — up to 900 package queries per
request — and then only the advisories that actually matched get their details
fetched, concurrently and capped. That inverts the naive shape (one request per
package) into roughly one request plus a handful. No API key, no account, free,
and it covers npm, PyPI, Go, crates.io, and RubyGems from the same lockfile
parse that generates the SBOM.

The honest limitation: severity is taken from the OSV record rather than
independently computed, so severity accuracy is bounded by the completeness of
the upstream advisory. Records without a CVSS vector get an estimate, and that
estimate is the weakest number in the whole report.

## Where this is weak, stated plainly

- **No dataflow analysis.** Every config and code rule is a pattern match, not
  taint tracking, not AST-based, no cross-function or cross-file propagation.
  Anything routed through an intermediate variable is invisible. If you need
  real dataflow-aware SAST, this is not it and Semgrep is.
- **Regex secret detection has an irreducible error rate** in both directions.
  Nothing above eliminates that; it manages it.
- **Git-history scanning is not cached** and dominates a full run on a repo
  with deep history. `--only secrets,config` and `--diff <ref>` exist to skip it.
- **Live surface checks are a handful of unauthenticated GETs** (`/.env`,
  `/.git/config`, `/actuator/env`) plus TLS validity/expiry and header checks.
  That is not a scanner and it is definitely not DAST.
- **The readiness score is a checklist proxy** — presence of lockfiles, CI,
  CODEOWNERS, SECURITY.md — not verification that any of those controls work.

## What I would most like torn apart

Two things:

1. **The config and IaC rule set** (Docker, k8s, Terraform, GitHub Actions,
   cloud IAM, frontend, LLM-app patterns). It is the newest part and the most
   likely to have both false positives and coverage gaps I have not found. One
   already-fixed example of the failure mode: a `gcp-allusers` rule matched a
   bare substring, so any file merely *mentioning* `allUsers` went critical —
   including the tool's own rule table.

2. **Redaction completeness.** Every finding masks its value (`sk_l****nZaQ`)
   so reports are shareable without a second pass. I have not had that checked
   under adversarial input — multiline values, values spanning a capture-group
   boundary, unicode. If someone wants to try to get a full credential to
   survive into the SARIF or HTML output, I would take that seriously and fix
   it fast.

Repo: https://github.com/Yusuf-Gadelrab/dira (MIT, Python 3.9+, no runtime
dependencies, 98 tests). SARIF 2.1.0 output validates against GitHub's
code-scanning schema.
```

---

## Comment-thread prep

- **"This is regex grep."** Concede immediately for the secrets scanner. The writeup above is
  about regex semantics, so the comment is on-topic rather than hostile — engage with it.
- **"Why not Semgrep rules?"** Honest answer: Semgrep is the right tool for dataflow, and
  Dira's value is being one process with no install footprint, not out-detecting Semgrep. A
  Semgrep-rules export would be a reasonable feature request; say so.
- **"Severity estimation from incomplete OSV records is doing a lot of work."** Agree. It is
  the weakest number in the report and it is labelled as an estimate.
- **Do not defend the readiness score in r/netsec.** That audience is not the buyer for it.
  Say it is a founder-facing checklist proxy and move the conversation back to detection.

---

## Alternate subreddits, with tone notes

Post to at most one per day, and never the same body twice — Reddit's spam filter and the
mods both catch cross-posted identical text.

| Subreddit | Fit | Tone | Mechanism |
|---|---|---|---|
| **r/devsecops** | Best fit and the friendliest. CI gating, SARIF, PR checks, SBOM are all core topics. | Practitioner. Lead with the GitHub Action workflow and the `--diff` PR gate, not the regex writeup. | Text post, self-promo tolerated when disclosed. Check the pinned rules for a self-promo day. |
| **r/Python** | Strong fit for the zero-dependency angle. Existing draft is in `reddit-r-python.md`. | Language-nerd. Lead with the stdlib-only constraint and what it costs. Nobody there cares about SOC 2. | Text post. Self-promotion allowed if you are the author and say so. Sunday "Showcase" threads exist — check the sidebar. |
| **r/opensource** | Fits a genuinely MIT, no-strings project. | Community and licensing. Lead with MIT, no telemetry, no account, no paid tier. | Text post with the repo link. Low volume, low risk. |
| **r/SideProject** | Fits the solo-builder story. Lowest signal, easiest approval. | Personal. The "built this because I could not answer a customer's security questionnaire" story is the whole post. | Text post. Effectively no self-promo restriction. |
| **r/cybersecurity** | Fits but is enormous and heavily moderated for vendor spam. | Practitioner, no marketing words at all. | Check for a weekly self-promotion or tool thread — a top-level tool post is usually removed. |
| **r/golang, r/rust, r/node** | Only if a language-specific angle exists (their lockfile is supported). | Ecosystem-specific. Do not post generic copy. | Skip unless there is something specific to say. |

**Sequencing recommendation:** r/devsecops first (friendliest, builds a comment history),
then r/Python a few days later, then r/netsec once the account has real contribution history
in the sub. r/SideProject and r/opensource any time as low-stakes fill.
