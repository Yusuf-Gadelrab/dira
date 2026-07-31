# Show HN

**Status: DRAFT — not yet posted. Publish the packages first; every link here assumes they resolve.**

Every install line below assumes `dira-scan` is published. If you post before publishing,
change the install line to the git URL — HN will find a 404 within ninety seconds.

---

## Title

```
Show HN: Dira – security scanner for startup codebases, no dependencies
```

70 characters. En dash. No adjectives, no emoji, no exclamation. HN's title guidelines
penalize hype and the moderators will rewrite a title that reads like marketing.

Alternates if the first feels off:

```
Show HN: Dira – one command for secrets, CVEs, misconfigs, and git-history leaks
```
(79 chars, right at the limit)

```
Show HN: Dira – stdlib-only Python security scanner with SARIF output
```
(68 chars, leads with the technical hook)

## URL field

```
https://github.com/Yusuf-Gadelrab/dira
```

Point at the repo, not the landing page. HN's audience clicks through to source, and a
marketing page as the submission URL reads as an ad. Put the landing page in the comment.

---

## First comment (post this immediately after submitting)

```
I built this because I kept hitting the same wall on small projects: "is this
repo safe enough to hand to a customer" has no cheap fast answer. You either
pay for a platform you cannot justify at three people, or you install gitleaks,
Semgrep, an SCA tool, and a TLS checker and wire four of them into CI. I did
neither on most projects, which is the actual problem.

Dira runs one command and checks six things: hardcoded secrets, dependency CVEs
against OSV.dev, config and IaC misconfigurations (Docker, Kubernetes,
Terraform, GitHub Actions, cloud IAM, plus frontend and LLM-app patterns),
dependency license risk, secrets in git history, and TLS and security headers
on a live domain. It prints a graded report with a remediation per finding, and
can emit SARIF for GitHub code scanning, Markdown for a PR comment, or an SBOM
in CycloneDX or SPDX.

It is pure Python standard library, no runtime dependencies. That was partly
principle, since it felt wrong to ship requests inside a tool that also flags
vulnerable requests versions, and partly because install friction is the whole
game for something you want people to run before their first commit.

What it is not:

- Not a pentest. It reads files. It cannot log into anything.
- Not a replacement for Semgrep. The rules are pattern-based, not taint
  analysis. Anything routed through an intermediate variable or a helper
  function is invisible to it. That is the single biggest gap and I would
  rather say it here than have someone find out during an incident.
- Not a replacement for Snyk, gitleaks, or trufflehog either. If you already
  run those, Dira's secret and dependency scanning is probably redundant for
  you. The bundling is the point, not any individual detector.
- Not an attestation. A clean run means "no known bad patterns in this repo".

Some implementation notes in case they are interesting:

- The secret patterns compile into one alternation, so a file is read once and
  matched once rather than once per rule. That created a shadowing bug worth
  knowing about: regex alternation is leftmost-first, so a broad generic
  credential rule wins over a specific provider rule on the same line, and
  API_KEY = "sk_live_..." reported as "generic credential" instead of "Stripe
  key". Fixed with a second pass over the provider-specific patterns plus
  same-line dedup, so the specific rule always wins.
- The generic credential rule is gated on Shannon entropy, which is what keeps
  base64 config blobs and git hashes out of the report.
- Findings in tests/, fixtures/, and docs are downgraded rather than hidden. A
  deliberately vulnerable fixture is not a production incident, but silently
  dropping it is how scanners get trusted for the wrong reasons.
- OSV lookups batch up to 900 packages per request and fetch advisory detail
  concurrently, so the dependency pass is usually the cheapest part of a run.
- There is an incremental cache keyed on (size, mtime, ruleset version). Git
  history scanning is not cached and dominates a full run on an old repo,
  which is why --only secrets,config exists.

I am a CS undergrad, not a security researcher, and I would rather hear where
this is wrong now than after someone relies on it. The parts I am least sure
about are the config and IaC rules, which are the newest, and whether the
redaction holds up under adversarial input. If you break either, I will fix it
and credit you.

Repo: https://github.com/Yusuf-Gadelrab/dira
Landing page: https://yusuf-gadelrab.github.io/dira.html
```

---

## Likely objections, and honest answers

Do not paste these preemptively. Wait for the comment, reply directly to it, concede the true
part first. HN rewards a poster who agrees with a good criticism and punishes one who
defends.

**"This is just regex grep with extra steps."**

> Largely yes, for the secrets scanner. Regex plus Shannon entropy gating plus path-based
> downgrading, and I would not claim the detection technique is novel. What is not grep is
> the dependency scanner (lockfile resolution against OSV), the git-history pass, and the
> SARIF output. What I think is worth something is that it is one process and one command,
> which is the difference between running it and not running it. If you already have the four
> tools wired up, this buys you nothing and I would not try to convince you otherwise.

**"Trufflehog and Gitleaks already do this, and better."**

> They do secret scanning better than I do, unambiguously — verified-detector support, years
> of pattern tuning, real adversarial testing. Dira is not trying to beat them at secrets. It
> is trying to answer a broader and shallower question in one run: secrets *and* CVEs *and*
> IaC misconfig *and* license risk *and* live headers, graded. If secrets are your only
> concern, use Gitleaks. Honestly.

**"A security readiness score is arbitrary."**

> It is. It is an 18-item checklist with weights I chose, and it verifies that a control is
> present, not that it works — a `SECURITY.md` full of nonsense scores the same as a good
> one. I kept it because founders get sent enterprise security questionnaires asking exactly
> these questions and have no idea where they stand, and a rough map beats none. The score is
> printed alongside the raw checklist under `--verbose` for that reason: the list is the
> useful part, the number is the hook. If you have a better model for what belongs on that
> list, I will take the PR.

**"Who are you to write a security tool?"**

> Nobody, and that is a fair question. I am a CS undergrad, I have not done incident
> response, and this has not been reviewed by anyone who has. Which is why the README leads
> with what it cannot do, why every finding carries a CWE or OSV ID you can check yourself,
> and why nothing in it is a black box — `dira rules` prints every rule it has. It is MIT and
> the scanner is around 1,200 lines. If it is wrong, it is wrong in public and readable in an
> afternoon.

**"Zero dependencies is a fake virtue, you just reimplemented requests badly."**

> Partly true. There is hand-rolled `urllib` batching and hand-written ANSI in there that
> `requests` and `rich` would do better. The tradeoff I made it for is install: `pipx install
> dira-scan` never fails on a resolver conflict, and a tool that flags vulnerable transitive
> dependencies looks silly shipping fifteen of its own. Whether that is worth the maintenance
> cost is a real argument and I do not think it is settled.

**"Yet another AI-generated security tool."**

> Fair suspicion given the volume of those. Check the changelog — the entries are bug fixes
> found by running it against real repositories, including one where an uncommitted local
> `.env` was reported as a critical breach and graded a clean repo an F. That kind of fix only
> comes from using the thing. Run it on your own repo and tell me what it gets wrong.

**"What is the false positive rate?"**

> Do not quote a number. Say: it is tuned against real repositories, entropy-gated, and
> path-downgraded, and the failure mode I care most about is a false critical, because that
> is what gets a scanner uninstalled. If you hit one, open an issue with the line that
> triggered it and it becomes a regression test.

---

## Posting notes

- **Best time:** a weekday between 8 and 10am ET, ideally Tuesday through Thursday. That puts
  you on the front page while US morning and European afternoon traffic overlap. Avoid Friday
  afternoon, weekends, and US holidays.
- **One submission only.** If it does not catch, do not resubmit within a couple of weeks and
  never from a second account. HN detects that and it is unrecoverable.
- **Be at the keyboard for the next four hours.** Response speed in the first hour is a real
  ranking input and it is the entire reputational payoff of a Show HN. Do not post and walk
  away.
- **Never argue.** Concede, thank, fix. The comment thread is the product demo.
- **Do not ask for upvotes anywhere.** Voting-ring detection is automated and a flagged Show
  HN is a permanent mark on the account.
- Expect a traffic spike to the repo and the landing page. Click the README install line
  yourself one more time before you submit.
