# LinkedIn — DIRA launch

**Status: DRAFT — not yet posted.**

Three variants. Pick one, do not post all three. Second and third can be reused weeks later
with the numbers refreshed.

House rules applied throughout: no em dashes, short lines, line break between every beat,
build-in-public voice, no corporate filler, no emoji spam.

---

## Link strategy (applies to all three)

LinkedIn suppresses reach on posts with an external link in the body. The fix is mechanical:

1. Post the body with **zero links**.
2. Immediately post the link as your **own first comment**.
3. Edit the post ~10 minutes later to add "link in the comments" at the end if it is not
   already there. Editing after the first burst of impressions costs less than launching with
   a link.

First comment, all three variants:

```
Repo and install: github.com/Yusuf-Gadelrab/dira
What it checks, in plain English: yusuf-gadelrab.github.io/dira.html
MIT licensed. Free. No account, no API key, no telemetry.
```

**Timing:** Tuesday, Wednesday, or Thursday, 8 to 10am PT. Reply to every comment within the
first 90 minutes, because reply velocity is the single biggest reach lever on the platform.

**Hashtags:** three, at the very end, never mid-sentence.
`#buildinpublic #devsecops #opensource`

---

## Variant 1 — the "I scanned my own repos" angle

> **FILL IN BEFORE POSTING.** Every `[X]` below is a placeholder. Run the scan, use the real
> numbers, and if a number is unflattering, keep it. That is the entire credibility of the
> post. If any finding is a live credential, rotate it first and never name the repo.
>
> Command to generate the numbers:
> ```bash
> for r in ~/Startups/* ~/SwingTrend ~/swing-screener; do
>   [ -d "$r/.git" ] && dira scan "$r" --offline -f json -o "/tmp/dira-$(basename $r).json"
> done
> ```

```
I pointed my own security scanner at my own repositories last week.

I expected to feel good about it.

Results across [X] repos:
[X] hardcoded credentials still sitting in git history
[X] dependencies with known CVEs
[X] misconfigurations I would have sworn were not there
Average security readiness score: [X]%

Not one of those was a repo I thought had a problem.

Three things I learned building and then eating this:

1. Deleting a file does not rotate a key.
Every credential that ever touched a commit is still in that history. The file is gone. The key is not. I found [X] of these in code I wrote myself.

2. The problem was never knowing what to fix. It was friction.
I knew about gitleaks. I knew about Semgrep. I knew about OSV. I had wired up exactly zero of them, on any project, ever, because each one is its own install and its own config and its own CI job. Four good tools I never ran beat zero tools I never ran by nothing at all.

3. A tool you have to configure is a tool you will not run.
So the version I built has no config file, no account, no API key, and no dependencies. One command. Either it tells you something or it does not.

That is DIRA.

It checks six things in one run: hardcoded secrets, dependency CVEs against OSV.dev, config and infrastructure misconfigurations, dependency license risk, secrets buried in git history, and TLS and security headers on your live domain. Then it grades the result against the checklist enterprise buyers actually send you.

It is not a pentest. It is not a replacement for Semgrep or Snyk. It is the fast honest first pass you run before you would ever justify paying for either.

Pure Python standard library. Zero runtime dependencies. MIT licensed. Free.

If you have a repo you are quietly nervous about, run it on that one.

Then tell me what it got wrong. That is the part I actually want.

Link in the comments.

#buildinpublic #devsecops #opensource
```

---

## Variant 2 — the founder-pain angle

```
A founder I know lost an enterprise deal over a spreadsheet.

Not the product. Not the price. A security questionnaire.

Forty questions about secret management, dependency scanning, incident response, and access reviews. He had answers for maybe six of them. He was not insecure. He just had no idea where he stood, and no cheap way to find out.

That gap is absurd when you look at it.

On one side: security platforms that start around 2 thousand dollars a month, priced for a company with a security team.

On the other side: five separate open source CLIs that each solve one slice, that you have to find, install, configure, and wire into CI before any of them tell you a single thing.

Nothing in the middle. So most small teams pick neither, and find out what was in the repo when somebody else finds it first.

I built the middle.

DIRA is one command. It scans for hardcoded secrets, dependency CVEs, infrastructure misconfigurations, license risk, and secrets buried in git history, checks TLS and security headers on your live domain, and then scores you against an 18 point readiness model built on what those questionnaires actually ask.

Every finding comes with the exact fix. Credentials are masked in every report, so you can hand the output straight to the customer who asked.

What it will not do, and I put this in the README before I put it anywhere else: it is not a penetration test, it cannot see your cloud IAM or your MFA posture, and a clean run means no known bad patterns found. It does not mean secure. Any tool that tells you otherwise is selling you something.

Zero dependencies. MIT licensed. Free forever, because the version of this that helps somebody is the version they can run in the next thirty seconds.

If you are the person who gets sent those questionnaires, this is for you.

Link in the comments.

#buildinpublic #devsecops #opensource
```

---

## Variant 3 — the engineering-decision angle

```
I shipped a security tool with zero dependencies.

Not "few." Zero. Python standard library only.

That decision cost me real things and I want to be honest about both sides.

Why I did it:

It felt indefensible to ship the requests library inside a tool whose job is flagging your vulnerable copy of the requests library. A scanner that adds fifteen transitive dependencies to reduce your supply chain risk is a joke with a straight face.

And install friction is the whole game. The people who most need a thirty second security check are the ones least willing to manage a virtualenv to get one. pipx install, done, nothing to resolve, nothing to break.

What it cost:

I hand rolled HTTP batching on urllib instead of using requests. More code, more edge cases around timeouts and retries.

I hand wrote the ANSI terminal output instead of using rich. It is more code than I want to maintain.

I gave up things I would have gotten free from click, like shell completion generation.

So was it worth it?

For this tool, yes. The dependency count is a feature customers can verify in one command, and the install has never once failed on a resolver conflict.

For most tools, no. If you are not building something where your own supply chain is part of the pitch, use the library. Reinventing requests badly is not a virtue.

That is the whole tradeoff. I am not sure it generalizes past this one case, and I would rather say that than pretend I found a rule.

The tool is DIRA. Secrets, dependency CVEs, misconfigurations, license risk, git history leaks, and live TLS checks in one command. MIT licensed, free.

If you have built a CLI under a hard constraint like this, I want to hear whether it held up for you.

Link in the comments.

#buildinpublic #devsecops #opensource
```

---

## Pre-post checklist

- [ ] Every `[X]` in Variant 1 replaced with a real number, or Variant 1 not used.
- [ ] No links anywhere in the post body.
- [ ] First comment drafted and ready to paste within 60 seconds of posting.
- [ ] No em dashes anywhere in the body.
- [ ] Install command in the README works right now.
- [ ] Any credential found while generating Variant 1's numbers has been rotated, and no repo
      is named.
- [ ] Blocked out 90 minutes to reply to comments.
