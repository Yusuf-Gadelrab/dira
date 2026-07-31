---
name: Feature / rule request
about: A new scanner rule, ecosystem, or capability you'd want
title: ""
labels: enhancement
assignees: ""
---

**What's missing**

Describe the gap. If it's a detection rule, include a real (redacted/fake) example of the pattern
that should be caught, and — just as important — an example that should **not** be caught, so a
false-positive test can be written alongside the fix.

**Why it belongs in DIRA rather than a more specialized tool**

DIRA deliberately stays out of dataflow analysis, container image scanning, and hosted dashboards
(see the README's comparison table and `CONTRIBUTING.md`'s "out of scope" section). If the request
overlaps one of those, say why it's still a fit here — otherwise it's likely to be redirected to
Semgrep/Trivy/etc. instead of implemented.

**Would you be willing to open the PR yourself?**

- [ ] Yes, with some guidance on the rule/scanner structure
- [ ] Yes, I've already got a draft
- [ ] No, just flagging the gap
