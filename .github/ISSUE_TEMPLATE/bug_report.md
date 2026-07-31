---
name: Bug report
about: Something crashed, or a scanner reported something wrong
title: ""
labels: bug
assignees: ""
---

**What happened**

A clear description of the bug.

**False positive / false negative? (if scanner-related)**

- [ ] False positive — DIRA flagged something that isn't real
- [ ] False negative — DIRA missed something it should have caught
- [ ] Crash / stack trace
- [ ] Wrong output format / bad report rendering
- [ ] Other

**The file/line that triggered it**

```
paste the exact line (redact any real secret first — replace the value with something
obviously fake, e.g. AKIAIOSFODNN7EXAMPLE, and say so)
```

**Command you ran**

```bash
dira scan . --...
```

**Expected vs actual**

What you expected DIRA to report, and what it actually reported.

**Environment**

- DIRA version: `dira --version`
- Python version: `python3 --version`
- OS:
- Install method: pipx / uvx / pip / source / GitHub Action / pre-commit

**Anything else**

Logs, `--verbose` output, or a minimal repro repo, if you can share one.
