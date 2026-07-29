# Security policy

## Reporting a vulnerability

Email **yusuf.gadelrab06@gmail.com** with `DIRA SECURITY` in the subject. Include a description,
reproduction steps, and the impact you believe it has. Please do not open a public issue for a
vulnerability.

- Acknowledgement: within 72 hours
- Triage and severity assessment: within 7 days
- Fix or mitigation for high/critical issues: within 30 days

## Scope

In scope: the `dira` CLI and library — false negatives that let a real credential through, code
execution while scanning untrusted repositories, and any path where DIRA writes secret material in
cleartext to a report or cache.

Out of scope: findings in other people's repositories, false positives (open a normal issue), and
denial of service caused by pointing DIRA at a pathological input.

## How DIRA handles secrets it finds

Detected values are **redacted** (`AKIA****VK9D`) before they reach any report or the on-disk cache.
Reports are written only where you point them. DIRA makes no network calls except OSV.dev package
lookups and, when you pass `--target`, requests to the host you named. `--offline` disables both.
