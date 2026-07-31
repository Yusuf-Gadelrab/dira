# Contributing to DIRA

Thanks for considering it. DIRA is a solo-maintained, zero-dependency project, so the bar for a
change is simple: does it make the tool more correct or more useful without adding a runtime
dependency or a false sense of security.

## Before you open a PR

```bash
git clone https://github.com/Yusuf-Gadelrab/dira
cd dira
uv sync --extra dev        # or: pip install -e ".[dev]"
uv run pytest -q           # expect: 98 passed
uv run python -m dira scan . --offline --fail-on critical   # dogfood: dira must pass its own scan
```

There is no build step and no linter configured yet — `pytest` is the whole gate. If you add a
scanner rule, add a test that proves both the detection and the non-detection (a rule with no
false-positive test is half a rule).

## Ground rules

- **Zero runtime dependencies.** `dependencies = []` in `pyproject.toml` is load-bearing, not
  incidental — it is the property a competitor cannot copy without a rewrite and the reason DIRA
  installs cleanly everywhere. A PR that adds a runtime dependency (`requests`, `click`, `rich`,
  etc.) will be asked to solve the problem with the standard library instead. `dev` dependencies
  (test runner only) are fine.
- **New detection rules need a fixture, not just a regex.** Add a positive case (it should fire)
  and a negative case (it should not) to `tests/`. A rule that only has a positive test is how
  the typosquat false-positive bug (`CHANGELOG.md`, "100% false-positive rate") happened.
- **Never make a "fix" that rotates a key, rewrites history, or edits application code.**
  `dira fix` is additive and reversible by design (see the README's "the boring 80%" section).
  If your change makes `fix` do something destructive, it needs a `--apply`-gated dry-run and a
  test that the dry-run path never writes.
- **Findings must stay redacted.** Never print, log, or write a full credential value anywhere in
  a report, cache file, or test fixture that looks like a real key. Use obviously-fake values
  (`AKIAIOSFODNN7EXAMPLE`, `sk_test_...`) in fixtures.
- **No compliance claims.** Don't add copy implying SOC 2 / ISO 27001 certification, a verified
  false-positive rate, or that a clean scan means "secure." See `README.md`'s "Limits" section for
  the standing policy.

## What's genuinely useful right now

- **False positives and false negatives on real repositories.** This is the single most valuable
  contribution. Open an issue with the file/line and what it should have done — see the issue
  template.
- **Config/IaC rules** — the newest scanner and the one most likely to have coverage gaps.
- **New ecosystems for the dependency/license scanners** (`deps.py`, `licenses.py`) beyond
  npm/PyPI/Go/crates.io/RubyGems.
- **Docs fixes.** Every install path in `README.md` and `DISTRIBUTION.md` is meant to be copy-paste
  correct — if one doesn't work verbatim on your machine, that's a real bug.

## What's out of scope (for now)

Dataflow/taint analysis, container image scanning, a hosted dashboard, and telemetry of any kind.
These are deliberate scope boundaries, not gaps waiting for a PR — see the README's comparison
table for why each belongs to a different tool.

## Reporting a security issue in DIRA itself

Do not open a public issue. See `SECURITY.md` — email with `DIRA SECURITY` in the subject, 72-hour
acknowledgement, 30-day fix target for high/critical.

## Code of conduct

This project follows `CODE_OF_CONDUCT.md`. Report violations to yusuf.gadelrab06@gmail.com.

## License

By contributing, you agree your contribution is licensed under the MIT License that covers the
rest of the project (`LICENSE`).
