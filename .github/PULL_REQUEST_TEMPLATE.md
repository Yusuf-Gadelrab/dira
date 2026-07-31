**What this changes and why**

**If this adds or changes a detection rule:**

- [ ] Added a positive test (it fires on a real-shaped example)
- [ ] Added a negative test (it does *not* fire on a plausible look-alike)
- [ ] Ran `dira scan . --offline --fail-on critical` locally and it still passes (dogfooding)

**If this touches `dira fix`:**

- [ ] The change is additive/reversible — it does not rotate a key, rewrite git history, or edit
      application code (see `CONTRIBUTING.md`)
- [ ] Dry-run by default; `--apply` gates the write; there's a test for both

**Checklist**

- [ ] `uv run pytest -q` passes locally
- [ ] No new runtime dependency added (`dependencies = []` in `pyproject.toml` stays empty)
- [ ] No real credential, only obviously-fake values, in any new fixture
- [ ] Docs updated if a flag, rule count, or install path changed (`README.md`, `CHANGELOG.md`)
