"""Startup security-readiness score — the evidence an enterprise buyer, SOC 2 auditor,
or diligence questionnaire actually asks for, checked against the repo."""

from __future__ import annotations

import re
from pathlib import Path

from ..core import Finding

NAME = "readiness"

# (key, label, weight, why it matters, remediation, matcher spec)
CHECKS = [
    ("lockfile", "Dependencies are lock-pinned", 6,
     "Unpinned deps mean an attacker who takes over a maintainer account ships straight to prod.",
     "Commit a lockfile (package-lock.json / uv.lock / poetry.lock / Cargo.lock).",
     {"files": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
                "uv.lock", "Pipfile.lock", "Cargo.lock", "go.sum", "Gemfile.lock"]}),
    ("dep-updates", "Automated dependency updates", 6,
     "Most breaches start with a known CVE nobody upgraded.",
     "Add .github/dependabot.yml or renovate.json.",
     {"files": ["dependabot.yml", "dependabot.yaml", "renovate.json", ".renovaterc",
                "renovate.json5"]}),
    ("ci", "Continuous integration configured", 5,
     "No CI means nothing is verified before it ships.",
     "Add a CI workflow that installs, lints, and tests on every PR.",
     {"dirs": [".github/workflows"], "files": [".gitlab-ci.yml", ".circleci/config.yml",
                                               "Jenkinsfile", "azure-pipelines.yml"]}),
    ("tests", "Automated tests present", 6,
     "Security fixes you cannot regression-test get silently reverted.",
     "Add a tests/ directory and wire it into CI.",
     {"dirs": ["tests", "test", "__tests__", "spec"],
      "glob": ["*_test.go", "*.test.ts", "*.test.js", "test_*.py", "*_test.py", "*.spec.ts"]}),
    ("secret-scanning", "Secret scanning in CI", 8,
     "Committed keys are the single most common startup breach; catch them before merge.",
     "Add dira / gitleaks / trufflehog as a required CI job and a pre-commit hook.",
     {"content": [r"(?i)gitleaks|trufflehog|detect-secrets|dira[-_ ]?scan|ggshield"],
      "in": [".github/workflows", ".pre-commit-config.yaml", ".gitlab-ci.yml"]}),
    ("sast", "Static analysis / code scanning", 5,
     "Buyers ask for evidence of SAST in every security questionnaire.",
     "Enable CodeQL, Semgrep, bandit, or gosec in CI.",
     {"content": [r"(?i)codeql|semgrep|bandit|gosec|snyk|sonarqube|bearer"],
      "in": [".github/workflows", ".gitlab-ci.yml", "Makefile", "pyproject.toml"]}),
    ("precommit", "Pre-commit hooks", 3,
     "The cheapest place to stop a secret is the developer's laptop.",
     "Add .pre-commit-config.yaml (or husky) with a secret-scan hook.",
     {"files": [".pre-commit-config.yaml", ".husky", "lefthook.yml"]}),
    ("codeowners", "Code review ownership defined", 4,
     "Unreviewed merges to main are the top finding in SOC 2 change-management.",
     "Add a CODEOWNERS file and require review on the default branch.",
     {"files": ["CODEOWNERS"]}),
    ("security-policy", "Vulnerability disclosure policy", 4,
     "Researchers need a place to report; auditors check for one.",
     "Add SECURITY.md with a contact address and response SLA.",
     {"files": ["SECURITY.md", "security.md", "SECURITY.txt"]}),
    ("env-example", "Config documented without secrets", 3,
     "An .env.example proves config is externalised rather than hardcoded.",
     "Add .env.example listing every required variable with empty values.",
     {"files": [".env.example", ".env.sample", ".env.template", "env.example"]}),
    ("iac", "Infrastructure as code", 4,
     "Click-ops infrastructure cannot be reviewed, diffed, or restored.",
     "Move infra into Terraform / Pulumi / CloudFormation / compose files.",
     {"glob": ["*.tf", "*.bicep"], "files": ["docker-compose.yml", "docker-compose.yaml",
                                             "Pulumi.yaml", "serverless.yml", "template.yaml"]}),
    ("containerized", "Reproducible build/runtime definition", 3,
     "A Dockerfile makes the runtime auditable and patchable.",
     "Add a Dockerfile (non-root, pinned base image).",
     {"glob": ["Dockerfile*"]}),
    ("observability", "Error tracking / monitoring wired in", 5,
     "You cannot respond to an incident you never see.",
     "Wire in Sentry, OpenTelemetry, Datadog, or equivalent, with alerting.",
     {"content": [r"(?i)\bsentry\b|opentelemetry|datadog|newrelic|honeycomb|prometheus|logtail|betterstack"],
      "in": ["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Gemfile"]}),
    ("auth-lib", "Vetted auth implementation", 4,
     "Hand-rolled auth is where startups lose customer data.",
     "Use a vetted provider/library (Auth0, Clerk, Supabase Auth, NextAuth, Devise, Django auth).",
     {"content": [r"(?i)next-?auth|@auth/|auth0|clerk|supabase|firebase-admin|django\.contrib\.auth|devise|passport|lucia|better-auth|authlib"],
      "in": ["package.json", "pyproject.toml", "requirements.txt", "Gemfile", "go.mod"]}),
    ("incident-plan", "Incident response / runbook documented", 5,
     "Enterprise contracts require a documented breach-notification process.",
     "Add docs/INCIDENT-RESPONSE.md: severities, on-call, comms, 72h notification path.",
     {"content": [r"(?i)incident response|runbook|on-?call|postmortem|breach notification"],
      "in": ["docs", "README.md", "SECURITY.md", "RUNBOOK.md"]}),
    ("backups", "Backup / recovery documented", 4,
     "Ransomware and a bad migration have the same fix: tested restores.",
     "Document backup schedule, retention, and a tested restore procedure.",
     {"content": [r"(?i)backup|restore|point-in-time|disaster recovery|pg_dump"],
      "in": ["docs", "README.md", "Makefile", "scripts"]}),
    ("privacy", "Privacy policy / data handling documented", 3,
     "Required before you can legally take EU or enterprise customer data.",
     "Publish a privacy policy and record what personal data you store and where.",
     {"content": [r"(?i)privacy policy|gdpr|ccpa|data processing|dpa\b|subprocessor"],
      "in": ["docs", "README.md", "PRIVACY.md", "legal"]}),
    ("license", "License declared", 2,
     "Diligence flags unlicensed code as an IP risk.",
     "Add a LICENSE file.",
     {"files": ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]}),
]

MANUAL = [
    "MFA enforced on GitHub, cloud, email, and the domain registrar",
    "Branch protection: required reviews + status checks on the default branch",
    "Least-privilege cloud IAM (no long-lived root/admin keys)",
    "Offboarding checklist that revokes SSO, repo, and cloud access same-day",
    "Encrypted backups with a restore tested in the last 90 days",
    "Vendor/subprocessor list maintained for customer security reviews",
]


def evaluate(root: Path, files: list[tuple[Path, str]]) -> tuple[dict, list[Finding]]:
    rels = {rel.replace("\\", "/") for _, rel in files}
    names = {rel.rsplit("/", 1)[-1] for rel in rels}
    dirs = {d for rel in rels for d in _ancestors(rel)}
    by_rel = {rel: p for p, rel in files}

    results = []
    for key, label, weight, why, fix, spec in CHECKS:
        ok = _check(spec, rels, names, dirs, by_rel)
        results.append({"key": key, "label": label, "weight": weight, "passed": ok,
                        "why": why, "remediation": fix})

    total = sum(c["weight"] for c in results)
    earned = sum(c["weight"] for c in results if c["passed"])
    pct = round(100 * earned / total) if total else 0

    findings = []
    for c in results:
        if c["passed"]:
            continue
        sev = "medium" if c["weight"] >= 6 else "low" if c["weight"] >= 4 else "info"
        findings.append(Finding(
            id=f"readiness/{c['key']}", title=f"Missing: {c['label']}", severity=sev,
            scanner=NAME, path=".", line=0, evidence=c["why"], remediation=c["remediation"]))

    summary = {
        "score": pct,
        "earned": earned,
        "total": total,
        "checks": results,
        "manual": MANUAL,
        "tier": ("Enterprise-ready" if pct >= 85 else "Diligence-ready" if pct >= 70
                 else "Early-stage gaps" if pct >= 45 else "Pre-security"),
    }
    return summary, findings


def _ancestors(rel: str) -> list[str]:
    parts = rel.split("/")[:-1]
    return ["/".join(parts[:i + 1]) for i in range(len(parts))]


def _check(spec: dict, rels: set, names: set, dirs: set, by_rel: dict) -> bool:
    for f in spec.get("files", []):
        if f in names or f in rels or f in dirs:
            return True
    for d in spec.get("dirs", []):
        if d in dirs or any(x == d or x.endswith("/" + d) for x in dirs):
            return True
    for g in spec.get("glob", []):
        pref, _, suf = g.partition("*")
        if any(n.startswith(pref) and n.endswith(suf) for n in names):
            return True
    patterns = [re.compile(p) for p in spec.get("content", [])]
    if patterns:
        targets = spec.get("in", [])
        for rel, p in by_rel.items():
            if not any(rel == t or rel.startswith(t + "/") or rel.endswith("/" + t)
                       or rel.rsplit("/", 1)[-1] == t for t in targets):
                continue
            try:
                text = p.read_text(errors="replace")[:400_000]
            except OSError:
                continue
            if any(rx.search(text) for rx in patterns):
                return True
    return False
