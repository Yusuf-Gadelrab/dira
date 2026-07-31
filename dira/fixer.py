"""Safe auto-remediation.

Only additive, reversible changes: creating a missing policy file, appending .gitignore
lines, deriving a secret-free .env.example. Anything that touches application code, git
history, or a live credential is printed as an instruction — never executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from .scanners.readiness import MANUAL

GITIGNORE_LINES = [
    ".env", ".env.*", "!.env.example", "*.pem", "*.key", "*.p12", "*.keystore",
    "id_rsa", "id_ed25519", "credentials", "service-account.json",
    "terraform.tfstate", "terraform.tfstate.backup", ".dira-cache.json",
]

SECURITY_MD = """# Security policy

## Reporting a vulnerability

Email **{contact}** with `SECURITY` in the subject line. Please include a description,
reproduction steps, and the impact you believe it has. Do not open a public issue.

- Acknowledgement: within 72 hours
- Triage and severity assessment: within 7 days
- Fix or mitigation for high/critical issues: within 30 days

We will credit reporters who ask to be credited, and we will not pursue legal action
against good-faith research that stays within this policy.

## Supported versions

The latest released version receives security fixes.
"""

DEPENDABOT = """version: 2
updates:
{ecosystems}  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
"""

ECOSYSTEM_BLOCK = """  - package-ecosystem: "{eco}"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
"""

ECOSYSTEM_BY_FILE = {
    "package.json": "npm", "package-lock.json": "npm", "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm", "bun.lock": "bun", "bun.lockb": "bun",
    "requirements.txt": "pip", "pyproject.toml": "pip",
    "Pipfile": "pip", "poetry.lock": "pip", "go.mod": "gomod",
    "Cargo.toml": "cargo", "Gemfile": "bundler", "Dockerfile": "docker",
}

SECURITY_TXT = """Contact: mailto:{contact}
Expires: {expires}
Preferred-Languages: en
Canonical: https://{domain}/.well-known/security.txt
"""

INCIDENT_MD = """# Incident response

## Severities
- **SEV1** — customer data exposed, production down, or a credential is known-compromised.
- **SEV2** — degraded service or a security control failed without confirmed exposure.
- **SEV3** — contained issue with a workaround.

## First 30 minutes (SEV1)
1. Declare. One person is incident commander; they do not debug.
2. Contain: revoke the credential, disable the endpoint, or roll back the deploy.
3. Preserve evidence — snapshot logs before restarting anything.
4. Open a running timeline document. Every action gets a timestamp.

## Communication
- Internal: dedicated channel per incident.
- Customers: notify affected customers within the window your contracts require
  (commonly 72 hours; GDPR Art. 33 is 72 hours to the supervisory authority).

## After
- Blameless postmortem within 5 business days: timeline, root cause, contributing factors,
  and action items with owners and dates.
- Every SEV1 produces at least one detection improvement.

## Contacts
| Role | Who | Contact |
|---|---|---|
| Incident commander | TODO | TODO |
| Security lead | TODO | TODO |
| Legal / privacy | TODO | TODO |
"""


class Fix:
    def __init__(self, key: str, description: str, path: Path, action):
        self.key = key
        self.description = description
        self.path = path
        self.action = action


def _detect_ecosystems(root: Path) -> list[str]:
    found = []
    has_bun = (root / "bun.lock").exists() or (root / "bun.lockb").exists()
    for fname, eco in ECOSYSTEM_BY_FILE.items():
        if eco == "npm" and fname == "package.json" and has_bun:
            continue  # bun.lock is the real lockfile — don't also propose a bare npm block
        if (root / fname).exists() and eco not in found:
            found.append(eco)
    return found


def plan(root: Path, contact: str = "security@example.com",
         domain: str = "example.com") -> list[Fix]:
    fixes: list[Fix] = []

    gi = root / ".gitignore"
    existing = gi.read_text(errors="replace") if gi.is_file() else ""
    missing = [l for l in GITIGNORE_LINES if l not in existing.splitlines()]
    if missing:
        def add_gitignore():
            body = existing.rstrip("\n")
            block = "\n".join(missing)
            new = (body + "\n\n# added by dira\n" + block + "\n") if body else \
                  ("# added by dira\n" + block + "\n")
            gi.write_text(new)
        fixes.append(Fix("gitignore", f"add {len(missing)} secret patterns to .gitignore",
                         gi, add_gitignore))

    sec = root / "SECURITY.md"
    if not sec.exists():
        fixes.append(Fix("security-policy", "create SECURITY.md (vulnerability disclosure policy)",
                         sec, lambda: sec.write_text(SECURITY_MD.format(contact=contact))))

    db = root / ".github" / "dependabot.yml"
    if not db.exists() and not (root / "renovate.json").exists():
        ecos = _detect_ecosystems(root)
        blocks = "".join(ECOSYSTEM_BLOCK.format(eco=e) for e in ecos)

        def add_dependabot():
            db.parent.mkdir(parents=True, exist_ok=True)
            db.write_text(DEPENDABOT.format(ecosystems=blocks))
        fixes.append(Fix("dep-updates",
                         f"create .github/dependabot.yml ({', '.join(ecos) or 'actions'})",
                         db, add_dependabot))

    env = next((root / n for n in (".env", ".env.local") if (root / n).is_file()), None)
    example = root / ".env.example"
    if env and not example.exists():
        def add_env_example():
            keys = []
            for line in env.read_text(errors="replace").splitlines():
                m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
                if m:
                    keys.append(m.group(1))
            example.write_text("\n".join(f"{k}=" for k in keys) + "\n")
        fixes.append(Fix("env-example",
                         "derive .env.example from .env (names only, no values)",
                         example, add_env_example))

    ir = root / "docs" / "INCIDENT-RESPONSE.md"
    if not ir.exists() and not (root / "INCIDENT-RESPONSE.md").exists():
        def add_ir():
            ir.parent.mkdir(parents=True, exist_ok=True)
            ir.write_text(INCIDENT_MD)
        fixes.append(Fix("incident-plan", "create docs/INCIDENT-RESPONSE.md", ir, add_ir))

    st = root / ".well-known" / "security.txt"
    if not st.exists() and (root / "index.html").exists():
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")

        def add_security_txt():
            st.parent.mkdir(parents=True, exist_ok=True)
            st.write_text(SECURITY_TXT.format(contact=contact, expires=expires, domain=domain))
        fixes.append(Fix("security-txt", "publish /.well-known/security.txt", st, add_security_txt))

    return fixes


def manual_steps(result) -> list[str]:
    """Things a tool must not do for you."""
    steps: list[str] = []
    ids = {f.id for f in result.findings}
    if any(i.startswith(("secret/", "git-history/")) for i in ids):
        steps.append("ROTATE every credential reported above — a scanner can find a key, "
                     "it cannot un-leak one.")
    if any(i.startswith("git-history/") for i in ids):
        steps.append("Purge history: `git filter-repo --invert-paths --path <file>`, then "
                     "force-push and tell collaborators to re-clone.")
    if "config/committed-secret-file" in ids or "git/tracked-secret-file" in ids:
        steps.append("Untrack the committed credential files: `git rm --cached <file>`.")
    if any(i.startswith("deps/") for i in ids):
        steps.append("Upgrade the vulnerable dependencies listed above, then re-run dira.")
    steps.extend(MANUAL[:3])
    return steps
