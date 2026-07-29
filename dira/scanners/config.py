"""Misconfiguration scanning across Docker, compose, k8s, Terraform, CI, and app code."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from ..core import Finding, line_of, read_text
from ..rules import CODE_RULE_IDS, CONFIG_RULES, DANGEROUS_FILES, DOC_EXT, TEST_PATH_RE

NAME = "config"

CODE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rb", ".php",
    ".java", ".kt", ".cs", ".rs", ".sh", ".bash", ".zsh", ".yml", ".yaml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".env", ".tf", ".tfvars",
    ".sql", ".rules", ".hcl", ".svelte", ".vue", ".astro", ".swift", ".m",
}

_COMPILED = [
    (rid, title, sev, glob, re.compile(pat), fix)
    for rid, title, sev, glob, pat, fix in CONFIG_RULES
]

CWE = {
    "cors-wildcard": "https://cwe.mitre.org/data/definitions/942.html",
    "sql-injection": "https://cwe.mitre.org/data/definitions/89.html",
    "shell-injection": "https://cwe.mitre.org/data/definitions/78.html",
    "eval-use": "https://cwe.mitre.org/data/definitions/95.html",
    "tls-verify-off": "https://cwe.mitre.org/data/definitions/295.html",
    "weak-hash": "https://cwe.mitre.org/data/definitions/327.html",
    "debug-enabled": "https://cwe.mitre.org/data/definitions/489.html",
    "public-env-secret": "https://cwe.mitre.org/data/definitions/200.html",
    "token-in-localstorage": "https://cwe.mitre.org/data/definitions/522.html",
    "react-dangerous-html": "https://cwe.mitre.org/data/definitions/79.html",
    "dom-innerhtml": "https://cwe.mitre.org/data/definitions/79.html",
    "postmessage-wildcard": "https://cwe.mitre.org/data/definitions/346.html",
    "jwt-none-alg": "https://cwe.mitre.org/data/definitions/347.html",
    "llm-browser-key": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "llm-prompt-injection": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "llm-unbounded-exec": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    "firebase-open-rules": "https://cwe.mitre.org/data/definitions/732.html",
    "iam-wildcard-principal": "https://cwe.mitre.org/data/definitions/732.html",
    "iam-wildcard-action": "https://cwe.mitre.org/data/definitions/732.html",
    "gcp-allusers": "https://cwe.mitre.org/data/definitions/732.html",
    "curl-pipe-shell": "https://cwe.mitre.org/data/definitions/494.html",
}


def _matches(rel: str, name: str, glob: str) -> bool:
    if glob == "*":
        return True
    if "/" in glob:
        return fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, f"*/{glob}")
    return fnmatch.fnmatch(name, glob)


DOWNGRADE = {"critical": "medium", "high": "low", "medium": "low", "low": "info"}


def scan_file(path: Path, rel: str, tracked: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    name = path.name
    # A deliberately-vulnerable fixture is not a production incident. Report it, rank it lower.
    low_trust = bool(TEST_PATH_RE.search(rel)) or path.suffix.lower() in DOC_EXT

    for pat, sev, why in DANGEROUS_FILES:
        if fnmatch.fnmatch(name, pat) if "*" in pat else name == pat:
            if any(x in name for x in ("example", "sample", "template")):
                break
            # Only git can say whether the file was actually committed. Every developer has a
            # local untracked .env; calling that a critical breach is the fastest way to get
            # a scanner uninstalled. `tracked` is None when the target is not a git repo.
            if tracked is not None and rel not in tracked:
                out.append(Finding(
                    id="config/untracked-secret-file",
                    title=f"`{name}` is present and not ignored — one `git add` from being committed",
                    severity=DOWNGRADE.get(sev, "low"),
                    scanner=NAME, path=rel, line=0, evidence=name,
                    remediation=f"Add `{name}` to .gitignore now. It is not in git yet, so this is "
                                "a near miss rather than an incident — no rotation needed.",
                    reference="https://cwe.mitre.org/data/definitions/540.html"))
            else:
                out.append(Finding(
                    id="config/committed-secret-file", title=why, severity=sev,
                    scanner=NAME, path=rel, line=0, evidence=name,
                    remediation="Add it to .gitignore, remove it from the index (`git rm --cached`), "
                                "purge it from history, and rotate everything it contained.",
                    reference="https://cwe.mitre.org/data/definitions/540.html"))
            break

    suffix = path.suffix.lower()
    if suffix not in CODE_EXT and not name.startswith(("Dockerfile", ".env", "Makefile")):
        return out

    text = read_text(path)
    if not text:
        return out

    for rid, title, sev, glob, rx, fix in _COMPILED:
        if rid in CODE_RULE_IDS and suffix not in CODE_EXT:
            continue
        if not _matches(rel, name, glob):
            continue
        for m in rx.finditer(text):
            line = line_of(text, m.start())
            out.append(Finding(
                id=f"config/{rid}", title=title, severity=sev, scanner=NAME,
                path=rel, line=line, evidence=m.group(0).strip()[:160],
                remediation=fix, reference=CWE.get(rid, "")))
            if len(out) > 200:
                break

    if name.startswith("Dockerfile"):
        out.extend(_dockerfile_checks(text, rel))

    if low_trust:
        for f in out:
            f.severity = DOWNGRADE.get(f.severity, f.severity)
            f.title += " (in test/docs path)"
    return out


_USER_RE = re.compile(r"(?im)^\s*USER\s+(\S+)")
_HEALTH_RE = re.compile(r"(?im)^\s*HEALTHCHECK\s")


def _dockerfile_checks(text: str, rel: str) -> list[Finding]:
    out = []
    users = _USER_RE.findall(text)
    if not users or all(u.lower() in ("root", "0") for u in users):
        out.append(Finding(
            id="config/docker-root-user", title="Container runs as root",
            severity="medium", scanner=NAME, path=rel, line=1,
            evidence="no non-root USER directive",
            remediation="Create an unprivileged user and add `USER app` before CMD/ENTRYPOINT.",
            reference="https://cwe.mitre.org/data/definitions/250.html"))
    if not _HEALTH_RE.search(text):
        out.append(Finding(
            id="config/docker-no-healthcheck", title="No container HEALTHCHECK",
            severity="info", scanner=NAME, path=rel, line=1, evidence="",
            remediation="Add a HEALTHCHECK so orchestrators can detect a wedged process."))
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Two rules can flag the same line (e.g. compose + k8s privileged). Keep the worst."""
    from ..core import SEVERITY_ORDER
    best: dict[tuple[str, int, str], Finding] = {}
    for f in findings:
        key = (f.path, f.line, f.evidence[:60])
        cur = best.get(key)
        if cur is None or SEVERITY_ORDER.index(f.severity) < SEVERITY_ORDER.index(cur.severity):
            best[key] = f
    return list(best.values())
