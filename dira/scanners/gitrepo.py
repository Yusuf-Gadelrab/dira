"""Git hygiene: tracked secrets, history leaks, and repo settings."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..core import Finding, redact
from ..rules import DANGEROUS_FILES, is_placeholder, scan_secrets

NAME = "git"


def _git(root: Path, *args: str, timeout: int = 25) -> str:
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def scan(root: Path, history_commits: int = 200) -> list[Finding]:
    if not (root / ".git").exists():
        return []
    out: list[Finding] = []

    tracked = set(_git(root, "ls-files").splitlines())

    gitignore = root / ".gitignore"
    ig_text = gitignore.read_text(errors="replace") if gitignore.is_file() else ""
    if not ig_text:
        out.append(Finding(
            id="git/no-gitignore", title="No .gitignore in the repository",
            severity="medium", scanner=NAME, path=".gitignore", line=0, evidence="",
            remediation="Add a .gitignore covering .env*, credentials, keys, build output, and local state."))
    else:
        for needle in (".env", "*.pem", "node_modules"):
            if needle not in ig_text:
                out.append(Finding(
                    id="git/gitignore-gap", title=f".gitignore does not cover `{needle}`",
                    severity="low", scanner=NAME, path=".gitignore", line=0, evidence=needle,
                    remediation=f"Add `{needle}` to .gitignore."))

    for pat, sev, why in DANGEROUS_FILES:
        for f in tracked:
            base = f.rsplit("/", 1)[-1]
            hit = (base == pat) if "*" not in pat else base.endswith(pat.lstrip("*"))
            if hit and not any(x in base for x in ("example", "sample", "template")):
                out.append(Finding(
                    id="git/tracked-secret-file", title=f"{why} (tracked by git)",
                    severity=sev, scanner=NAME, path=f, line=0, evidence=base,
                    remediation="`git rm --cached` it, add to .gitignore, purge history with "
                                "git-filter-repo, and rotate the credentials."))

    out.extend(_history_secrets(root, history_commits))

    origin = _git(root, "remote", "get-url", "origin").strip()
    if origin.startswith("https://") and "@" in origin.split("//", 1)[1].split("/", 1)[0]:
        out.append(Finding(
            id="git/remote-credentials", title="Git remote URL embeds credentials",
            severity="high", scanner=NAME, path=".git/config", line=0,
            evidence=redact(origin, 12),
            remediation="Switch to SSH or a credential helper; the token is stored in plaintext in .git/config."))
    return out


def _history_secrets(root: Path, commits: int) -> list[Finding]:
    """Scan recent commit diffs — a rotated-out secret is still a live secret."""
    diff = _git(root, "log", f"-{commits}", "-p", "--no-color", "--no-merges",
                "--diff-filter=AM", "-U0", timeout=60)
    if not diff:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    commit = ""
    for chunk in diff.split("\ncommit ")[:commits + 1]:
        sha = chunk.split("\n", 1)[0].strip()[:8]
        commit = sha or commit
        added = "\n".join(l[1:] for l in chunk.splitlines()
                          if l.startswith("+") and not l.startswith("+++"))
        if not added:
            continue
        for rule, m in scan_secrets(added):
            if rule.id == "generic-secret":
                continue  # too noisy across history; live-tree scan covers it
            value = next((g for g in m.groups() if g), m.group(0))
            if is_placeholder(value) and rule.id != "private-key":
                continue
            key = f"{rule.id}:{value[:24]}"
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                id=f"git-history/{rule.id}",
                title=f"{rule.title} found in git history (commit {commit})",
                severity=rule.severity, scanner=NAME, path=f"git history @ {commit}", line=0,
                evidence=redact(value),
                remediation="Deleting the file does not remove it from history — rotate the "
                            "credential now, then purge with git-filter-repo and force-push.",
                reference="https://cwe.mitre.org/data/definitions/540.html"))
    return out[:40]
