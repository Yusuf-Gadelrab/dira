"""Secret detection: one regex pass per file, entropy-gated generic rule."""

from __future__ import annotations

from pathlib import Path

from ..core import Finding, line_of, read_text, redact
from ..rules import (DOC_EXT, TEST_PATH_RE, is_placeholder, scan_secrets,
                     shannon_entropy)

NAME = "secrets"


def scan_file(path: Path, rel: str) -> list[Finding]:
    text = read_text(path)
    if not text:
        return []
    is_low_trust = bool(TEST_PATH_RE.search(rel)) or path.suffix.lower() in DOC_EXT
    is_example_env = path.name.startswith(".env") and (
        "example" in path.name or "sample" in path.name or "template" in path.name)

    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule, m in scan_secrets(text):
        value = next((g for g in m.groups() if g), m.group(0))
        if rule.id == "generic-secret":
            if is_placeholder(value) or shannon_entropy(value) < rule.entropy:
                continue
        elif rule.id not in ("private-key", "gcp-service-account") and is_placeholder(value):
            continue

        sev = rule.severity
        if is_low_trust or is_example_env:
            # Still report, but a fixture/README hit is not a production incident.
            sev = {"critical": "medium", "high": "low", "medium": "low"}.get(sev, "info")

        line = line_of(text, m.start())
        key = (rule.id, line)
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            id=f"secret/{rule.id}",
            title=rule.title + (" (in test/docs path)" if is_low_trust or is_example_env else ""),
            severity=sev,
            scanner=NAME,
            path=rel,
            line=line,
            evidence=redact(value),
            remediation=rule.remediation,
            reference="https://cwe.mitre.org/data/definitions/798.html",
        ))
    return out
