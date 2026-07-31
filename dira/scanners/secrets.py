"""Secret detection: one regex pass per file, entropy-gated generic rule."""

from __future__ import annotations

from pathlib import Path

from ..core import Finding, line_of, read_text, redact
from ..rules import (DOC_EXT, TEST_PATH_RE, is_minified, is_placeholder,
                     scan_secrets, shannon_entropy)

NAME = "secrets"


def scan_file(path: Path, rel: str) -> list[Finding]:
    text = read_text(path)
    if not text:
        return []
    # Minified/generated bundles are wall-to-wall high-entropy mangled identifiers, so
    # the entropy-gated generic rule fires on essentially every one of them. Precise
    # provider rules still run — a NEXT_PUBLIC key compiled into a bundle is exactly
    # the kind of leak worth shipping this tool for.
    minified = is_minified(path.name, text)
    is_low_trust = bool(TEST_PATH_RE.search(rel)) or path.suffix.lower() in DOC_EXT
    is_example_env = path.name.startswith(".env") and (
        "example" in path.name or "sample" in path.name or "template" in path.name)

    out: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for rule, m in scan_secrets(text):
        if minified and rule.entropy:
            continue
        # Group 1 of a match is the master alternation's per-rule wrapper, i.e. the whole
        # match including the variable name. The rule's own capture is the innermost —
        # take the last non-empty group. Using the first meant `client_secret = "<real
        # key>"` was judged a placeholder because "secret" appears in the *name*, and it
        # made evidence redact the assignment rather than the credential.
        groups = [g for g in m.groups() if g]
        value = groups[-1] if groups else m.group(0)
        if rule.id in ("private-key", "gcp-service-account"):
            pass  # structural markers, not a captured value — nothing to gate on
        elif is_placeholder(value):
            continue
        elif rule.entropy and shannon_entropy(value) < rule.entropy:
            # Applies to generic-secret and any newer, looser-charset provider rule
            # that opted into an entropy floor — tight fixed-prefix rules (AKIA…,
            # sk-ant-…) leave `entropy` at 0.0 since their prefix is signal enough.
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

    # A provider rule identifies the same value precisely and at the right severity,
    # so the generic catch-all on that line is pure duplicate noise.
    typed_lines = {f.line for f in out if f.id != "secret/generic-secret"}
    return [f for f in out if f.id != "secret/generic-secret" or f.line not in typed_lines]
