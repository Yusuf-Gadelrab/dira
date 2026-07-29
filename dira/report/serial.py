"""JSON, SARIF 2.1.0 (GitHub code scanning), and Markdown (PR comment) output."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..core import ScanResult, SEVERITY_ORDER

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}
SARIF_RANK = {"critical": 9.5, "high": 8.0, "medium": 5.0, "low": 3.0, "info": 1.0}


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "dira",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": result.root,
        "grade": result.grade(),
        "risk_score": result.risk_score(),
        "counts": result.counts(),
        "readiness": result.readiness,
        "stats": result.stats,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2)


def to_sarif(result: ScanResult) -> str:
    rules, seen = [], set()
    for f in result.findings:
        if f.id in seen:
            continue
        seen.add(f.id)
        rules.append({
            "id": f.id,
            "name": f.id.replace("/", "_"),
            "shortDescription": {"text": f.title[:120]},
            "fullDescription": {"text": f.remediation or f.title},
            "helpUri": f.reference or "https://github.com/Yusuf-Gadelrab/dira",
            "help": {"text": f.remediation or ""},
            "properties": {"security-severity": str(SARIF_RANK[f.severity]),
                           "tags": ["security", f.scanner]},
            "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
        })

    results = []
    for f in result.findings:
        loc = {"physicalLocation": {
            "artifactLocation": {"uri": f.path or "."},
            "region": {"startLine": max(1, f.line)},
        }} if f.path and not f.path.startswith("http") else {
            "physicalLocation": {"artifactLocation": {"uri": "."},
                                 "region": {"startLine": 1}}}
        results.append({
            "ruleId": f.id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}" + (f" — {f.evidence}" if f.evidence else "")},
            "locations": [loc],
            "partialFingerprints": {"diraFingerprint/v1": f.fingerprint()},
        })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DIRA",
                "informationUri": "https://github.com/Yusuf-Gadelrab/dira",
                "version": result.stats.get("ruleset", "1.0.0"),
                "rules": rules}},
            "results": results,
        }],
    }, indent=2)


def to_markdown(result: ScanResult) -> str:
    c = result.counts()
    lines = [
        "## 🛡️ DIRA security scan",
        "",
        f"**Grade `{result.grade()}`** · risk {result.risk_score()}/100"
        + (f" · readiness {result.readiness['score']}% ({result.readiness['tier']})"
           if result.readiness else ""),
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |",
        "",
    ]
    top = [f for f in result.findings if f.severity in ("critical", "high", "medium")][:25]
    if not top:
        lines.append("No critical, high, or medium findings. ✅")
    else:
        lines += ["| Sev | Finding | Location |", "|---|---|---|"]
        for f in top:
            loc = (f"`{f.path}{':' + str(f.line) if f.line else ''}`"
                   if f.path and f.path != "." else "—")
            title = f.title.replace("|", "\\|")[:90]
            lines.append(f"| {f.severity} | {title} | {loc} |")
        remaining = len(result.findings) - len(top)
        if remaining > 0:
            lines.append("")
            lines.append(f"_+{remaining} more findings — run `dira scan --format html` for the full report._")
    lines += ["", f"<sub>{result.stats.get('files_scanned', 0)} files · "
                  f"{result.stats.get('duration_sec', 0)}s · dira</sub>"]
    return "\n".join(lines)


def to_baseline(result: ScanResult) -> str:
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "Fingerprints listed here are suppressed on future scans.",
        "fingerprints": sorted({f.fingerprint() for f in result.findings}),
    }, indent=2)


def severity_at_least(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(threshold)
