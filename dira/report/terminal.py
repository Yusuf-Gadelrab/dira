"""Terminal report — gold-on-black, ANSI, no dependencies."""

from __future__ import annotations

import os
import sys

from ..core import ScanResult, SEVERITY_ORDER

GOLD = "\033[38;5;178m"
GOLD_B = "\033[1;38;5;220m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"
SEV_COLOR = {
    "critical": "\033[1;38;5;196m",
    "high": "\033[38;5;208m",
    "medium": "\033[38;5;220m",
    "low": "\033[38;5;110m",
    "info": "\033[38;5;245m",
}


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def render(result: ScanResult, verbose: bool = False, max_per_rule: int = 5) -> str:
    color = _supports_color()

    def c(s: str, code: str) -> str:
        return f"{code}{s}{RESET}" if color else s

    w = 74
    out: list[str] = []
    out.append(c("╔" + "═" * w + "╗", GOLD))
    out.append(c("║", GOLD) + c("  DIRA  ".center(w, " "), GOLD_B) + c("║", GOLD))
    out.append(c("║", GOLD) + c("درع · security audit for startups".center(w), DIM) + c("║", GOLD))
    out.append(c("╚" + "═" * w + "╝", GOLD))
    out.append("")
    out.append(f"  {c('Target', DIM)}  {result.root}")
    if result.stats.get("target"):
        out.append(f"  {c('Surface', DIM)} {result.stats['target']}")

    counts = result.counts()
    grade = result.grade()
    risk = result.risk_score()
    grade_color = {"A": "\033[1;38;5;46m", "B": "\033[1;38;5;220m",
                   "C": "\033[1;38;5;208m", "D": "\033[1;38;5;202m",
                   "F": "\033[1;38;5;196m"}[grade]
    out.append("")
    out.append(f"  {c('SECURITY GRADE', BOLD)}   {c(grade, grade_color)}"
               f"   {c(f'risk {risk}/100', DIM)}")
    if result.readiness:
        r = result.readiness
        out.append(f"  {c('STARTUP READINESS', BOLD)} {c(str(r['score']) + '%', GOLD_B)}"
                   f"  {c(r['tier'], DIM)}  ({r['earned']}/{r['total']} pts)")
    out.append("")
    bar = "  " + "  ".join(
        c(f"{s.upper()} {counts[s]}", SEV_COLOR[s]) for s in SEVERITY_ORDER if counts[s])
    out.append(bar if counts and any(counts.values()) else c("  No findings.", "\033[38;5;46m"))
    out.append("")

    grouped: dict[str, list] = {}
    for f in result.findings:
        grouped.setdefault(f.id, []).append(f)

    shown = 0
    for sev in SEVERITY_ORDER:
        ids = [i for i, fs in grouped.items() if fs[0].severity == sev]
        if not ids:
            continue
        if sev in ("info",) and not verbose:
            out.append(c(f"  … {sum(len(grouped[i]) for i in ids)} info findings "
                         f"(run with --verbose)", DIM))
            continue
        out.append(c(f"  {'─' * 3} {sev.upper()} {'─' * (66 - len(sev))}", SEV_COLOR[sev]))
        for rid in ids:
            fs = grouped[rid]
            head = fs[0]
            out.append(f"  {c('●', SEV_COLOR[sev])} {c(head.title, BOLD)}"
                       + (c(f"  ×{len(fs)}", DIM) if len(fs) > 1 else ""))
            limit = len(fs) if verbose else max_per_rule
            for f in fs[:limit]:
                loc = f"{f.path}:{f.line}" if f.line else f.path
                if loc in (".", ""):
                    if f.evidence:
                        out.append(f"      {c(f.evidence, DIM)}")
                else:
                    out.append(f"      {c(loc, GOLD)}"
                               + (f"  {c(f.evidence, DIM)}" if f.evidence else ""))
                shown += 1
            if len(fs) > limit:
                out.append(c(f"      … {len(fs) - limit} more (--verbose)", DIM))
            if head.remediation:
                out.append(f"      {c('→ ' + head.remediation, DIM)}")
            if head.reference and verbose:
                out.append(f"      {c(head.reference, DIM)}")
            out.append("")

    if result.readiness and verbose:
        out.append(c("  ─── READINESS CHECKLIST " + "─" * 48, GOLD))
        for chk in result.readiness["checks"]:
            mark = c("✔", "\033[38;5;46m") if chk["passed"] else c("✘", "\033[38;5;196m")
            out.append(f"   {mark} {chk['label']} {c('(' + str(chk['weight']) + ' pts)', DIM)}")
        out.append("")
        out.append(c("   Manual attestations (cannot be verified from code):", DIM))
        for m in result.readiness["manual"]:
            out.append(c(f"    ☐ {m}", DIM))
        out.append("")

    s = result.stats
    dep = s.get("deps", {})
    lic = s.get("licenses", {})
    if lic.get("inventory"):
        top = "  ".join(f"{k} ×{v}" for k, v in list(lic["inventory"].items())[:6])
        out.append(c(f"  Licenses  {top}", DIM))
        out.append("")
    scope = (f" · diff vs {s['diff_ref']}" if s.get("diff_ref") else "")
    line = (f"  {s.get('files_scanned', 0)} files{scope} · {s.get('cache_hits', 0)} cached · "
            f"{s.get('packages', dep.get('packages', 0))} deps · {s.get('duration_sec', 0)}s")
    out.append(c(line, DIM))
    for src in (dep, lic):
        for k in ("error", "note", "truncated"):
            if src.get(k):
                out.append(c(f"  ⚠ {src[k]}", SEV_COLOR["medium"]))
    return "\n".join(out)
