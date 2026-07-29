"""DHAHAB-branded HTML report — self-contained, printable, client-shareable."""

from __future__ import annotations

import html
from datetime import datetime

from ..core import ScanResult, SEVERITY_ORDER

SEV_HEX = {"critical": "#ff4d4f", "high": "#ff8c42", "medium": "#d4af37",
           "low": "#7fb2d4", "info": "#8a8a8a"}

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--gold:#d4af37;--gold-l:#f0d98c;--ink:#0a0a0a;--ink-2:#121212;--line:#262218;--txt:#e8e4dc;--dim:#95908a}
body{background:var(--ink);color:var(--txt);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,sans-serif;
padding:56px 24px}
.wrap{max-width:960px;margin:0 auto}
h1,h2,h3,.serif{font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;font-weight:600;letter-spacing:.01em}
header{text-align:center;border-bottom:1px solid var(--line);padding-bottom:40px;margin-bottom:48px}
.mark{font-size:13px;letter-spacing:.42em;color:var(--gold);text-transform:uppercase}
h1{font-size:52px;margin:14px 0 6px;background:linear-gradient(100deg,var(--gold-l),var(--gold) 55%,#8a6d1f);
-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:var(--dim);font-size:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:18px;margin-bottom:44px}
.card{background:linear-gradient(160deg,var(--ink-2),#0d0d0d);border:1px solid var(--line);border-radius:14px;
padding:22px;text-align:center}
.card .k{font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:var(--dim)}
.card .v{font-size:42px;font-family:"Iowan Old Style",Georgia,serif;color:var(--gold-l);margin-top:6px;line-height:1.1}
.card .n{font-size:12px;color:var(--dim);margin-top:4px}
h2{font-size:13px;letter-spacing:.28em;text-transform:uppercase;color:var(--gold);margin:44px 0 18px;
padding-bottom:10px;border-bottom:1px solid var(--line)}
.f{border:1px solid var(--line);border-left:3px solid var(--sev);border-radius:12px;padding:18px 20px;margin-bottom:14px;
background:#0e0e0e}
.f .t{font-weight:600;font-size:17px}
.pill{display:inline-block;font-size:10px;letter-spacing:.16em;text-transform:uppercase;padding:3px 10px;border-radius:999px;
border:1px solid var(--sev);color:var(--sev);margin-right:10px;vertical-align:2px}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--gold);margin-top:9px;
word-break:break-all}
.ev{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--dim)}
.fix{color:#cfc9bd;font-size:14px;margin-top:10px;padding-top:10px;border-top:1px dashed var(--line)}
.fix b{color:var(--gold);font-weight:600}
a{color:var(--gold);text-decoration:none;border-bottom:1px solid rgba(212,175,55,.35)}
ul.chk{list-style:none;display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:8px}
ul.chk li{padding:11px 14px;border:1px solid var(--line);border-radius:10px;background:#0e0e0e;font-size:14px}
.ok{color:#5ac36a}.no{color:#ff6b6b}
.meter{height:7px;background:#1c1a16;border-radius:99px;overflow:hidden;margin-top:14px}
.meter i{display:block;height:100%;background:linear-gradient(90deg,var(--gold),var(--gold-l))}
footer{margin-top:64px;padding-top:26px;border-top:1px solid var(--line);color:var(--dim);font-size:12.5px;text-align:center}
.none{text-align:center;padding:52px;border:1px solid var(--line);border-radius:14px;color:var(--dim)}
@media print{body{background:#fff;color:#111}.card,.f,ul.chk li{background:#fff}h1{color:#8a6d1f}}
"""


def _esc(s: str) -> str:
    return html.escape(str(s or ""))


def render(result: ScanResult, title: str = "Security Audit") -> str:
    counts = result.counts()
    r = result.readiness
    when = datetime.now().strftime("%B %d, %Y · %H:%M")

    cards = [
        ("Security grade", result.grade(), f"risk {result.risk_score()}/100"),
        ("Findings", str(len(result.findings)), f"{counts['critical']} critical · {counts['high']} high"),
    ]
    if r:
        cards.append(("Startup readiness", f"{r['score']}%", _esc(r["tier"])))
    cards.append(("Files scanned", str(result.stats.get("files_scanned", 0)),
                  f"{result.stats.get('deps', {}).get('packages', 0)} dependencies"))

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>DIRA — {_esc(title)}</title><style>{CSS}</style></head><body><div class='wrap'>",
        "<header><div class='mark'>Dhahab · Dira</div>",
        f"<h1>{_esc(title)}</h1>",
        f"<div class='sub'>{_esc(result.root)}<br>{when}</div></header>",
        "<div class='grid'>",
    ]
    for k, v, n in cards:
        parts.append(f"<div class='card'><div class='k'>{_esc(k)}</div>"
                     f"<div class='v'>{_esc(v)}</div><div class='n'>{n}</div></div>")
    parts.append("</div>")

    if not result.findings:
        parts.append("<div class='none'>No findings. Every enabled scanner came back clean.</div>")

    for sev in SEVERITY_ORDER:
        group = result.by_severity(sev)
        if not group:
            continue
        parts.append(f"<h2>{sev} · {len(group)}</h2>")
        seen: dict[str, list] = {}
        for f in group:
            seen.setdefault(f.id, []).append(f)
        for rid, fs in seen.items():
            head = fs[0]
            locs = "".join(
                f"<div class='loc'>{_esc(f.path) if f.path != '.' else ''}"
                f"{':' + str(f.line) if f.line else ''}"
                + (f" <span class='ev'>{_esc(f.evidence)}</span>" if f.evidence else "")
                + "</div>" for f in fs[:12])
            more = (f"<div class='ev' style='margin-top:6px'>+{len(fs) - 12} more occurrences</div>"
                    if len(fs) > 12 else "")
            ref = (f" <a href='{_esc(head.reference)}'>reference</a>" if head.reference else "")
            parts.append(
                f"<div class='f' style='--sev:{SEV_HEX[sev]}'>"
                f"<div class='t'><span class='pill'>{sev}</span>{_esc(head.title)}"
                + (f" <span class='ev'>×{len(fs)}</span>" if len(fs) > 1 else "") + "</div>"
                + locs + more
                + (f"<div class='fix'><b>Fix:</b> {_esc(head.remediation)}{ref}</div>"
                   if head.remediation else "")
                + "</div>")

    if r:
        parts.append(f"<h2>Startup readiness · {r['score']}%</h2>")
        parts.append(f"<div class='meter'><i style='width:{r['score']}%'></i></div>")
        parts.append("<ul class='chk' style='margin-top:18px'>")
        for c in r["checks"]:
            mark = "<span class='ok'>✔</span>" if c["passed"] else "<span class='no'>✘</span>"
            parts.append(f"<li>{mark} {_esc(c['label'])} <span class='ev'>({c['weight']} pts)</span>"
                         + ("" if c["passed"] else f"<div class='ev' style='margin-top:5px'>{_esc(c['remediation'])}</div>")
                         + "</li>")
        parts.append("</ul>")
        parts.append("<h2>Manual attestations</h2><ul class='chk'>")
        for m in r["manual"]:
            parts.append(f"<li>☐ {_esc(m)}</li>")
        parts.append("</ul>")

    lic = result.stats.get("licenses", {})
    if lic.get("inventory"):
        parts.append("<h2>License inventory</h2><ul class='chk'>")
        for name, n in lic["inventory"].items():
            parts.append(f"<li>{_esc(name)} <span class='ev'>×{n}</span></li>")
        parts.append("</ul>")

    s = result.stats
    parts.append(
        f"<footer>Generated by DIRA v{s.get('ruleset', '')} in {s.get('duration_sec', 0)}s · "
        f"{s.get('files_scanned', 0)} files · {s.get('cache_hits', 0)} cached<br>"
        "Automated analysis. It finds known patterns — it does not replace a manual "
        "penetration test or a threat model.</footer></div></body></html>")
    return "\n".join(parts)
