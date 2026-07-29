"""dira — security audit for startup codebases."""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from . import __version__
from .engine import ALL_SCANNERS, scan
from .report import html as html_report
from .report import serial
from .report import terminal

BANNER = "dira · درع — security audit for startups"


def _load_baseline(path: Path | None) -> set[str]:
    if not path or not path.is_file():
        return set()
    try:
        return set(json.loads(path.read_text()).get("fingerprints", []))
    except (OSError, ValueError):
        return set()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dira", description=BANNER)
    p.add_argument("--version", action="version", version=f"dira {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a codebase (default command)")
    s.add_argument("path", nargs="?", default=".", help="directory to scan")
    s.add_argument("-t", "--target", help="live domain to also audit (headers, TLS, exposed paths)")
    s.add_argument("-f", "--format", default="terminal",
                   choices=["terminal", "json", "sarif", "html", "markdown"])
    s.add_argument("-o", "--output", help="write the report to a file")
    s.add_argument("--open", action="store_true", help="open the HTML report in a browser")
    s.add_argument("--only", help="comma-separated scanners: " + ",".join(ALL_SCANNERS))
    s.add_argument("--skip", help="comma-separated scanners to disable")
    s.add_argument("--fail-on", default="high",
                   choices=["critical", "high", "medium", "low", "info", "never"],
                   help="exit 1 when a finding at/above this severity exists (default: high)")
    s.add_argument("--baseline", help="baseline JSON of fingerprints to suppress")
    s.add_argument("--offline", action="store_true", help="no network (skips OSV + surface checks)")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--no-probe", action="store_true", help="skip live path probing on --target")
    s.add_argument("--diff", metavar="REF",
                   help="only scan files changed since REF (e.g. origin/main) — fast PR gate")
    s.add_argument("--history", type=int, default=200, help="commits of git history to scan")
    s.add_argument("--workers", type=int)
    s.add_argument("-v", "--verbose", action="store_true")

    b = sub.add_parser("baseline", help="write a baseline file that suppresses today's findings")
    b.add_argument("path", nargs="?", default=".")
    b.add_argument("-o", "--output", default=".dira-baseline.json")
    b.add_argument("--offline", action="store_true")

    sub.add_parser("rules", help="list every detection rule")

    sb = sub.add_parser("sbom", help="generate a CycloneDX or SPDX software bill of materials")
    sb.add_argument("path", nargs="?", default=".")
    sb.add_argument("-f", "--format", default="cyclonedx", choices=["cyclonedx", "spdx"])
    sb.add_argument("-o", "--output", help="write to a file instead of stdout")

    fx = sub.add_parser("fix", help="apply the safe, additive remediations (dry-run by default)")
    fx.add_argument("path", nargs="?", default=".")
    fx.add_argument("--apply", action="store_true", help="actually write the files")
    fx.add_argument("--contact", default="security@example.com",
                    help="security contact address used in generated policy files")
    fx.add_argument("--domain", default="example.com", help="domain used in security.txt")
    fx.add_argument("--only", help="comma-separated fix keys to apply")

    i = sub.add_parser("init", help="install CI workflow + pre-commit hook into the repo")
    i.add_argument("path", nargs="?", default=".")
    return p


def cmd_scan(a) -> int:
    root = Path(a.path).expanduser().resolve()
    if not root.is_dir():
        print(f"dira: {root} is not a directory", file=sys.stderr)
        return 2

    enabled = [s.strip() for s in a.only.split(",")] if a.only else list(ALL_SCANNERS)
    if a.skip:
        skip = {s.strip() for s in a.skip.split(",")}
        enabled = [s for s in enabled if s not in skip]
    bad = [s for s in enabled if s not in ALL_SCANNERS]
    if bad:
        print(f"dira: unknown scanner(s): {', '.join(bad)}", file=sys.stderr)
        return 2
    if a.offline:
        enabled = [s for s in enabled if s != "surface"]  # deps still runs, minus the OSV call

    result = scan(
        root, enabled=enabled, target=a.target, offline=a.offline,
        use_cache=not a.no_cache, workers=a.workers, history_commits=a.history,
        probe=not a.no_probe, diff_ref=a.diff,
        baseline=_load_baseline(Path(a.baseline) if a.baseline else None))

    if a.format == "json":
        body = serial.to_json(result)
    elif a.format == "sarif":
        body = serial.to_sarif(result)
    elif a.format == "markdown":
        body = serial.to_markdown(result)
    elif a.format == "html":
        body = html_report.render(result, title=f"Security Audit — {root.name or 'project'}")
    else:
        body = terminal.render(result, verbose=a.verbose)

    if a.output:
        out = Path(a.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body)
        print(terminal.render(result, verbose=a.verbose) if a.format != "terminal" else body)
        if a.format != "terminal":
            print(f"\n  report written → {out}")
        if a.open and a.format == "html":
            webbrowser.open(out.resolve().as_uri())
    else:
        print(body)

    if a.fail_on == "never":
        return 0
    worst = [f for f in result.findings if serial.severity_at_least(f.severity, a.fail_on)]
    return 1 if worst else 0


def cmd_sbom(a) -> int:
    from .core import load_ignore_patterns, walk_files
    from .report import sbom as sbom_report
    from .scanners import deps as deps_scanner
    from .scanners.licenses import project_license

    root = Path(a.path).expanduser().resolve()
    files = [(p, str(p.relative_to(root))) for p in walk_files(root, load_ignore_patterns(root))]
    packages, manifests = deps_scanner.collect_packages(files)
    if not packages:
        print("dira: no lockfiles or manifests found — nothing to bill.", file=sys.stderr)
        return 2

    name = root.name or "project"
    if a.format == "spdx":
        body = sbom_report.to_spdx(packages, name, str(root))
    else:
        body = sbom_report.to_cyclonedx(packages, name, str(root), project_license(root))

    if a.output:
        out = Path(a.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(body)
        print(f"{len(packages)} components from {', '.join(manifests)} → {out}")
    else:
        print(body)
    return 0


def cmd_fix(a) -> int:
    from . import fixer

    root = Path(a.path).expanduser().resolve()
    fixes = fixer.plan(root, contact=a.contact, domain=a.domain)
    if a.only:
        want = {k.strip() for k in a.only.split(",")}
        fixes = [f for f in fixes if f.key in want]

    if not fixes:
        print("Nothing safe left to auto-fix — the additive remediations are already in place.")
        return 0

    for f in fixes:
        mark = "✔" if a.apply else "•"
        print(f"  {mark} {f.description}")
        print(f"      {f.path}")
        if a.apply:
            f.action()

    if not a.apply:
        print(f"\n  Dry run — {len(fixes)} change(s) not written. Re-run with --apply.")
        print("  Tip: pass --contact you@yourdomain.com --domain yourdomain.com first.")
    else:
        print(f"\n  {len(fixes)} change(s) written. Review the diff before committing.")

    result = scan(root, enabled=["secrets", "config", "git"], offline=True, use_cache=False)
    manual = fixer.manual_steps(result)
    if manual:
        print("\n  Cannot be automated — do these yourself:")
        for m in manual:
            print(f"    ☐ {m}")
    return 0


def cmd_baseline(a) -> int:
    result = scan(Path(a.path).expanduser(), offline=a.offline, use_cache=False)
    out = Path(a.output)
    out.write_text(serial.to_baseline(result))
    print(f"baseline written → {out} ({len(result.findings)} findings suppressed)")
    print("Fix these over time; new issues will still fail the build.")
    return 0


def cmd_rules(_a) -> int:
    from .rules import CONFIG_RULES, DANGEROUS_FILES, SECRET_RULES
    from .scanners.readiness import CHECKS
    print(f"\n{BANNER}\n")
    print("SECRET RULES")
    for r in SECRET_RULES:
        print(f"  secret/{r.id:<24} {r.severity:<9} {r.title}")
    print("\nCONFIG / IaC RULES")
    for rid, title, sev, glob, *_ in CONFIG_RULES:
        print(f"  config/{rid:<24} {sev:<9} {title}  [{glob}]")
    print("\nFILES THAT MUST NOT BE COMMITTED")
    for pat, sev, why in DANGEROUS_FILES:
        print(f"  {pat:<26} {sev:<9} {why}")
    print("\nREADINESS CHECKS")
    for key, label, weight, *_ in CHECKS:
        print(f"  readiness/{key:<22} {weight:>2} pts   {label}")
    print()
    return 0


WORKFLOW = """name: dira security scan
on:
  pull_request:
  push:
    branches: [main, master]
  schedule:
    - cron: '0 12 * * 1'

permissions:
  contents: read
  security-events: write

jobs:
  dira:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - run: pip install git+https://github.com/Yusuf-Gadelrab/dira@v1.1.0

      # PRs: only what changed, so the gate stays fast.
      - name: Scan changed files
        if: github.event_name == 'pull_request'
        run: dira scan . --diff origin/${{ github.base_ref }} --format sarif --output dira.sarif --fail-on high

      # Push / schedule: full scan.
      - name: Full scan
        if: github.event_name != 'pull_request'
        run: dira scan . --format sarif --output dira.sarif --fail-on high

      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: dira.sarif

      - name: Generate SBOM
        if: github.event_name != 'pull_request'
        run: dira sbom . --format cyclonedx --output sbom.cdx.json

      - uses: actions/upload-artifact@v4
        if: github.event_name != 'pull_request'
        with:
          name: sbom
          path: sbom.cdx.json
"""

PRECOMMIT = """repos:
  - repo: https://github.com/Yusuf-Gadelrab/dira
    rev: v{version}
    hooks:
      - id: dira
"""


def cmd_init(a) -> int:
    root = Path(a.path).expanduser()
    wf = root / ".github" / "workflows" / "dira.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(WORKFLOW)
    print(f"✔ CI workflow → {wf}")

    pc = root / ".pre-commit-config.yaml"
    if pc.exists():
        print(f"• {pc} already exists — add this block manually:\n\n{PRECOMMIT.format(version=__version__)}")
    else:
        pc.write_text(PRECOMMIT.format(version=__version__))
        print(f"✔ pre-commit hook → {pc}  (run `pre-commit install`)")

    gi = root / ".gitignore"
    line = ".dira-cache.json\n"
    if gi.exists():
        if ".dira-cache.json" not in gi.read_text():
            gi.write_text(gi.read_text().rstrip("\n") + "\n" + line)
            print("✔ .dira-cache.json added to .gitignore")
    else:
        gi.write_text(line)
        print("✔ .gitignore created")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("scan", "baseline", "rules", "init", "sbom", "fix",
                                "-h", "--help", "--version"):
        argv.insert(0, "scan")  # `dira .` and `dira ~/proj -t x.com` just work
    if not argv:
        argv = ["scan", "."]
    a = parser.parse_args(argv)
    try:
        return {"scan": cmd_scan, "baseline": cmd_baseline, "rules": cmd_rules,
                "init": cmd_init, "sbom": cmd_sbom, "fix": cmd_fix}[a.cmd](a)
    except KeyboardInterrupt:
        print("\naborted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
