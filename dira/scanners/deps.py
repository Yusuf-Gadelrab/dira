"""Dependency vulnerability scanning via OSV.dev (free, no API key, batched)."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core import Finding, read_text

NAME = "deps"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 900          # OSV caps a batch at 1000 queries
MAX_DETAIL_LOOKUPS = 120  # keep a huge lockfile from turning into 5k HTTP calls


def _post(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "dira-scan"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "dira-scan"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# --- manifest parsers -------------------------------------------------------

def _npm_lock(text: str) -> list[tuple[str, str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version")
        if name and ver:
            out.append((name, ver, "npm"))

    def walk(deps: dict):
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append((name, meta["version"], "npm"))
                walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return out


_YARN_RE = re.compile(r'(?m)^"?((?:@[^/@\s"]+/)?[^@\s"]+)@[^\n]*?:\n(?:.*\n)*?\s+version:?\s+"?([^"\s]+)"?')


def _yarn_lock(text: str):
    return [(m.group(1), m.group(2), "npm") for m in _YARN_RE.finditer(text)]


_PNPM_RE = re.compile(r"(?m)^\s+/?((?:@[^/]+/)?[^/@\s]+)[/@](\d+\.\d+\.\d+[^\s:(]*)")


def _pnpm_lock(text: str):
    return [(m.group(1), m.group(2), "npm") for m in _PNPM_RE.finditer(text)]


_REQ_RE = re.compile(r"(?m)^\s*([A-Za-z0-9._\-]+)\s*==\s*([0-9][^\s;#\\]*)")


def _requirements(text: str):
    return [(m.group(1), m.group(2), "PyPI") for m in _REQ_RE.finditer(text)]


_TOML_PKG_RE = re.compile(r'(?ms)^\[\[package\]\](.*?)(?=^\[\[|\Z)')


def _toml_lock(text: str, eco: str):
    out = []
    for block in _TOML_PKG_RE.findall(text):
        n = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
        v = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"', block)
        if n and v:
            out.append((n.group(1), v.group(1), eco))
    return out


def _pipfile_lock(text: str):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "")
            if ver.startswith("=="):
                out.append((name, ver[2:], "PyPI"))
    return out


_GOMOD_RE = re.compile(r"(?m)^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[^\s]+)\s+v([^\s/]+)")


def _go_mod(text: str):
    return [(m.group(1), m.group(2), "Go") for m in _GOMOD_RE.finditer(text)
            if "// indirect" not in m.group(0)]


_GEM_RE = re.compile(r"(?m)^\s{4}([A-Za-z0-9._\-]+) \(([\d][^)]*)\)")


def _gemfile_lock(text: str):
    return [(m.group(1), m.group(2), "RubyGems") for m in _GEM_RE.finditer(text)]


PARSERS = {
    "package-lock.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "requirements.txt": _requirements,
    "requirements-dev.txt": _requirements,
    "Pipfile.lock": _pipfile_lock,
    "Gemfile.lock": _gemfile_lock,
    "go.mod": _go_mod,
    "poetry.lock": lambda t: _toml_lock(t, "PyPI"),
    "uv.lock": lambda t: _toml_lock(t, "PyPI"),
    "Cargo.lock": lambda t: _toml_lock(t, "crates.io"),
}


def collect_packages(files: list[tuple[Path, str]]) -> tuple[list[tuple[str, str, str]], list[str]]:
    pkgs: set[tuple[str, str, str]] = set()
    manifests: list[str] = []
    for path, rel in files:
        parser = PARSERS.get(path.name)
        if not parser:
            continue
        text = read_text(path)
        if not text:
            continue
        found = parser(text)
        if found:
            manifests.append(rel)
            pkgs.update(found)
    return sorted(pkgs), manifests


def _severity_of(vuln: dict) -> str:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.lower() in ("critical", "high", "moderate", "medium", "low"):
        return {"moderate": "medium"}.get(ds.lower(), ds.lower())
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        m = re.search(r"/(?:C|A):", score)
        if sev.get("type", "").startswith("CVSS"):
            base = _cvss_base(score)
            if base is not None:
                return ("critical" if base >= 9 else "high" if base >= 7
                        else "medium" if base >= 4 else "low")
            if m:
                return "high"
    return "medium"


_CVSS_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}


def _cvss_base(vector: str):
    """Rough CVSS3 base estimate from the vector string (OSV rarely ships numeric scores)."""
    if not vector.startswith("CVSS:3"):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    impact_parts = [_CVSS_WEIGHTS.get(parts.get(k, "N"), 0.0) for k in ("C", "I", "A")]
    iss = 1 - ((1 - impact_parts[0]) * (1 - impact_parts[1]) * (1 - impact_parts[2]))
    if iss <= 0:
        return 0.0
    scope_changed = parts.get("S") == "C"
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
    ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
    pr_map = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}
    pr = pr_map.get(parts.get("PR", "N"), 0.85)
    ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
    exploit = 8.22 * av * ac * pr * ui
    total = min((1.08 if scope_changed else 1.0) * (impact + exploit), 10.0)
    import math
    return math.ceil(total * 10) / 10


def _fixed_version(vuln: dict, name: str) -> str:
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return ""


def scan(files: list[tuple[Path, str]], timeout: float = 20.0,
         offline: bool = False, workers: int = 8) -> tuple[list[Finding], dict]:
    pkgs, manifests = collect_packages(files)
    stats = {"packages": len(pkgs), "manifests": manifests, "online": not offline}
    if not pkgs:
        return [], stats
    if offline:
        stats["note"] = "offline: dependency CVE lookup skipped"
        return [], stats

    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for n, v, e in pkgs]
    results: list[dict] = []
    try:
        for i in range(0, len(queries), BATCH_SIZE):
            chunk = queries[i:i + BATCH_SIZE]
            resp = _post(OSV_BATCH, {"queries": chunk}, timeout)
            results.extend(resp.get("results", []))
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as e:
        stats["error"] = f"OSV lookup failed ({e.__class__.__name__}); dependency CVEs not checked"
        stats["online"] = False
        return [], stats

    hits: list[tuple[tuple[str, str, str], str]] = []
    for pkg, res in zip(pkgs, results):
        for v in (res or {}).get("vulns", []) or []:
            hits.append((pkg, v["id"]))

    ids = list(dict.fromkeys(vid for _, vid in hits))[:MAX_DETAIL_LOOKUPS]
    details: dict[str, dict] = {}
    if ids:
        def fetch(vid: str):
            try:
                return vid, _get(OSV_VULN + vid, timeout)
            except Exception:
                return vid, {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for vid, d in ex.map(fetch, ids):
                details[vid] = d

    manifest_hint = manifests[0] if manifests else ""
    findings = []
    for (name, ver, eco), vid in hits:
        d = details.get(vid, {})
        if d.get("withdrawn"):
            continue
        sev = _severity_of(d) if d else "medium"
        fixed = _fixed_version(d, name)
        aliases = [a for a in (d.get("aliases") or []) if a.startswith("CVE-")]
        label = aliases[0] if aliases else vid
        findings.append(Finding(
            id=f"deps/{vid}",
            title=f"{name} {ver} — {label}: {(d.get('summary') or 'known vulnerability')[:110]}",
            severity=sev, scanner=NAME, path=manifest_hint, line=0,
            evidence=f"{eco}:{name}@{ver}",
            remediation=(f"Upgrade {name} to {fixed} or later." if fixed
                         else f"No fixed version published — pin, patch, or replace {name}."),
            reference=f"https://osv.dev/vulnerability/{vid}"))

    stats["vulnerable_packages"] = len({f.evidence for f in findings})
    stats["detail_lookups"] = len(ids)
    if len(set(vid for _, vid in hits)) > MAX_DETAIL_LOOKUPS:
        stats["truncated"] = f"severity detail fetched for first {MAX_DETAIL_LOOKUPS} advisories only"
    return findings, stats
