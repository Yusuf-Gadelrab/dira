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


_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def _strip_jsonc(text: str) -> str:
    """bun.lock is JSONC: `//` line comments and trailing commas are both legal,
    and Python's json module accepts neither."""
    out = []
    in_str = False
    escape = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return _TRAILING_COMMA_RE.sub(r"\1", "".join(out))


def _bun_lock(text: str):
    """Bun's default text lockfile since 1.1 — a `packages` map of
    `"name": ["name@version", registry, {deps}, "sha…"]`."""
    try:
        data = json.loads(_strip_jsonc(text))
    except ValueError:
        return []
    out = []
    for entry in (data.get("packages") or {}).values():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name, sep, version = entry[0].rpartition("@")
        if not sep or not name or not version:
            continue
        out.append((name, version, "npm"))
    return out


PARSERS = {
    "package-lock.json": _npm_lock,
    "yarn.lock": _yarn_lock,
    "pnpm-lock.yaml": _pnpm_lock,
    "bun.lock": _bun_lock,
    "requirements.txt": _requirements,
    "requirements-dev.txt": _requirements,
    "Pipfile.lock": _pipfile_lock,
    "Gemfile.lock": _gemfile_lock,
    "go.mod": _go_mod,
    "poetry.lock": lambda t: _toml_lock(t, "PyPI"),
    "uv.lock": lambda t: _toml_lock(t, "PyPI"),
    "Cargo.lock": lambda t: _toml_lock(t, "crates.io"),
}


# Declared-dependency manifests. These carry version *ranges*, not resolved versions, so
# they cannot be matched against OSV — but their presence without a sibling lockfile means
# CVE scanning silently covered nothing, which must never be reported as a clean result.
UNRESOLVED_MANIFESTS = {
    "package.json": ({"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
                      "bun.lock", "bun.lockb"}, "npm"),
    "pyproject.toml": ({"uv.lock", "poetry.lock", "pdm.lock", "requirements.txt"}, "PyPI"),
    "Gemfile": ({"Gemfile.lock"}, "RubyGems"),
    "Cargo.toml": ({"Cargo.lock"}, "crates.io"),
}


def _declared_count(name: str, text: str) -> int:
    try:
        if name == "package.json":
            data = json.loads(text)
            return sum(len(data.get(k) or {})
                       for k in ("dependencies", "devDependencies", "optionalDependencies"))
        if name == "pyproject.toml":
            return len(re.findall(r"(?m)^\s*[\"']?[A-Za-z0-9][\w.\-]*[\"']?\s*[=><~^]", text))
    except (ValueError, TypeError):
        pass
    return 0


def unlocked_manifests(files: list[tuple[Path, str]]) -> list[Finding]:
    """Flag manifests whose dependencies were never resolved, so the user knows the
    zero-CVE result for that ecosystem is 'not checked', not 'checked and clean'."""
    out: list[Finding] = []
    for path, rel in files:
        entry = UNRESOLVED_MANIFESTS.get(path.name)
        if not entry:
            continue
        locks, eco = entry
        if any((path.parent / lock).is_file() for lock in locks):
            continue
        text = read_text(path)
        if not text:
            continue
        n = _declared_count(path.name, text)
        if path.name == "package.json" and n == 0:
            continue
        count = f"{n} declared dependencies" if n else "declared dependencies"
        out.append(Finding(
            id="deps/unresolved-manifest",
            title=f"{path.name} has {count} but no lockfile — CVE scan skipped for {eco}",
            severity="medium", scanner=NAME, path=rel, line=0, evidence=path.name,
            remediation=f"Commit a lockfile ({' / '.join(sorted(locks))}). Without resolved "
                        "versions these packages cannot be matched against OSV, so a clean "
                        "report for this ecosystem means unchecked, not safe.",
            reference="https://cwe.mitre.org/data/definitions/1104.html"))
    return out


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


def _pkg_key(name: str, version: str, eco: str) -> str:
    return f"{eco}:{name}@{version}"


def _npm_lock_dev(data: dict) -> tuple[set[str], set[str]]:
    prod: set[str] = set()
    dev: set[str] = set()
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        ver = meta.get("version")
        if not (name and ver):
            continue
        (dev if (meta.get("dev") or meta.get("devOptional")) else prod).add(
            _pkg_key(name, ver, "npm"))
    return prod, dev


def _bun_lock_dev(data: dict) -> tuple[set[str], set[str]]:
    """bun.lock carries no per-package dev flag, so reachability is computed: anything
    not reachable from the workspace's runtime `dependencies` is build-time only."""
    entries: dict[str, tuple[str, str, list]] = {}
    for key, entry in (data.get("packages") or {}).items():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            continue
        name, sep, version = entry[0].rpartition("@")
        if sep and name and version:
            entries[key] = (name, version, entry)

    roots: set[str] = set()
    for ws in (data.get("workspaces") or {}).values():
        if isinstance(ws, dict):
            roots.update((ws.get("dependencies") or {}).keys())

    prod_keys: set[str] = set()
    stack = [r for r in roots if r in entries]
    seen: set[str] = set(stack)
    while stack:
        key = stack.pop()
        name, version, entry = entries[key]
        prod_keys.add(_pkg_key(name, version, "npm"))
        meta = entry[2] if len(entry) > 2 and isinstance(entry[2], dict) else {}
        for section in ("dependencies", "peerDependencies", "optionalDependencies"):
            for child in (meta.get(section) or {}):
                if child in entries and child not in seen:
                    seen.add(child)
                    stack.append(child)

    all_keys = {_pkg_key(n, v, "npm") for n, v, _e in entries.values()}
    return prod_keys, all_keys - prod_keys


def _pipfile_lock_dev(data: dict) -> tuple[set[str], set[str]]:
    def keys(section: str) -> set[str]:
        out = set()
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "").lstrip("=")
            if ver:
                out.add(_pkg_key(name, ver, "PyPI"))
        return out
    return keys("default"), keys("develop")


def dev_only_packages(files: list[tuple[Path, str]]) -> set[str]:
    """Packages that only ever reach a build machine, never production traffic.

    This is the single biggest relevance lever in dependency scanning. A prototype-
    pollution CVE in a bundler plugin and the same CVE in the request path of a live
    API are not the same finding, and grading a repo `F` because its build tooling has
    known advisories is how a scanner gets classified as noise and switched off.
    Reported either way — ranked one level lower, and labelled.
    """
    prod: set[str] = set()
    dev: set[str] = set()
    for path, _rel in files:
        if path.name not in ("package-lock.json", "bun.lock", "Pipfile.lock",
                             "requirements-dev.txt"):
            continue
        text = read_text(path)
        if not text:
            continue
        if path.name == "requirements-dev.txt":
            dev.update(_pkg_key(n, v, e) for n, v, e in _requirements(text))
            continue
        try:
            data = json.loads(_strip_jsonc(text) if path.name == "bun.lock" else text)
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        fn = {"package-lock.json": _npm_lock_dev, "bun.lock": _bun_lock_dev,
              "Pipfile.lock": _pipfile_lock_dev}[path.name]
        try:
            p, d = fn(data)
        except (AttributeError, TypeError, ValueError):
            continue
        prod |= p
        dev |= d
    return dev - prod


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


DEV_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}


def scan(files: list[tuple[Path, str]], timeout: float = 20.0,
         offline: bool = False, workers: int = 8) -> tuple[list[Finding], dict]:
    pkgs, manifests = collect_packages(files)
    dev_only = dev_only_packages(files)
    stats = {"packages": len(pkgs), "manifests": manifests, "online": not offline,
             "dev_only_packages": len(dev_only)}
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
        is_dev = _pkg_key(name, ver, eco) in dev_only
        remediation = (f"Upgrade {name} to {fixed} or later." if fixed
                       else f"No fixed version published — pin, patch, or replace {name}.")
        if is_dev:
            sev = DEV_DOWNGRADE.get(sev, sev)
            remediation += (" This package is build/dev-time only and is not reachable from "
                            "production traffic, so it is ranked one level lower — it still "
                            "matters if your CI runs untrusted code or builds are attacker-"
                            "influenced.")
        findings.append(Finding(
            id=f"deps/{vid}",
            title=f"{name} {ver}{' (dev-only)' if is_dev else ''} — {label}: "
                  f"{(d.get('summary') or 'known vulnerability')[:110]}",
            severity=sev, scanner=NAME, path=manifest_hint, line=0,
            evidence=f"{eco}:{name}@{ver}",
            remediation=remediation,
            reference=f"https://osv.dev/vulnerability/{vid}"))

    stats["vulnerable_packages"] = len({f.evidence for f in findings})
    stats["detail_lookups"] = len(ids)
    if len(set(vid for _, vid in hits)) > MAX_DETAIL_LOOKUPS:
        stats["truncated"] = f"severity detail fetched for first {MAX_DETAIL_LOOKUPS} advisories only"
    return findings, stats


# --- supply chain: floating/git dependencies, install hooks, typosquats ----
# All three run offline, straight off the manifest text already read for
# `unlocked_manifests`, so they cost nothing extra on an --offline run.

_FLOAT_SPEC_RE = re.compile(r"^\*$|^latest$", re.IGNORECASE)
_GIT_SPEC_RE = re.compile(r"^(?:git\+|git://|github:|[\w-]+/[\w.-]+#)")
INSTALL_HOOK_KEYS = ("preinstall", "install", "postinstall")
_DANGEROUS_HOOK_RE = re.compile(r"(?i)\bcurl\s|\bwget\s|\bnode\s+-e\b|\beval\(|\|\s*(?:sudo\s+)?(?:ba|z|s)?sh\b")


def unpinned_dependency_findings(files: list[tuple[Path, str]]) -> list[Finding]:
    """Floating (`*`/`latest`) or git-ref `package.json` dependencies resolve to
    whatever exists at install time — a lockfile pins the *result*, not the risk
    that the next `npm install` (a fresh CI runner, a new hire) resolves differently."""
    out: list[Finding] = []
    for path, rel in files:
        if path.name != "package.json":
            continue
        text = read_text(path)
        if not text:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if not isinstance(spec, str):
                    continue
                spec = spec.strip()
                if _FLOAT_SPEC_RE.match(spec):
                    out.append(Finding(
                        id="deps/floating-version",
                        title=f"{name} is pinned to \"{spec}\" — resolves to whatever is newest at install time",
                        severity="medium", scanner=NAME, path=rel, line=0,
                        evidence=f"{name}: {spec}",
                        remediation="A floating version means every fresh install can silently pull a "
                                    "different, unreviewed release. Pin a version range and let the "
                                    "lockfile carry the reproducibility.",
                        reference="https://cwe.mitre.org/data/definitions/1357.html"))
                elif _GIT_SPEC_RE.match(spec):
                    out.append(Finding(
                        id="deps/git-dependency",
                        title=f"{name} installs directly from a git ref, bypassing registry integrity checks",
                        severity="medium", scanner=NAME, path=rel, line=0,
                        evidence=f"{name}: {spec}",
                        remediation="Git-ref dependencies ship no published checksum and can change without "
                                    "a version bump. Prefer a published registry release; if you must use "
                                    "git, pin an exact commit SHA, never a branch name.",
                        reference="https://cwe.mitre.org/data/definitions/829.html"))
    return out


def install_hook_findings(files: list[tuple[Path, str]]) -> list[Finding]:
    """npm lifecycle scripts run automatically on `npm install` — for you, for CI, and
    for everyone who depends on your package. event-stream, ua-parser-js, and node-ipc
    were all compromised through exactly this hook."""
    out: list[Finding] = []
    for path, rel in files:
        if path.name != "package.json":
            continue
        text = read_text(path)
        if not text:
            continue
        try:
            scripts = json.loads(text).get("scripts") or {}
        except (ValueError, AttributeError):
            continue
        for key in INSTALL_HOOK_KEYS:
            cmd = scripts.get(key)
            if not cmd or not isinstance(cmd, str):
                continue
            dangerous = bool(_DANGEROUS_HOOK_RE.search(cmd))
            out.append(Finding(
                id="deps/install-script-hook",
                title=f"package.json runs a `{key}` lifecycle script on install"
                      + (" — pipes a remote script into a shell" if dangerous else ""),
                severity="high" if dangerous else "medium", scanner=NAME, path=rel, line=0,
                evidence=cmd[:160],
                remediation="Lifecycle scripts run unattended on every install. Review it, vendor it if "
                            "trivial, and run untrusted-dependency installs with "
                            "`npm config set ignore-scripts true` in CI.",
                reference="https://cwe.mitre.org/data/definitions/506.html"))
    return out


# Curated, not exhaustive — the packages with a real history of being typosquatted
# (event-stream/flatmap-stream, ua-parser-js, node-ipc, colours, python3-dateutil…)
# plus the highest-download-count anchors an attacker gets the most cover from
# impersonating. A short, high-confidence list beats a long, noisy one.
POPULAR_PACKAGES = {
    "npm": {
        "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug",
        "request", "moment", "webpack", "eslint", "jest", "typescript", "vue", "next",
        "colors", "left-pad", "event-stream", "ua-parser-js", "node-ipc", "cross-env",
        "dotenv", "semver", "underscore", "async", "glob", "minimist", "yargs", "inquirer",
        "socket.io", "mongoose", "prettier", "rimraf", "mkdirp", "uuid", "classnames",
        "styled-components", "redux", "electron", "vite", "tailwindcss", "eslint-config-next",
    },
    "PyPI": {
        "requests", "numpy", "urllib3", "django", "flask", "boto3", "pandas", "scipy",
        "pytest", "setuptools", "pip", "six", "pyyaml", "cryptography", "click", "jinja2",
        "sqlalchemy", "pillow", "pytz", "certifi", "idna", "attrs", "packaging", "wheel",
        "colorama", "markdown", "protobuf", "grpcio", "docutils", "python-dateutil",
    },
}
_MIN_TYPOSQUAT_LEN = 4

# Legitimate, widely-used packages that sit one edit from a popular name. Without this
# list they are reported forever and the rule trains the user to ignore it.
TYPOSQUAT_ALLOWLIST = {
    "npm": {
        "colord", "globby", "jsesc", "commondir", "ohash", "destr", "defu", "jiti",
        "mime", "exit", "chalk", "chai", "clone", "yargs-parser", "async-each",
        "es6-promise", "resolve", "reselect", "asap", "acorn", "assert",
    },
    "PyPI": {
        "numba", "pyotp", "pynacl", "soxr", "six", "pytz", "pyarrow", "pytest-cov",
        "click-plugins", "cligj", "attrs", "chardet", "charset-normalizer", "idna",
    },
}


def direct_dependency_names(files: list[tuple[Path, str]]) -> dict[str, set[str]]:
    """Names a human actually typed into a manifest, per ecosystem.

    A typosquat is delivered by *your* typo at install time, so it lands in a manifest
    you wrote. It is never a transitive dependency of a legitimate package — a real
    package's own dependencies are not typos. Scanning the whole resolved lockfile
    instead of the declared set is what makes edit-distance typosquat detection a
    noise generator: it compares thousands of legitimate transitive packages against
    a popular-name list and flags every near-collision.
    """
    out: dict[str, set[str]] = {"npm": set(), "PyPI": set(), "crates.io": set(),
                                "RubyGems": set(), "Go": set()}
    for path, _rel in files:
        name = path.name
        if name not in ("package.json", "requirements.txt", "requirements-dev.txt",
                        "pyproject.toml", "Pipfile", "Gemfile", "Cargo.toml"):
            continue
        text = read_text(path)
        if not text:
            continue
        if name == "package.json":
            try:
                data = json.loads(text)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies",
                            "peerDependencies"):
                sec = data.get(section)
                if isinstance(sec, dict):
                    out["npm"].update(k.lower() for k in sec if isinstance(k, str))
        elif name.startswith("requirements"):
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                m = re.match(r"^([A-Za-z0-9][\w.\-]*)", line)
                if m and not line.startswith("-"):
                    out["PyPI"].add(m.group(1).lower())
        elif name == "pyproject.toml":
            for m in re.finditer(r"[\"']([A-Za-z0-9][\w.\-]*)\s*(?:[<>=!~\[]|[\"'])", text):
                out["PyPI"].add(m.group(1).lower())
        elif name == "Cargo.toml":
            for m in re.finditer(r"(?m)^\s*([A-Za-z0-9][\w.\-]*)\s*=", text):
                out["crates.io"].add(m.group(1).lower())
        elif name == "Gemfile":
            for m in re.finditer(r"(?m)^\s*gem\s+[\"']([^\"']+)[\"']", text):
                out["RubyGems"].add(m.group(1).lower())
        elif name == "Pipfile":
            for m in re.finditer(r"(?m)^\s*[\"']?([A-Za-z0-9][\w.\-]*)[\"']?\s*=", text):
                out["PyPI"].add(m.group(1).lower())
    return out


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    """Edit distance, short-circuited above `cap` — this only ever needs to answer
    'is it 1 or 2 edits away', never the exact distance for unrelated strings."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) >= cap:
        return cap
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
        if min(cur) >= cap:
            return cap
    return prev[-1]


def typosquat_findings(packages: list[tuple[str, str, str]],
                       direct: dict[str, set[str]] | None = None) -> list[Finding]:
    """Flag near-miss impersonations of popular packages among the *declared* dependencies.

    Three constraints keep this precise, and all three are load-bearing:

    1. Declared dependencies only. Measured against real repositories, running this over
       a full resolved lockfile produced a 100% false-positive rate — every hit was a
       legitimate transitive package that merely rhymes with a famous one.
    2. Edit distance of exactly 1. Distance 2 is where the noise lives, and the
       documented real-world typosquats (crossenv, colourama, python3-dateutil,
       jeIlyfish, urlib3) are all a single edit from their target anyway.
    3. An explicit allowlist of well-known packages that legitimately sit one edit away.

    When the declared set cannot be determined the check is skipped rather than
    falling back to the lockfile — silence beats a page of false alarms.
    """
    if not direct:
        return []
    out: list[Finding] = []
    seen: set[str] = set()
    for name, version, eco in packages:
        pop = POPULAR_PACKAGES.get(eco)
        declared = direct.get(eco)
        if not pop or not declared:
            continue
        low = name.lower()
        if low not in declared:
            continue
        if (low in pop or len(low) < _MIN_TYPOSQUAT_LEN
                or low in TYPOSQUAT_ALLOWLIST.get(eco, ()) or low in seen):
            continue
        for target in pop:
            if abs(len(low) - len(target)) > 1:
                continue
            if _levenshtein(low, target) != 1:
                continue
            seen.add(low)
            out.append(Finding(
                id="deps/possible-typosquat",
                title=f"{name} ({eco}) is 1 edit from the popular package '{target}'",
                severity="medium", scanner=NAME, path="", line=0,
                evidence=f"{eco}:{name}@{version} ~ {target}",
                remediation=f"Confirm this is not a typosquat of '{target}' before shipping it — check "
                            "the registry page, maintainer history, and download count. If it is a "
                            "legitimate package, add it to your baseline.",
                reference="https://cwe.mitre.org/data/definitions/1357.html"))
            break
    return out
