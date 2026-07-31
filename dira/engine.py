"""Scan orchestration: one walk, one thread pool, cached per-file results."""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .core import (Cache, Finding, ScanResult, SEVERITY_ORDER, finding_from_dict,
                   load_ignore_patterns, walk_files)
from .rules import RULESET_VERSION
from .scanners import config as config_scanner
from .scanners import deps as deps_scanner
from .scanners import gitrepo as git_scanner
from .scanners import headers as headers_scanner
from .scanners import licenses as license_scanner
from .scanners import readiness as readiness_scanner

ALL_SCANNERS = ["secrets", "config", "deps", "licenses", "git", "readiness", "surface"]


def default_workers() -> int:
    return min(16, max(4, (os.cpu_count() or 4) * 2))


def scan(root: Path, *, enabled: list[str] | None = None, target: str | None = None,
         offline: bool = False, use_cache: bool = True, workers: int | None = None,
         history_commits: int = 200, probe: bool = True,
         baseline: set[str] | None = None,
         diff_ref: str | None = None) -> ScanResult:
    from .scanners import secrets as secrets_scanner

    root = root.resolve()
    enabled = enabled or list(ALL_SCANNERS)
    workers = workers or default_workers()
    t0 = time.time()

    patterns = load_ignore_patterns(root)
    paths = walk_files(root, patterns)
    files = [(p, str(p.relative_to(root))) for p in paths]

    all_files = files
    changed: set[str] | None = None
    if diff_ref:
        changed = changed_files(root, diff_ref)
        files = [(p, rel) for p, rel in files if rel in changed]

    cache = Cache(root, f"{RULESET_VERSION}:{','.join(sorted(enabled))}", enabled=use_cache)
    findings: list[Finding] = []

    want_secrets = "secrets" in enabled
    want_config = "config" in enabled

    # None when this is not a git repo — the config scanner must not claim a file was
    # "committed" when there is no index to check it against.
    tracked = git_scanner.tracked_files(root) if (root / ".git").exists() else None

    if want_secrets or want_config:
        def work(item):
            p, rel = item
            cached = cache.get(p, rel)
            if cached is not None:
                return rel, p, [finding_from_dict(d) for d in cached], True
            found: list[Finding] = []
            if want_secrets:
                found += secrets_scanner.scan_file(p, rel)
            if want_config:
                found += config_scanner.scan_file(p, rel, tracked)
            return rel, p, found, False

        with ThreadPoolExecutor(max_workers=workers) as ex:
            for rel, p, found, was_cached in ex.map(work, files, chunksize=16):
                if not was_cached:
                    cache.put(p, rel, found)
                findings.extend(found)
        cache.save()

    findings = config_scanner.dedupe(findings)

    stats: dict = {"files_scanned": len(files), "cache_hits": cache.hits,
                   "workers": workers, "ruleset": RULESET_VERSION}
    if changed is not None:
        stats["diff_ref"] = diff_ref
        stats["changed_files"] = len(files)

    packages: list = []
    if "deps" in enabled or "licenses" in enabled:
        packages, manifests = deps_scanner.collect_packages(all_files)
        stats["packages"] = len(packages)

    if "deps" in enabled:
        dep_findings, dep_stats = deps_scanner.scan(all_files, offline=offline, workers=workers)
        findings.extend(dep_findings)
        findings.extend(deps_scanner.unlocked_manifests(all_files))
        # Supply-chain checks below are local/offline — manifest text already on disk,
        # no network — so they run on every scan regardless of --offline.
        findings.extend(deps_scanner.unpinned_dependency_findings(all_files))
        findings.extend(deps_scanner.install_hook_findings(all_files))
        findings.extend(deps_scanner.typosquat_findings(
            packages, deps_scanner.direct_dependency_names(all_files)))
        stats["deps"] = dep_stats

    if "licenses" in enabled and packages:
        lic_findings, lic_stats = license_scanner.scan(
            packages, manifest=(manifests[0] if manifests else ""),
            offline=offline, workers=workers)
        findings.extend(lic_findings)
        stats["licenses"] = lic_stats

    if "git" in enabled:
        findings.extend(git_scanner.scan(root, history_commits=history_commits))

    readiness: dict = {}
    if "readiness" in enabled and changed is None:
        readiness, ready_findings = readiness_scanner.evaluate(root, all_files)
        findings.extend(ready_findings)

    if "surface" in enabled and target:
        findings.extend(headers_scanner.scan(target, probe=probe))

    if baseline:
        findings = [f for f in findings if f.fingerprint() not in baseline]

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.scanner, f.path, f.line))
    stats["duration_sec"] = round(time.time() - t0, 2)
    stats["target"] = target or ""
    return ScanResult(root=str(root), findings=findings, readiness=readiness, stats=stats)


class DiffRefError(RuntimeError):
    """--diff was given a ref git cannot resolve. Never degrade silently: a
    typo'd base ref in CI would scan almost nothing and report a false green."""


def changed_files(root: Path, ref: str) -> set[str]:
    """Files touched since `ref`, plus anything untracked — the PR-gating fast path."""
    import subprocess

    def git(*args) -> str:
        try:
            r = subprocess.run(["git", "-C", str(root), *args],
                               capture_output=True, text=True, timeout=30)
            return r.stdout if r.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    if not git("rev-parse", "--is-inside-work-tree").strip():
        raise DiffRefError(f"--diff {ref}: {root} is not a git repository")
    if not git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip():
        raise DiffRefError(
            f"--diff {ref}: git cannot resolve that ref. "
            "In CI, fetch it first (e.g. actions/checkout with fetch-depth: 0)")

    merge_base = git("merge-base", ref, "HEAD").strip()
    base = merge_base or ref
    out = set()
    for chunk in (git("diff", "--name-only", "--diff-filter=ACMR", base, "HEAD"),
                  git("diff", "--name-only", "--diff-filter=ACMR"),
                  git("ls-files", "--others", "--exclude-standard")):
        out.update(l.strip() for l in chunk.splitlines() if l.strip())
    return out
