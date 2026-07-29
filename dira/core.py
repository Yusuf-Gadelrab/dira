"""Core types, file walking, and the incremental cache."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_SCORE = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}

DEFAULT_EXCLUDES = [
    ".git", "node_modules", "vendor", "dist", "build", "out", "target",
    ".next", ".nuxt", ".venv", "venv", "env", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".tox", "site-packages", ".terraform",
    "coverage", ".gradle", "Pods", ".dira-cache.json", ".idea", ".DS_Store",
]

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".bz2", ".xz", ".7z", ".mp4", ".mov", ".mp3", ".wav", ".woff",
    ".woff2", ".ttf", ".otf", ".eot", ".so", ".dylib", ".dll", ".class",
    ".jar", ".pyc", ".pdb", ".bin", ".exe", ".wasm", ".psd", ".sqlite",
    ".db", ".pack", ".idx", ".heic", ".avif",
}

MAX_FILE_BYTES = 2_000_000  # skip anything bigger; secrets don't live in 2MB blobs


@dataclass
class Finding:
    """One security issue. `fingerprint` is stable across runs for baselining."""

    id: str
    title: str
    severity: str
    scanner: str
    path: str = ""
    line: int = 0
    evidence: str = ""
    remediation: str = ""
    reference: str = ""

    def fingerprint(self) -> str:
        raw = f"{self.id}|{self.path}|{self.evidence}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint()
        return d


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    readiness: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def counts(self) -> dict:
        return {s: len(self.by_severity(s)) for s in SEVERITY_ORDER}

    def risk_score(self) -> int:
        """0-100, higher is worse.

        Diminishing returns within a severity (the 15th medium is not as informative as
        the first) so volume never drowns out one critical, and process gaps from the
        readiness scanner are excluded — those have their own score.
        """
        buckets: dict[str, int] = {}
        for f in self.findings:
            if f.scanner == "readiness":
                continue
            buckets[f.severity] = buckets.get(f.severity, 0) + 1
        raw = sum(SEVERITY_SCORE[sev] * (1 + math.log(n)) for sev, n in buckets.items() if n)
        return min(100, round(raw))

    def grade(self) -> str:
        """Letter from the risk score, then capped by the worst thing present — a repo
        with one live critical cannot earn a B no matter how clean the rest is."""
        s = 100 - self.risk_score()
        letter = "F"
        for cutoff, l in ((85, "A"), (70, "B"), (50, "C"), (30, "D")):
            if s >= cutoff:
                letter = l
                break
        worst = {f.severity for f in self.findings if f.scanner != "readiness"}
        cap = ("F" if "critical" in worst else "C" if "high" in worst
               else "B" if "medium" in worst else "A")
        return max(letter, cap)  # letters sort A < B < C < D < F, so max() is the worse grade


def load_ignore_patterns(root: Path) -> list[str]:
    pats = list(DEFAULT_EXCLUDES)
    for name in (".diraignore", ".gitignore"):
        p = root / name
        if not p.is_file():
            continue
        try:
            for line in p.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("!"):
                    pats.append(line.rstrip("/"))
        except OSError:
            pass
    return pats


def _ignored(rel: str, name: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, f"*/{pat}") or fnmatch.fnmatch(rel, f"{pat}/*"):
            return True
    return False


def walk_files(root: Path, patterns: list[str]) -> list[Path]:
    """Single directory walk shared by every file-based scanner."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        rel_dir = d.relative_to(root).as_posix()
        # NB: never lstrip("./") here — it eats the leading dot of ".env"/".github"
        # and silently drops the most important files in the repo.
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [n for n in dirnames if not _ignored(prefix + n, n, patterns)]
        for fn in filenames:
            rel = prefix + fn
            if _ignored(rel, fn, patterns):
                continue
            p = d / fn
            if p.suffix.lower() in BINARY_EXT:
                continue
            try:
                if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            out.append(p)
    return out


def read_text(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if b"\x00" in data[:4096]:  # binary sniff beats extension lists
        return ""
    return data.decode("utf-8", "replace")


class Cache:
    """Skips re-scanning unchanged files. Keyed by (size, mtime_ns, ruleset hash)."""

    def __init__(self, root: Path, ruleset_version: str, enabled: bool = True):
        self.path = root / ".dira-cache.json"
        self.enabled = enabled
        self.version = ruleset_version
        self.data: dict = {}
        self.hits = 0
        if enabled and self.path.is_file():
            try:
                blob = json.loads(self.path.read_text())
                if blob.get("version") == ruleset_version:
                    self.data = blob.get("files", {})
            except (OSError, ValueError):
                self.data = {}
        self.next: dict = {}

    def _key(self, p: Path) -> str | None:
        try:
            st = p.stat()
        except OSError:
            return None
        return f"{st.st_size}:{st.st_mtime_ns}"

    def get(self, p: Path, rel: str) -> list[dict] | None:
        if not self.enabled:
            return None
        k = self._key(p)
        entry = self.data.get(rel)
        if entry and k and entry.get("k") == k:
            self.hits += 1
            self.next[rel] = entry
            return entry["f"]
        return None

    def put(self, p: Path, rel: str, findings: list[Finding]) -> None:
        if not self.enabled:
            return
        k = self._key(p)
        if k:
            self.next[rel] = {"k": k, "f": [f.to_dict() for f in findings]}

    def save(self) -> None:
        if not self.enabled:
            return
        try:
            self.path.write_text(json.dumps({"version": self.version, "files": self.next}))
        except OSError:
            pass


def finding_from_dict(d: dict) -> Finding:
    d = {k: v for k, v in d.items() if k != "fingerprint"}
    return Finding(**d)


def redact(secret: str, keep: int = 4) -> str:
    s = secret.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * min(12, len(s) - keep * 2)}{s[-keep:]}"


LINE_RE = re.compile(rb"\n")


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
