"""Dependency license risk — the other half of diligence.

A copyleft package inside a proprietary product is the finding that kills acquisitions,
and it is invisible to every secret scanner.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core import Finding

NAME = "licenses"
MAX_LOOKUPS = 300

# license family -> (severity, why)
COPYLEFT_STRONG = ("AGPL", "SSPL", "OSL", "EUPL", "CPAL")
COPYLEFT_WEAK = ("GPL-2", "GPL-3", "GPL2", "GPL3", "GPLV2", "GPLV3")
COPYLEFT_FILE = ("LGPL", "MPL", "EPL", "CDDL")
PERMISSIVE = ("MIT", "BSD", "APACHE", "ISC", "UNLICENSE", "0BSD", "ZLIB", "PSF",
              "PYTHON", "WTFPL", "CC0", "BSL")


def classify(license_id: str) -> tuple[str, str, str] | None:
    """Returns (severity, family, explanation) or None when the license is fine."""
    if not license_id:
        return ("low", "unknown", "No license declared — legally you have no right to use it.")
    up = license_id.upper()
    if any(k in up for k in COPYLEFT_STRONG):
        return ("high", "network copyleft",
                "AGPL/SSPL-class terms can require you to publish your own source to every user "
                "of your hosted service. Replace it, or get written legal sign-off before shipping.")
    # LGPL must be tested BEFORE GPL — "LGPL-2.1" contains the substring "GPL-2".
    if any(k in up for k in COPYLEFT_FILE):
        return ("medium", "file-level copyleft",
                "Modifications to these files must be published. Usually fine if you link rather "
                "than fork — record the obligation in your license inventory.")
    if any(k in up for k in COPYLEFT_WEAK):
        return ("high", "strong copyleft",
                "GPL terms can require your distributed product to be released under the GPL too. "
                "Replace it, isolate it behind a process boundary, or get legal sign-off.")
    if any(k in up for k in PERMISSIVE):
        return None
    if "PROPRIETARY" in up or "COMMERCIAL" in up or "NOLICENSE" in up:
        return ("medium", "proprietary",
                "Proprietary dependency — confirm your usage is covered by a paid license.")
    return ("info", "unrecognised",
            f"License `{license_id}` was not recognised — check it manually before shipping.")


def _get(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "dira-scan"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _npm_license(name: str, version: str, timeout: float) -> str:
    d = _get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{version}", timeout)
    lic = d.get("license") or d.get("licenses")
    if isinstance(lic, list):
        return ", ".join(x.get("type", "") if isinstance(x, dict) else str(x) for x in lic)
    if isinstance(lic, dict):
        return lic.get("type", "")
    return lic or ""


def _pypi_license(name: str, version: str, timeout: float) -> str:
    d = _get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/{version}/json", timeout)
    info = d.get("info") or {}
    lic = (info.get("license_expression") or info.get("license") or "").strip()
    if not lic or len(lic) > 60:  # some packages dump the whole license text here
        for c in info.get("classifiers") or []:
            if c.startswith("License :: "):
                lic = c.rsplit("::", 1)[-1].strip()
                break
    return lic[:80]

FETCHERS = {"npm": _npm_license, "PyPI": _pypi_license}


def scan(packages: list[tuple[str, str, str]], manifest: str = "",
         timeout: float = 12.0, workers: int = 8,
         offline: bool = False) -> tuple[list[Finding], dict]:
    stats: dict = {"checked": 0}
    if offline or not packages:
        if offline:
            stats["note"] = "offline: license lookup skipped"
        return [], stats

    targets = [p for p in packages if p[2] in FETCHERS][:MAX_LOOKUPS]
    if not targets:
        return [], stats

    def fetch(pkg):
        name, version, eco = pkg
        try:
            return pkg, FETCHERS[eco](name, version, timeout)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            return pkg, None  # unreachable != unlicensed; stay silent

    findings: list[Finding] = []
    inventory: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for (name, version, eco), lic in ex.map(fetch, targets):
            if lic is None:
                continue
            stats["checked"] += 1
            key = (lic or "unknown").strip() or "unknown"
            inventory[key] = inventory.get(key, 0) + 1
            verdict = classify(lic)
            if not verdict:
                continue
            sev, family, why = verdict
            findings.append(Finding(
                id=f"license/{family.replace(' ', '-')}",
                title=f"{name} {version} is {lic or 'unlicensed'} ({family})",
                severity=sev, scanner=NAME, path=manifest, line=0,
                evidence=f"{eco}:{name}@{version} — {lic or 'no license'}",
                remediation=why,
                reference="https://spdx.org/licenses/"))

    stats["inventory"] = dict(sorted(inventory.items(), key=lambda kv: -kv[1])[:25])
    if len(packages) > MAX_LOOKUPS:
        stats["truncated"] = f"licenses resolved for the first {MAX_LOOKUPS} packages"
    return findings, stats


_SPDX_FILE_RE = re.compile(r"(?i)\b(MIT|Apache-2\.0|BSD-[23]-Clause|GPL-[23]\.0|AGPL-3\.0|ISC|MPL-2\.0)\b")


def project_license(root: Path) -> str:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        p = root / name
        if p.is_file():
            head = p.read_text(errors="replace")[:2000]
            m = _SPDX_FILE_RE.search(head)
            if m:
                return m.group(1)
            for marker, spdx in (("MIT License", "MIT"), ("Apache License", "Apache-2.0"),
                                 ("GNU GENERAL PUBLIC", "GPL"), ("GNU AFFERO", "AGPL-3.0"),
                                 ("BSD", "BSD")):
                if marker.lower() in head.lower():
                    return spdx
            return "custom"
    return ""
