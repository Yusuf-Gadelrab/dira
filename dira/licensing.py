"""Offline entitlement scaffolding for the paid tier.

Design constraints, in priority order:

1. **The community tier is the whole scanner.** Every capability DIRA shipped through
   v1.2.0 is in `COMMUNITY_FEATURES` and stays there permanently. A missing or invalid
   key never degrades a scan, never nags beyond one line on stderr, and never exits.
2. **No network, ever.** Verification is a local HMAC check. There is no activation
   server, no license call-home, no telemetry. An air-gapped user with a key is a
   fully licensed user, which is the point of a zero-dependency tool.
3. **Standard library only.** `hmac`, `hashlib`, `base64`, `json`, `datetime`.

Honest security assessment, stated here rather than buried: this scheme is symmetric.
`_SIGNING_KEY` must live in the client to verify a tag, so anyone willing to read the
source can mint their own key in about five minutes. That is a deliberate trade, not an
oversight — it makes accidental sharing and casual expiry-editing fail, which is the
realistic threat for a developer tool, and it costs nothing at runtime. A scheme that
actually resists a motivated cracker needs asymmetric signing (Ed25519 keys issued
offline, only the *public* key shipped) so the client can verify without being able to
issue. That is the upgrade path if the tier ever earns real revenue. Until then, treat
this module as bookkeeping, not DRM.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path

# DEV-ONLY PLACEHOLDER. Replace with a secret held solely by the issuer before minting
# any key that changes hands. Shipping this value is what makes the scheme symmetric and
# therefore forgeable; see the module docstring.
_SIGNING_KEY = b"dira-dev-signing-key-not-a-production-secret"

_PREFIX = "DIRA"
_TAG_LEN = 8

COMMUNITY_FEATURES = frozenset({
    "scan.secrets",
    "scan.config",
    "scan.deps",
    "scan.licenses",
    "scan.git",
    "scan.readiness",
    "scan.surface",
    "report.terminal",
    "report.json",
    "report.sarif",
    "report.html",
    "report.markdown",
    "sbom.cyclonedx",
    "sbom.spdx",
    "fix.apply",
    "baseline",
    "diff",
    "init",
})

PRO_FEATURES = frozenset({
    "policy",            # policy-as-code: per-rule severity overrides and gates
})

TEAM_FEATURES = frozenset()

_TIER_FEATURES = {
    "community": COMMUNITY_FEATURES,
    "pro": COMMUNITY_FEATURES | PRO_FEATURES,
    "team": COMMUNITY_FEATURES | PRO_FEATURES | TEAM_FEATURES,
}

PRO_URL = "https://yusuf-gadelrab.github.io/dira.html"


@dataclass(frozen=True)
class License:
    key: str
    tier: str
    licensee: str
    issued: str
    expires: str | None
    features: frozenset
    valid: bool
    reason: str

    def summary(self) -> str:
        if self.tier == "community":
            return "community"
        return f"{self.tier} — {self.licensee}"


def _community(reason: str = "no key installed") -> License:
    return License(
        key="", tier="community", licensee="", issued="", expires=None,
        features=COMMUNITY_FEATURES, valid=True, reason=reason,
    )


def _invalid(key: str, reason: str) -> License:
    return License(
        key=key, tier="community", licensee="", issued="", expires=None,
        features=COMMUNITY_FEATURES, valid=False, reason=reason,
    )


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _tag(payload_b64: str) -> str:
    mac = hmac.new(_SIGNING_KEY, payload_b64.encode("ascii"), hashlib.sha256)
    return mac.hexdigest()[:_TAG_LEN]


def issue_key(licensee: str, tier: str = "pro", issued: str | None = None,
              expires: str | None = None, features: set | None = None) -> str:
    """Mint a key. Issuer-side helper — also what makes the round trip testable."""
    if tier not in _TIER_FEATURES:
        raise ValueError(f"unknown tier: {tier}")
    payload = {
        "l": licensee,
        "t": tier,
        "i": issued or date.today().isoformat(),
        "e": expires,
        "f": sorted(features) if features else None,
    }
    blob = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = _b64encode(blob)
    return f"{_PREFIX}-{tier.upper()}-{body}-{_tag(body)}"


def verify_key(key: str, today: date | None = None) -> License:
    """Parse and verify a key offline. Never raises."""
    key = (key or "").strip()
    if not key:
        return _community()

    parts = key.split("-")
    if len(parts) != 4 or parts[0] != _PREFIX:
        return _invalid(key, "malformed key")
    _, tier_label, body, tag = parts

    if not hmac.compare_digest(tag, _tag(body)):
        return _invalid(key, "signature does not match — key is altered or not ours")

    try:
        payload = json.loads(_b64decode(body).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return _invalid(key, "unreadable payload")
    if not isinstance(payload, dict):
        return _invalid(key, "unreadable payload")

    tier = payload.get("t", "")
    if tier not in _TIER_FEATURES:
        return _invalid(key, f"unknown tier: {tier or '?'}")
    if tier_label != tier.upper():
        return _invalid(key, "tier label does not match payload")

    expires = payload.get("e")
    if expires:
        try:
            expiry = date.fromisoformat(expires)
        except ValueError:
            return _invalid(key, "unreadable expiry date")
        if expiry < (today or date.today()):
            return License(
                key=key, tier="community", licensee=payload.get("l", ""),
                issued=payload.get("i", ""), expires=expires,
                features=COMMUNITY_FEATURES, valid=False,
                reason=f"license expired {expires} — running as community",
            )

    granted = payload.get("f")
    features = frozenset(granted) if granted else _TIER_FEATURES[tier]

    return License(
        key=key, tier=tier, licensee=payload.get("l", ""), issued=payload.get("i", ""),
        expires=expires, features=features, valid=True, reason="ok",
    )


def key_sources() -> list[Path]:
    return [Path(".dira-license"), Path.home() / ".config" / "dira" / "license"]


def load_license(today: date | None = None) -> License:
    """Resolve a key from env, then the project, then the user config. Never raises."""
    env = os.environ.get("DIRA_LICENSE_KEY", "").strip()
    if env:
        return verify_key(env, today=today)
    for path in key_sources():
        try:
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace").strip()
                if text:
                    return verify_key(text, today=today)
        except OSError:
            continue
    return _community()


def has_feature(feature: str, lic: License | None = None) -> bool:
    return feature in (lic or load_license()).features


def require_pro(feature: str, lic: License | None = None, stream=None) -> bool:
    """Gate a Pro feature. Prints one line and returns False; never exits."""
    import sys

    lic = lic or load_license()
    if feature in lic.features:
        return True
    out = stream or sys.stderr
    if not lic.valid and lic.reason:
        print(f"dira: {lic.reason}", file=out)
    print(f"dira: '{feature}' is a Pro feature — {PRO_URL}", file=out)
    return False
