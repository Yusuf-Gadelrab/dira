"""Policy-as-code: a repo-committed file that overrides severities and gates.

The problem it solves: every team disagrees with a scanner's default severities on a
handful of rules, and the only alternatives are living with the noise or turning the
scanner off. A committed policy file makes the disagreement explicit, reviewable in a
pull request, and identical on every developer's machine and in CI.

Format (JSON, all keys optional):

    {
      "fail_on": "medium",
      "severity": {"config/docker-latest-tag": "low"},
      "ignore": ["config/gha-mutable-ref"],
      "ignore_paths": ["examples/*", "tests/fixtures/*"]
    }
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path

from .core import SEVERITY_ORDER, ScanResult


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    fail_on: str | None = None
    severity: dict = field(default_factory=dict)
    ignore: set = field(default_factory=set)
    ignore_paths: list = field(default_factory=list)

    def apply(self, result: ScanResult) -> ScanResult:
        kept = []
        for f in result.findings:
            if f.id in self.ignore:
                continue
            if f.path and any(fnmatch.fnmatch(f.path, p) for p in self.ignore_paths):
                continue
            override = self.severity.get(f.id)
            if override:
                f.severity = override
            kept.append(f)
        result.findings = kept
        return result


def load(path: Path) -> Policy:
    try:
        raw = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except OSError as e:
        raise PolicyError(f"cannot read policy file {path}: {e}") from e
    except ValueError as e:
        raise PolicyError(f"policy file {path} is not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise PolicyError(f"policy file {path} must contain a JSON object")

    valid = set(SEVERITY_ORDER)
    fail_on = raw.get("fail_on")
    if fail_on is not None and fail_on not in valid | {"never"}:
        raise PolicyError(f"policy fail_on must be one of {sorted(valid)} or 'never'")

    # `or {}` would silently accept a falsy wrong type (an empty list), so the type is
    # checked before any defaulting.
    severity = raw.get("severity")
    severity = {} if severity is None else severity
    if not isinstance(severity, dict):
        raise PolicyError("policy 'severity' must be an object of rule-id to severity")
    bad = {k: v for k, v in severity.items() if v not in valid}
    if bad:
        raise PolicyError(f"policy 'severity' has invalid levels: {sorted(bad)}")

    ignore = raw.get("ignore")
    ignore = [] if ignore is None else ignore
    ignore_paths = raw.get("ignore_paths")
    ignore_paths = [] if ignore_paths is None else ignore_paths
    for name, value in (("ignore", ignore), ("ignore_paths", ignore_paths)):
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise PolicyError(f"policy '{name}' must be a list of strings")

    return Policy(fail_on=fail_on, severity=dict(severity), ignore=set(ignore),
                  ignore_paths=list(ignore_paths))
