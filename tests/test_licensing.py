import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dira import licensing, policy  # noqa: E402
from dira.cli import main  # noqa: E402
from dira.core import Finding, ScanResult  # noqa: E402


@pytest.fixture(autouse=True)
def no_ambient_license(monkeypatch, tmp_path):
    """A key on the developer's own machine must never leak into a test result."""
    monkeypatch.delenv("DIRA_LICENSE_KEY", raising=False)
    monkeypatch.setattr(licensing, "key_sources", lambda: [tmp_path / "absent"])
    return tmp_path


def test_a_freshly_minted_key_round_trips():
    key = licensing.issue_key("Acme Inc", tier="pro")
    lic = licensing.verify_key(key)
    assert lic.valid
    assert lic.tier == "pro"
    assert lic.licensee == "Acme Inc"
    assert "policy" in lic.features


def test_community_is_the_fallback_when_nothing_is_installed():
    lic = licensing.load_license()
    assert lic.tier == "community"
    assert lic.valid
    assert lic.features == licensing.COMMUNITY_FEATURES


def test_community_keeps_every_capability_the_scanner_already_shipped():
    for feature in ("scan.secrets", "scan.deps", "report.sarif", "sbom.cyclonedx",
                    "fix.apply", "baseline", "diff"):
        assert licensing.has_feature(feature, licensing.load_license())


def test_a_tampered_payload_is_rejected():
    key = licensing.issue_key("Acme Inc", tier="pro")
    prefix, tier, body, tag = key.split("-")
    forged = f"{prefix}-{tier}-{body[:-2]}XY-{tag}"
    lic = licensing.verify_key(forged)
    assert not lic.valid
    assert lic.tier == "community"
    assert "signature" in lic.reason


def test_a_wrong_tag_is_rejected():
    key = licensing.issue_key("Acme Inc", tier="pro")
    prefix, tier, body, _ = key.split("-")
    lic = licensing.verify_key(f"{prefix}-{tier}-{body}-deadbeef")
    assert not lic.valid
    assert "signature" in lic.reason


def test_a_malformed_key_never_raises():
    for junk in ("", "  ", "nonsense", "DIRA-PRO", "DIRA-PRO-x-y-z", "X-PRO-a-b"):
        lic = licensing.verify_key(junk)
        assert lic.tier == "community"
        assert lic.features == licensing.COMMUNITY_FEATURES


def test_an_expired_key_degrades_to_community_with_a_reason():
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    key = licensing.issue_key("Acme Inc", tier="pro", expires=yesterday)
    lic = licensing.verify_key(key)
    assert not lic.valid
    assert lic.tier == "community"
    assert "expired" in lic.reason
    assert "policy" not in lic.features


def test_a_key_expiring_today_is_still_valid():
    key = licensing.issue_key("Acme Inc", tier="pro", expires=date.today().isoformat())
    assert licensing.verify_key(key).valid


def test_the_tier_label_must_match_the_signed_payload():
    key = licensing.issue_key("Acme Inc", tier="pro")
    prefix, _, body, tag = key.split("-")
    lic = licensing.verify_key(f"{prefix}-TEAM-{body}-{tag}")
    assert not lic.valid
    assert "tier label" in lic.reason


def test_the_environment_variable_takes_precedence_over_a_file(monkeypatch, tmp_path):
    on_disk = tmp_path / "license"
    on_disk.write_text(licensing.issue_key("From Disk", tier="pro"))
    monkeypatch.setattr(licensing, "key_sources", lambda: [on_disk])
    monkeypatch.setenv("DIRA_LICENSE_KEY", licensing.issue_key("From Env", tier="pro"))
    assert licensing.load_license().licensee == "From Env"


def test_a_key_file_on_disk_is_read_when_no_env_var_is_set(monkeypatch, tmp_path):
    on_disk = tmp_path / "license"
    on_disk.write_text(licensing.issue_key("From Disk", tier="pro") + "\n")
    monkeypatch.setattr(licensing, "key_sources", lambda: [on_disk])
    assert licensing.load_license().licensee == "From Disk"


def test_an_unreadable_key_file_falls_back_to_community(monkeypatch, tmp_path):
    monkeypatch.setattr(licensing, "key_sources", lambda: [tmp_path])  # a directory
    assert licensing.load_license().tier == "community"


def test_require_pro_is_false_and_quiet_for_community(capsys):
    assert licensing.require_pro("policy", licensing.load_license()) is False
    err = capsys.readouterr().err
    assert "Pro feature" in err
    assert err.count("\n") <= 2


def test_require_pro_is_true_for_a_licensed_feature(capsys):
    lic = licensing.verify_key(licensing.issue_key("Acme Inc", tier="pro"))
    assert licensing.require_pro("policy", lic) is True
    assert capsys.readouterr().err == ""


def test_a_key_can_grant_an_explicit_feature_subset():
    key = licensing.issue_key("Acme Inc", tier="pro", features={"scan.secrets"})
    lic = licensing.verify_key(key)
    assert lic.valid
    assert lic.features == frozenset({"scan.secrets"})
    assert not licensing.has_feature("policy", lic)


def test_license_command_reports_community(capsys):
    assert main(["license"]) == 0
    out = capsys.readouterr().out
    assert "community" in out
    assert "policy" in out


def test_license_command_accepts_a_valid_key(capsys):
    key = licensing.issue_key("Acme Inc", tier="pro")
    assert main(["license", "--key", key]) == 0
    assert "Acme Inc" in capsys.readouterr().out


def test_license_command_exits_1_on_a_bad_key(capsys):
    assert main(["license", "--key", "DIRA-PRO-abc-deadbeef"]) == 1


def test_policy_file_overrides_severity_and_drops_ignored_rules(tmp_path):
    spec = tmp_path / "policy.json"
    spec.write_text(json.dumps({
        "fail_on": "critical",
        "severity": {"config/keep": "low"},
        "ignore": ["config/drop"],
        "ignore_paths": ["examples/*"],
    }))
    p = policy.load(spec)
    result = ScanResult(root=str(tmp_path), findings=[
        Finding(id="config/keep", title="k", severity="high", scanner="config", path="a.py"),
        Finding(id="config/drop", title="d", severity="high", scanner="config", path="b.py"),
        Finding(id="config/keep", title="k", severity="high", scanner="config",
                path="examples/c.py"),
    ])
    p.apply(result)
    assert [f.id for f in result.findings] == ["config/keep"]
    assert result.findings[0].severity == "low"
    assert p.fail_on == "critical"


@pytest.mark.parametrize("body", [
    "[]",
    '{"fail_on": "catastrophic"}',
    '{"severity": {"a/b": "spicy"}}',
    '{"severity": []}',
    '{"ignore": "not-a-list"}',
    '{"ignore_paths": [1, 2]}',
    "{not json",
])
def test_a_bad_policy_file_is_rejected_loudly(tmp_path, body):
    spec = tmp_path / "policy.json"
    spec.write_text(body)
    with pytest.raises(policy.PolicyError):
        policy.load(spec)


def test_a_missing_policy_file_is_rejected_loudly(tmp_path):
    with pytest.raises(policy.PolicyError):
        policy.load(tmp_path / "nope.json")


def test_policy_flag_is_gated_but_the_scan_still_runs(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "policy.json").write_text('{"fail_on": "never"}')
    code = main(["scan", str(tmp_path), "--policy", str(tmp_path / "policy.json"),
                 "--offline", "--fail-on", "never"])
    captured = capsys.readouterr()
    assert code == 0
    assert "Pro feature" in captured.err
    assert "default severities" in captured.err
    assert "DIRA" in captured.out


def test_policy_flag_applies_when_licensed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DIRA_LICENSE_KEY", licensing.issue_key("Acme Inc", tier="pro"))
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n")
    (tmp_path / "policy.json").write_text('{"fail_on": "never"}')
    code = main(["scan", str(tmp_path), "--policy", str(tmp_path / "policy.json"),
                 "--offline"])
    assert code == 0
    assert "Pro feature" not in capsys.readouterr().err


def test_an_invalid_policy_file_exits_2_when_licensed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DIRA_LICENSE_KEY", licensing.issue_key("Acme Inc", tier="pro"))
    (tmp_path / "policy.json").write_text("{not json")
    code = main(["scan", str(tmp_path), "--policy", str(tmp_path / "policy.json"),
                 "--offline"])
    assert code == 2
    assert "not valid JSON" in capsys.readouterr().err
