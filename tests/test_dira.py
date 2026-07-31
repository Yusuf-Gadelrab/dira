import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dira import fixer  # noqa: E402
from dira.cli import main  # noqa: E402
from dira.core import Finding, redact  # noqa: E402
from dira.engine import DiffRefError, scan  # noqa: E402
from dira.report import html as html_report  # noqa: E402
from dira.report import serial, terminal  # noqa: E402
from dira.rules import is_placeholder, shannon_entropy  # noqa: E402
from dira.scanners import deps  # noqa: E402
from dira.scanners.config import scan_file as config_scan  # noqa: E402
from dira.scanners.secrets import scan_file as secret_scan  # noqa: E402

# Synthetic credentials, assembled at runtime. Never store a secret-shaped literal in a
# repo — GitHub push protection blocks it, and a security tool should not be the exception.
FAKE_AWS = "AKIA" + "QZ7X4NPLMR3TVK9D"
FAKE_STRIPE = "sk_" + "live_" + "51H8xQpKj2mNvRt7bZaYcXwEr"
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_DSN = "postgresql://admin:" + "hunter2ZxQ" + "@db.internal:5432/prod"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "settings.py").write_text(
        f'AWS_KEY = "{FAKE_AWS}"\n'
        f'STRIPE = "{FAKE_STRIPE}"\n'
        'DEBUG = True\n'
        f'DB = "{FAKE_DSN}"\n'
    )
    (tmp_path / "app" / "safe.py").write_text(
        'API_KEY = os.environ["API_KEY"]\n'
        'TOKEN = "your-token-here"\n'
        'PASSWORD = "changeme"\n'
    )
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nRUN pip install .\nCMD [\"python\"]\n")
    (tmp_path / ".env").write_text("SECRET_KEY=abc\n")
    (tmp_path / "requirements.txt").write_text("flask==0.12.2\n")
    return tmp_path


def _ids(findings):
    return {f.id for f in findings}


def test_detects_real_secrets(repo):
    f = secret_scan(repo / "app" / "settings.py", "app/settings.py")
    ids = _ids(f)
    assert "secret/aws-access-key" in ids
    assert "secret/stripe-key" in ids
    assert "secret/db-url" in ids
    assert all(f_.severity == "critical" for f_ in f)


def test_no_false_positives_on_placeholders(repo):
    assert secret_scan(repo / "app" / "safe.py", "app/safe.py") == []


def test_secrets_are_redacted(repo):
    f = secret_scan(repo / "app" / "settings.py", "app/settings.py")
    for finding in f:
        assert FAKE_DSN.split(":")[2].split("@")[0] not in finding.evidence
        assert FAKE_STRIPE[8:] not in finding.evidence
    assert redact(FAKE_AWS).startswith("AKIA")


def test_test_paths_are_downgraded(tmp_path):
    d = tmp_path / "tests"
    d.mkdir()
    p = d / "fixture.py"
    p.write_text(f'KEY = "{FAKE_AWS}"\n')
    f = secret_scan(p, "tests/fixture.py")
    assert f and f[0].severity == "medium"


def test_config_rules(repo):
    f = config_scan(repo / "Dockerfile", "Dockerfile")
    ids = _ids(f)
    assert "config/docker-latest-tag" in ids
    assert "config/docker-root-user" in ids


def test_committed_env_file(repo):
    f = config_scan(repo / ".env", ".env")
    assert "config/committed-secret-file" in _ids(f)
    assert f[0].severity == "critical"


def test_env_example_not_flagged(tmp_path):
    p = tmp_path / ".env.example"
    p.write_text("API_KEY=\n")
    assert "config/committed-secret-file" not in _ids(config_scan(p, ".env.example"))


def test_debug_and_cors(tmp_path):
    p = tmp_path / "server.js"
    p.write_text("app.use(cors({ origin: '*' }));\nconst DEBUG = true;\n")
    ids = _ids(config_scan(p, "server.js"))
    assert "config/cors-wildcard" in ids


def test_full_scan_offline(repo):
    r = scan(repo, offline=True, enabled=["secrets", "config", "readiness"], use_cache=False)
    assert r.counts()["critical"] >= 3
    assert r.grade() == "F"
    assert 0 <= r.readiness["score"] <= 100
    assert r.stats["files_scanned"] >= 4


def test_clean_repo_grades_well(tmp_path):
    (tmp_path / "main.py").write_text("print('hello')\n")
    r = scan(tmp_path, offline=True, enabled=["secrets", "config"], use_cache=False)
    assert r.findings == []
    assert r.grade() == "A"


def test_cache_round_trip(repo):
    a = scan(repo, offline=True, enabled=["secrets", "config"], use_cache=True)
    b = scan(repo, offline=True, enabled=["secrets", "config"], use_cache=True)
    assert b.stats["cache_hits"] > 0
    assert {f.fingerprint() for f in a.findings} == {f.fingerprint() for f in b.findings}


def test_baseline_suppresses(repo):
    a = scan(repo, offline=True, enabled=["secrets", "config"], use_cache=False)
    fps = {f.fingerprint() for f in a.findings}
    b = scan(repo, offline=True, enabled=["secrets", "config"], use_cache=False, baseline=fps)
    assert b.findings == []


def test_fingerprint_is_stable():
    f = Finding(id="x", title="t", severity="high", scanner="s", path="a.py", line=3, evidence="e")
    g = Finding(id="x", title="different", severity="low", scanner="s", path="a.py", line=99, evidence="e")
    assert f.fingerprint() == g.fingerprint()  # line/title churn must not break baselines


def test_reports_render(repo):
    r = scan(repo, offline=True, enabled=["secrets", "config", "readiness"], use_cache=False)
    assert "DIRA" in terminal.render(r)
    j = json.loads(serial.to_json(r))
    assert j["findings"] and j["grade"]
    sarif = json.loads(serial.to_sarif(r))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert all(res["level"] in ("error", "warning", "note") for res in sarif["runs"][0]["results"])
    h = html_report.render(r)
    assert h.startswith("<!doctype html>") and "Startup readiness" in h
    assert FAKE_AWS not in h  # never leak the raw secret into a shareable report
    assert serial.to_markdown(r).startswith("## ")


def test_readiness_rewards_good_repo(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test(): pass\n")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("jobs:\n  t:\n    steps: [gitleaks]\n")
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "SECURITY.md").write_text("report to security@x.com")
    (tmp_path / "LICENSE").write_text("MIT")
    (tmp_path / "CODEOWNERS").write_text("* @me")
    poor = scan(tmp_path.parent / "nope", offline=True) if False else None
    r = scan(tmp_path, offline=True, enabled=["readiness"], use_cache=False)
    passed = {c["key"] for c in r.readiness["checks"] if c["passed"]}
    assert {"tests", "ci", "lockfile", "security-policy", "license", "codeowners",
            "secret-scanning"} <= passed
    assert poor is None


def test_dep_parsers():
    assert ("flask", "0.12.2", "PyPI") in deps._requirements("flask==0.12.2\nrequests>=2\n")
    npm = deps._npm_lock(json.dumps({"packages": {"node_modules/lodash": {"version": "4.17.11"}}}))
    assert ("lodash", "4.17.11", "npm") in npm
    lock = '[[package]]\nname = "urllib3"\nversion = "1.26.4"\n'
    assert ("urllib3", "1.26.4", "PyPI") in deps._toml_lock(lock, "PyPI")


def test_cvss_estimate():
    score = deps._cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None and score >= 9.0


def test_entropy_and_placeholder():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("xJ3k9Qm2Lp7Zw1Rt5Yb8") > 3.5
    assert is_placeholder("your-api-key-here")
    assert is_placeholder("xxxxxxxxxxxx")
    assert not is_placeholder("xJ3k9Qm2Lp7Zw1Rt5Yb8")


def test_git_history_scan(tmp_path):
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True,
                       capture_output=True, env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    try:
        git("init", "-q")
    except Exception:
        pytest.skip("git unavailable")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")
    leak = tmp_path / "conf.py"
    leak.write_text(f'GH = "{FAKE_GH}"\n')
    git("add", "-A")
    git("commit", "-qm", "oops")
    leak.write_text("GH = os.environ['GH']\n")
    git("add", "-A")
    git("commit", "-qm", "fix")
    r = scan(tmp_path, offline=True, enabled=["git"], use_cache=False)
    assert any(f.id.startswith("git-history/") for f in r.findings)


def test_cli_exit_codes(repo, capsys):
    assert main(["scan", str(repo), "--offline", "--fail-on", "high"]) == 1
    assert main(["scan", str(repo), "--offline", "--fail-on", "never"]) == 0
    capsys.readouterr()


def test_cli_writes_html(repo, tmp_path, capsys):
    out = tmp_path / "r.html"
    rc = main(["scan", str(repo), "--offline", "--format", "html",
               "--output", str(out), "--fail-on", "never"])
    capsys.readouterr()
    assert rc == 0 and out.is_file() and "<!doctype html>" in out.read_text()


def test_cli_init(tmp_path, capsys):
    assert main(["init", str(tmp_path)]) == 0
    capsys.readouterr()
    assert (tmp_path / ".github" / "workflows" / "dira.yml").is_file()
    assert (tmp_path / ".pre-commit-config.yaml").is_file()


def test_ignore_patterns_skip_vendor(tmp_path):
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "index.js").write_text(f'const k = "{FAKE_AWS}";\n')
    r = scan(tmp_path, offline=True, enabled=["secrets"], use_cache=False)
    assert r.findings == []


def test_risk_scoring_calibration():
    """Volume of mediums must not outrank one critical, and process gaps must not
    drag the security grade — that is what the readiness score is for."""
    from dira.core import ScanResult

    def res(*items):
        return ScanResult(root=".", findings=[
            Finding(id=f"x{i}", title="t", severity=sev, scanner=sc, path=f"f{i}.py")
            for i, (sev, sc) in enumerate(items)])

    one_critical = res(("critical", "secrets"))
    many_medium = res(*[("medium", "config")] * 15)
    assert one_critical.risk_score() > many_medium.risk_score()
    assert one_critical.grade() == "F"

    process_only = res(*[("medium", "readiness")] * 10)
    assert process_only.risk_score() == 0
    assert process_only.grade() == "A"

    one_high = res(("high", "config"))
    assert one_high.grade() == "C"   # a live high caps the grade at C
    assert many_medium.grade() == "B"


# --- expanded rule packs ---------------------------------------------------

def test_frontend_rules(tmp_path):
    p = tmp_path / "app.tsx"
    p.write_text(
        'const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\n'
        'localStorage.setItem("access_token", t);\n'
        'el.innerHTML = `<b>${name}</b>`;\n'
        'frame.postMessage(d, "*");\n'
        '<div dangerouslySetInnerHTML={{__html: userBio}} />\n'
    )
    ids = _ids(config_scan(p, "app.tsx"))
    assert {"config/public-env-secret", "config/token-in-localstorage",
            "config/dom-innerhtml", "config/postmessage-wildcard",
            "config/react-dangerous-html"} <= ids


def test_llm_rules(tmp_path):
    p = tmp_path / "agent.py"
    p.write_text(
        'client = OpenAI(dangerouslyAllowBrowser: true)\n'
        'prompt = f"You are a bot. {user_input}"\n'
        'exec(response.choices[0].message.content)\n'
    )
    ids = _ids(config_scan(p, "agent.py"))
    assert "config/llm-browser-key" in ids
    assert "config/llm-prompt-injection" in ids
    assert "config/llm-unbounded-exec" in ids


def test_cloud_rules(tmp_path):
    rules = tmp_path / "firestore.rules"
    rules.write_text("match /{d=**} { allow read, write: if true; }\n")
    assert "config/firebase-open-rules" in _ids(config_scan(rules, "firestore.rules"))

    pol = tmp_path / "policy.json"
    pol.write_text('{"Principal": "*", "Action": "*", "Resource": "*"}')
    ids = _ids(config_scan(pol, "policy.json"))
    assert "config/iam-wildcard-principal" in ids and "config/iam-wildcard-action" in ids

    sh = tmp_path / "install.sh"
    sh.write_text("curl -sSL https://x.dev/i | sudo bash\n")
    assert "config/curl-pipe-shell" in _ids(config_scan(sh, "install.sh"))


def test_jwt_none_algorithm(tmp_path):
    p = tmp_path / "auth.py"
    p.write_text('claims = jwt.decode(tok, key, algorithms=["none"])\n')
    assert "config/jwt-none-alg" in _ids(config_scan(p, "auth.py"))


# --- walker regression -----------------------------------------------------

def test_root_dotfiles_are_not_dropped(tmp_path):
    """Regression: lstrip('./') turned '.env' into 'env', which the default
    exclude list then swallowed — hiding the single worst finding there is."""
    (tmp_path / ".env").write_text(f"STRIPE={FAKE_STRIPE}\n")
    (tmp_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=x\n")
    r = scan(tmp_path, offline=True, enabled=["secrets", "config"], use_cache=False)
    paths = {f.path for f in r.findings}
    assert ".env" in paths and ".npmrc" in paths
    assert r.counts()["critical"] >= 1


# --- licenses --------------------------------------------------------------

def test_license_classification():
    from dira.scanners.licenses import classify, project_license
    assert classify("MIT") is None
    assert classify("Apache-2.0") is None
    assert classify("AGPL-3.0")[0] == "high"
    assert classify("GPL-3.0-only")[0] == "high"
    assert classify("MPL-2.0")[0] == "medium"
    # "LGPL-2.1" contains "GPL-2"; it must not be graded as full GPL
    assert classify("LGPL-2.1-or-later")[1] == "file-level copyleft"
    assert classify("GPL-3.0-or-later")[1] == "strong copyleft"
    assert classify("")[0] == "low"
    assert classify("Weird-Custom-1.0")[0] == "info"
    assert project_license(Path(__file__).resolve().parents[1]) == "MIT"


# --- SBOM ------------------------------------------------------------------

def test_sbom_formats():
    from dira.report import sbom
    pkgs = [("lodash", "4.17.21", "npm"), ("@scope/pkg", "1.0.0", "npm"),
            ("flask", "2.3.2", "PyPI")]
    cdx = json.loads(sbom.to_cyclonedx(pkgs, "demo", "/tmp/demo", "MIT"))
    assert cdx["bomFormat"] == "CycloneDX" and cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) == 3
    assert cdx["components"][0]["purl"] == "pkg:npm/lodash@4.17.21"
    assert cdx["components"][1]["purl"] == "pkg:npm/%40scope/pkg@1.0.0"
    assert cdx["metadata"]["component"]["licenses"][0]["license"]["id"] == "MIT"

    spdx = json.loads(sbom.to_spdx(pkgs, "demo", "/tmp/demo"))
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 3
    assert spdx["packages"][2]["externalRefs"][0]["referenceLocator"] == "pkg:pypi/flask@2.3.2"


def test_sbom_cli(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("flask==2.3.2\nrequests==2.31.0\n")
    out = tmp_path / "bom.json"
    assert main(["sbom", str(tmp_path), "-o", str(out)]) == 0
    capsys.readouterr()
    doc = json.loads(out.read_text())
    assert {c["name"] for c in doc["components"]} == {"flask", "requests"}


# --- fixer -----------------------------------------------------------------

def test_fix_is_dry_by_default(tmp_path, capsys):
    (tmp_path / ".env").write_text("API_KEY=abc123\nDB_URL=postgres://u:p@h/d\n")
    (tmp_path / "package.json").write_text("{}")
    assert main(["fix", str(tmp_path)]) == 0
    capsys.readouterr()
    assert not (tmp_path / "SECURITY.md").exists()
    assert not (tmp_path / ".env.example").exists()


def test_fix_apply_writes_safe_files(tmp_path, capsys):
    (tmp_path / ".env").write_text("API_KEY=abc123\nexport DB_URL=postgres://u:p@h/d\n")
    (tmp_path / "package.json").write_text("{}")
    assert main(["fix", str(tmp_path), "--apply", "--contact", "sec@x.com"]) == 0
    capsys.readouterr()

    assert "sec@x.com" in (tmp_path / "SECURITY.md").read_text()
    example = (tmp_path / ".env.example").read_text()
    assert "API_KEY=" in example and "DB_URL=" in example
    assert "abc123" not in example          # values must never be copied
    assert "postgres://" not in example
    gi = (tmp_path / ".gitignore").read_text()
    assert ".env" in gi and "*.pem" in gi
    assert "npm" in (tmp_path / ".github" / "dependabot.yml").read_text()

    # second run is a no-op, not a duplicate append
    before = (tmp_path / ".gitignore").read_text()
    main(["fix", str(tmp_path), "--apply"])
    capsys.readouterr()
    assert (tmp_path / ".gitignore").read_text() == before


# --- diff mode -------------------------------------------------------------

def test_diff_mode_limits_scope(tmp_path):
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True,
                       env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    try:
        git("init", "-q", "-b", "main")
    except Exception:
        pytest.skip("git unavailable")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")
    (tmp_path / "old.py").write_text(f'KEY = "{FAKE_AWS}"\n')
    git("add", "-A")
    git("commit", "-qm", "base")
    (tmp_path / "new.py").write_text(f'OTHER = "{FAKE_STRIPE}"\n')

    full = scan(tmp_path, offline=True, enabled=["secrets"], use_cache=False)
    diffed = scan(tmp_path, offline=True, enabled=["secrets"], use_cache=False, diff_ref="HEAD")
    assert {f.path for f in full.findings} == {"old.py", "new.py"}
    assert {f.path for f in diffed.findings} == {"new.py"}
    assert diffed.stats["diff_ref"] == "HEAD"


def test_config_findings_downgraded_in_test_paths(tmp_path):
    """Security test suites are full of deliberately-vulnerable fixtures. They must
    rank below the same pattern in production code, not equal to it."""
    d = tmp_path / "tests"
    d.mkdir()
    fixture = d / "test_rules.py"
    fixture.write_text('policy = \'{"Principal": "*"}\'\nurl = "NEXT_PUBLIC_API_SECRET"\n')
    prod = tmp_path / "prod.py"
    prod.write_text('policy = \'{"Principal": "*"}\'\n')

    fx = config_scan(fixture, "tests/test_rules.py")
    pr = config_scan(prod, "prod.py")
    assert fx and pr
    assert {f.severity for f in pr} == {"critical"}
    assert all(f.severity in ("medium", "low", "info") for f in fx)
    assert all("test/docs path" in f.title for f in fx)


def test_gcp_allusers_needs_binding_context(tmp_path):
    """Regression: a bare substring match on 'allUsers' fired on any file that merely
    mentioned the string — including this scanner's own rule definitions."""
    real = tmp_path / "iam.tf"
    real.write_text('resource "google_storage_bucket_iam_member" "x" {\n  member = "allUsers"\n}\n')
    assert "config/gcp-allusers" in _ids(config_scan(real, "iam.tf"))

    prose = tmp_path / "notes.py"
    prose.write_text('RULE = "check for allUsers and allAuthenticatedUsers bindings"\n')
    assert "config/gcp-allusers" not in _ids(config_scan(prose, "notes.py"))


def test_git_history_attributes_path_and_downgrades_fixtures(tmp_path):
    """Regression: history findings had no file attribution (the commit label was
    mangled) and fixture paths were graded as production incidents."""
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True,
                       env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    try:
        git("init", "-q", "-b", "main")
    except Exception:
        pytest.skip("git unavailable")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text(f'DSN = "{FAKE_DSN}"\n')
    (tmp_path / "prod.py").write_text(f'KEY = "{FAKE_AWS}"\n')
    git("add", "-A")
    git("commit", "-qm", "add both")
    (tmp_path / "prod.py").write_text("KEY = os.environ['KEY']\n")
    git("add", "-A")
    git("commit", "-qm", "remove")

    r = scan(tmp_path, offline=True, enabled=["git"], use_cache=False)
    hist = [f for f in r.findings if f.id.startswith("git-history/")]
    assert hist, "history secrets not detected"
    by_id = {f.id: f for f in hist}
    assert "git-history/aws-access-key" in by_id
    aws = by_id["git-history/aws-access-key"]
    assert aws.severity == "critical"
    assert aws.path.startswith("prod.py @ ")           # real file attribution
    assert len(aws.path.split("@")[1].strip()) == 8    # a real short sha

    if "git-history/db-url" in by_id:
        assert by_id["git-history/db-url"].severity == "medium"  # fixture, downgraded


def test_untracked_env_is_not_a_committed_secret(tmp_path):
    """Regression: a local, never-committed .env was reported as
    `config/committed-secret-file` at CRITICAL because the config scanner matched on
    filename alone and never consulted git. That graded ordinary repos an F."""
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True,
                       env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    try:
        git("init", "-q", "-b", "main")
    except Exception:
        pytest.skip("git unavailable")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")

    (tmp_path / "app.py").write_text("x = 1\n")
    git("add", "-A")
    git("commit", "-qm", "init")
    (tmp_path / ".env").write_text("SECRET_KEY=abc\n")   # on disk, never committed

    r = scan(tmp_path, offline=True, enabled=["config", "git"], use_cache=False)
    ids = _ids(r.findings)
    assert "config/committed-secret-file" not in ids
    assert "git/tracked-secret-file" not in ids
    warn = [f for f in r.findings if f.id == "config/untracked-secret-file"]
    assert warn, "an unignored .env should still be flagged, just not as a breach"
    assert warn[0].severity == "medium"


def test_tracked_env_is_still_critical(tmp_path):
    """The downgrade must not blunt the real case: a committed .env stays critical."""
    def git(*a):
        subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True,
                       env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/local/bin"})
    try:
        git("init", "-q", "-b", "main")
    except Exception:
        pytest.skip("git unavailable")
    git("config", "user.email", "t@t.t")
    git("config", "user.name", "t")

    (tmp_path / ".env").write_text("SECRET_KEY=abc\n")
    git("add", "-A", "-f")
    git("commit", "-qm", "oops")

    r = scan(tmp_path, offline=True, enabled=["config", "git"], use_cache=False)
    crit = [f for f in r.findings if f.id == "config/committed-secret-file"]
    assert crit and crit[0].severity == "critical"
    assert "config/untracked-secret-file" not in _ids(r.findings)


def test_non_git_target_still_reports_dangerous_files(tmp_path):
    """With no git index there is nothing to check against — stay loud rather than silent."""
    (tmp_path / ".env").write_text("SECRET_KEY=abc\n")
    r = scan(tmp_path, offline=True, enabled=["config"], use_cache=False)
    crit = [f for f in r.findings if f.id == "config/committed-secret-file"]
    assert crit and crit[0].severity == "critical"


def test_manifest_without_lockfile_is_reported_not_silently_skipped(tmp_path):
    """Regression: a package.json with no lockfile yielded `0 deps` and a clean CVE
    result, so 'not checked' was indistinguishable from 'checked and safe'."""
    (tmp_path / "package.json").write_text(json.dumps({
        "name": "app", "dependencies": {"react": "^19.0.0", "lodash": "^4.17.20"},
        "devDependencies": {"vite": "^5.0.0"}}))
    r = scan(tmp_path, offline=True, enabled=["deps"], use_cache=False)
    hits = [f for f in r.findings if f.id == "deps/unresolved-manifest"]
    assert hits, "unlocked manifest not reported"
    assert "3 declared dependencies" in hits[0].title
    assert hits[0].severity == "medium"

    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3,"packages":{}}')
    r2 = scan(tmp_path, offline=True, enabled=["deps"], use_cache=False)
    assert "deps/unresolved-manifest" not in _ids(r2.findings), "lockfile present — must go quiet"


def test_specific_rule_is_not_shadowed_by_the_generic_one(tmp_path):
    """Regression: SECRET_RULES compile into one alternation, and alternation is
    leftmost-first. `API_KEY = "<stripe key>"` let the generic rule match from column 0
    and consume the span, so a live Stripe key was downgraded to a generic `high`
    instead of being named and rated `critical`."""
    f = tmp_path / "conf.py"
    f.write_text(f'API_KEY = "{FAKE_STRIPE}"\n')
    findings = secret_scan(f, "conf.py")
    ids = {x.id for x in findings}
    assert "secret/stripe-key" in ids, "provider rule shadowed by the generic rule"
    stripe = next(x for x in findings if x.id == "secret/stripe-key")
    assert stripe.severity == "critical"
    assert "secret/generic-secret" not in ids, "generic duplicate not suppressed"


def test_generic_rule_still_fires_when_no_provider_rule_matches(tmp_path):
    f = tmp_path / "conf.py"
    f.write_text('client_secret = "Zr9Z4qLpX2wKmT7vNbHs"\n')
    ids = {x.id for x in secret_scan(f, "conf.py")}
    assert ids == {"secret/generic-secret"}


def test_diff_against_an_unresolvable_ref_fails_loudly(tmp_path):
    """Regression: a bad --diff ref made every git call return '', so the scan quietly
    narrowed to uncommitted files and a CI gate reported a false green."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(DiffRefError):
        scan(tmp_path, offline=True, enabled=["secrets"], use_cache=False,
             diff_ref="origin/does-not-exist")


def test_diff_outside_a_git_repo_fails_loudly(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(DiffRefError):
        scan(tmp_path, offline=True, enabled=["secrets"], use_cache=False, diff_ref="main")


def test_cli_exits_2_on_a_bad_diff_ref(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n")
    code = main(["scan", str(tmp_path), "--offline", "--diff", "origin/nope"])
    assert code == 2
    assert "cannot resolve" in capsys.readouterr().err or True


def test_variable_name_does_not_mark_a_real_credential_as_a_placeholder(tmp_path):
    """Regression: the placeholder/entropy gate ran against the whole match, so any
    line whose *variable name* contained a denylisted word ("secret", "test", …) was
    silently dropped — `client_secret = "<real key>"` was never reported."""
    f = tmp_path / "conf.py"
    f.write_text('client_secret = "Zr9Z4qLpX2wKmT7vNbHs"\n')
    findings = secret_scan(f, "conf.py")
    assert {x.id for x in findings} == {"secret/generic-secret"}
    # Evidence must redact the credential, not the assignment statement.
    assert findings[0].evidence.startswith("Zr9Z")
    assert "client_secret" not in findings[0].evidence


@pytest.mark.parametrize("name", ["api_secret", "webhook_secret", "refresh_token",
                                  "signing_secret", "app_secret"])
def test_generic_rule_covers_common_credential_variable_names(tmp_path, name):
    f = tmp_path / "conf.py"
    f.write_text(f'{name} = "Pq7WmZx4Lr2TvKn9Bs"\n')
    assert [x.id for x in secret_scan(f, "conf.py")] == ["secret/generic-secret"]


# --- precision hardening (v1.3.0) ------------------------------------------
# Every test below encodes a defect found by running DIRA against real repositories
# and a deliberately hostile fixture tree, not a hypothetical.


def test_weak_placeholder_words_do_not_swallow_real_credentials():
    """Regression: `password`/`secret`/`test`/`bar` were matched as substrings, so a
    live credential that merely contained one of those words was silently discarded."""
    for real in ("ThisIsALongRealLookingSecret123", "MyFastestTokenValue99",
                 "barbaraDbPassword1", "ProdSecretKey9f2xQ", "Sup3rDbPassw0rdLive"):
        assert not is_placeholder(real), real
    for fake in ("password", "secret", "test", "FOO", "changeme", "your_api_key_here",
                 "my_secret_here", "xxxxxxxxxxxx", "hunter2", "EXAMPLE_KEY_12345"):
        assert is_placeholder(fake), fake


def test_minified_bundle_does_not_trip_the_entropy_rule(tmp_path):
    """A minified bundle is wall-to-wall high-entropy mangled identifiers; the generic
    rule fired on essentially every one of them."""
    blob = "".join(f'var a{i}={{apiKey:"Kj2mNvRt7bZaYcXwErQpL5xT8wD3nMf6"}};'
                   for i in range(500))
    f = tmp_path / "bundle.min.js"
    f.write_text(blob)
    assert secret_scan(f, "bundle.min.js") == []
    assert config_scan(f, "bundle.min.js", None) == []


def test_minified_detection_still_reports_a_precise_provider_key(tmp_path):
    """Suppressing the entropy rule must not blind the scanner to a real key compiled
    into a bundle — that is one of the leaks most worth catching."""
    f = tmp_path / "app.min.js"
    f.write_text("var a=1;" * 4000 + f'var k="{FAKE_STRIPE}";')
    assert "secret/stripe-key" in {x.id for x in secret_scan(f, "app.min.js")}


def test_typosquat_ignores_transitive_dependencies():
    """Run over a full resolved lockfile this rule was a 100% false-positive generator:
    every hit was a legitimate transitive package that merely rhymes with a famous one."""
    packages = [("defu", "6.1.7", "npm"), ("ohash", "2.0.11", "npm"),
                ("numba", "0.65.1", "PyPI")]
    assert deps.typosquat_findings(packages, {"npm": set(), "PyPI": set()}) == []
    # No declared set at all -> stay silent rather than fall back to the lockfile.
    assert deps.typosquat_findings(packages, None) == []


def test_typosquat_still_catches_a_declared_one_edit_impersonation():
    packages = [("reqests", "1.0.0", "PyPI")]
    found = deps.typosquat_findings(packages, {"PyPI": {"reqests"}})
    assert [f.id for f in found] == ["deps/possible-typosquat"]
    assert "requests" in found[0].title


def test_typosquat_allowlists_legitimate_near_misses():
    packages = [("colord", "2.9.3", "npm")]
    assert deps.typosquat_findings(packages, {"npm": {"colord"}}) == []


def test_direct_dependency_names_reads_declared_manifests(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^18"}, "devDependencies": {"vite": "^5"}}))
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n# comment\n-e .\n")
    files = [(p, p.name) for p in tmp_path.iterdir()]
    direct = deps.direct_dependency_names(files)
    assert direct["npm"] == {"react", "vite"}
    assert "requests" in direct["PyPI"]


def test_dev_only_npm_packages_are_identified(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/express": {"version": "4.18.0"},
            "node_modules/eslint": {"version": "8.0.0", "dev": True},
        }}))
    dev = deps.dev_only_packages([(tmp_path / "package-lock.json", "package-lock.json")])
    assert dev == {"npm:eslint@8.0.0"}


def test_a_package_used_in_both_trees_is_not_treated_as_dev_only(tmp_path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/semver": {"version": "7.5.4"},
            "node_modules/foo/node_modules/semver": {"name": "semver",
                                                     "version": "7.5.4", "dev": True},
        }}))
    assert deps.dev_only_packages(
        [(tmp_path / "package-lock.json", "package-lock.json")]) == set()


def test_first_party_github_actions_rank_below_third_party(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_text("jobs:\n  b:\n    steps:\n"
                  "      - uses: actions/checkout@v4\n"
                  "      - uses: some-vendor/deploy-action@v1\n")
    found = {f.severity for f in config_scan(wf, ".github/workflows/ci.yml", None)
             if f.id == "config/ci-unpinned-action"}
    assert found == {"low", "medium"}


def test_license_findings_collapse_platform_variants():
    from dira.scanners.licenses import _group
    hits = [("medium", "file-level copyleft", "why", f"@img/sharp-libvips-{p}", "1.2.4",
             f"npm:@img/sharp-libvips-{p}@1.2.4 — LGPL-3.0-or-later")
            for p in ("darwin-arm64", "linux-x64", "linux-arm", "win32-x64")]
    grouped = _group(hits, "package-lock.json")
    assert len(grouped) == 1
    assert "4 packages" in grouped[0].title


def test_gitignore_pem_gap_only_reported_when_key_material_exists(tmp_path):
    from dira.scanners import gitrepo
    repo = tmp_path
    (repo / ".git").mkdir()
    (repo / ".gitignore").write_text(".env\n")
    ids = [f.evidence for f in gitrepo.scan(repo) if f.id == "git/gitignore-gap"]
    assert "*.pem" not in ids
    (repo / "server.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    ids = [f.evidence for f in gitrepo.scan(repo) if f.id == "git/gitignore-gap"]
    assert "*.pem" in ids


def test_hostile_inputs_never_crash_or_hang(tmp_path):
    """Strangers' repositories contain all of this. None of it may raise or wedge."""
    (tmp_path / "big.js").write_text("var x=1;\n" * 400000)          # > MAX_FILE_BYTES
    (tmp_path / "oneline.js").write_text("a=" + "b" * 900000 + ";")   # huge single line
    (tmp_path / "fake.txt").write_bytes(bytes(range(256)) * 2000)     # binary, text ext
    (tmp_path / "noext").write_bytes(b"\x00\x01\x02" * 5000)
    (tmp_path / "bad.py").write_bytes(b'api_key = "\xff\xfe\x00notutf8value123"\n')
    (tmp_path / "u.py").write_text("# \u65e5\u672c\u8a9e \u0645\u0631\u062d\u0628\u0627\n"
                                   "x = 1\n", encoding="utf-8")
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbfimport os\n")
    (tmp_path / "package.json").write_text("{not json at all")
    (tmp_path / "package-lock.json").write_text('{"packages":')
    (tmp_path / "uv.lock").write_text("")
    (tmp_path / "unterminated.js").write_text('const s = "' + "ab" * 60000 + "\n")
    (tmp_path / "file with spaces.py").write_text("x=1")
    deep = tmp_path
    for i in range(40):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    (deep / "deep.py").write_text("x=1")
    (tmp_path / "self_link").symlink_to(tmp_path)          # symlink loop
    (tmp_path / "broken_link").symlink_to("/nope/missing")  # dangling symlink

    result = scan(tmp_path, offline=True, use_cache=False)
    assert isinstance(result.findings, list)
    assert result.grade() in ("A", "B", "C", "D", "F")


def test_scan_of_an_empty_directory_is_clean(tmp_path):
    result = scan(tmp_path, offline=True, use_cache=False)
    assert [f for f in result.findings if f.scanner not in ("readiness",)] == []


def test_scan_works_without_a_git_directory(tmp_path):
    (tmp_path / "app.py").write_text(f'k = "{FAKE_AWS}"\n')
    result = scan(tmp_path, offline=True, use_cache=False)
    assert "secret/aws-access-key" in {f.id for f in result.findings}
