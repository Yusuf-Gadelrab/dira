"""Detection rules. Secret patterns compile into ONE alternation so each file is
scanned in a single pass instead of once per rule."""

from __future__ import annotations

import math
import re

RULESET_VERSION = "1.2.0"


class SecretRule:
    def __init__(self, rid: str, title: str, severity: str, pattern: str,
                 remediation: str, entropy: float = 0.0):
        self.id = rid
        self.title = title
        self.severity = severity
        self.pattern = pattern
        self.remediation = remediation
        self.entropy = entropy
        self.group = "g" + rid.replace("-", "_")


ROTATE = "Revoke the key at the provider, issue a new one, move it to a secret manager, and purge it from git history (git filter-repo / BFG)."

SECRET_RULES: list[SecretRule] = [
    SecretRule("aws-access-key", "AWS access key ID", "critical",
               r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b", ROTATE),
    SecretRule("aws-secret-key", "AWS secret access key", "critical",
               r"(?i)aws[_\-. ]?(?:secret|sec)[_\-. ]?(?:access)?[_\-. ]?key[\"'\s:=]{1,20}([A-Za-z0-9/+=]{40})", ROTATE),
    SecretRule("gcp-service-account", "GCP service-account private key", "critical",
               r"\"type\"\s*:\s*\"service_account\"", ROTATE),
    SecretRule("private-key", "Private key material", "critical",
               r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", ROTATE),
    SecretRule("github-token", "GitHub token", "critical",
               r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b", ROTATE),
    SecretRule("gitlab-token", "GitLab personal access token", "critical",
               r"\b(glpat-[A-Za-z0-9\-_]{20,})\b", ROTATE),
    SecretRule("slack-token", "Slack token", "high",
               r"\b(xox[abposr]-[A-Za-z0-9\-]{10,})\b", ROTATE),
    SecretRule("slack-webhook", "Slack incoming webhook", "medium",
               r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})", ROTATE),
    SecretRule("stripe-key", "Stripe secret/restricted key", "critical",
               r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b", ROTATE),
    SecretRule("openai-key", "OpenAI API key", "critical",
               r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})\b", ROTATE),
    SecretRule("anthropic-key", "Anthropic API key", "critical",
               r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b", ROTATE),
    SecretRule("google-api-key", "Google API key", "high",
               r"\b(AIza[0-9A-Za-z_\-]{35})\b", ROTATE),
    SecretRule("sendgrid-key", "SendGrid API key", "critical",
               r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b", ROTATE),
    SecretRule("twilio-key", "Twilio account SID / key", "high",
               r"\b((?:AC|SK)[0-9a-fA-F]{32})\b", ROTATE),
    SecretRule("npm-token", "npm access token", "critical",
               r"\b(npm_[A-Za-z0-9]{36})\b", ROTATE),
    SecretRule("hf-token", "Hugging Face token", "high",
               r"\b(hf_[A-Za-z0-9]{34,})\b", ROTATE),
    SecretRule("jwt", "Hardcoded JWT", "medium",
               r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
               "If this is a signed session/service token, rotate the signing secret and stop committing tokens."),
    SecretRule("db-url", "Database URL with inline credentials", "critical",
               r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/\"']+:[^\s:@/\"']+@[^\s\"'<>]+)",
               "Move the DSN to an env var / secret manager and rotate the database password."),
    SecretRule("basic-auth-url", "URL with embedded basic-auth credentials", "high",
               r"\b(https?://[^\s:@/\"']+:[^\s:@/\"']{3,}@[^\s\"'<>]+)",
               "Use a header-based token from a secret store instead of credentials in the URL."),
    SecretRule("generic-secret", "Generic hardcoded credential", "high",
               r"(?i)\b(?:api[_\-]?key|apikey|secret|passwd|password|pwd|token|client[_\-]?secret|auth[_\-]?token|access[_\-]?token|private[_\-]?key)\b\s*[:=]\s*[\"']([^\"'\s]{12,120})[\"']",
               ROTATE, entropy=3.4),
]

PLACEHOLDER_RE = re.compile(
    r"^(?:\$|\{\{|<|%|process\.env|os\.environ|env\[|import\.meta|null|none|true|false)"
    r"|\byour[_\-]?\w*|[_\-]here\b|\bhere\b"
    r"|(?:my[_\-]?|the[_\-]?)?(?:example|sample|placeholder|changeme|change[_\-]?me"
    r"|dummy|fake|test|foo|bar|redacted|xxx+|todo|insert|replace|abcdef|123456|password"
    r"|secret|s3cret|not[_\-]?real)",
    re.IGNORECASE,
)
TEST_PATH_RE = re.compile(r"(?i)(^|/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|docs?|samples?)(/|$)")
DOC_EXT = {".md", ".mdx", ".rst", ".txt", ".adoc"}

def _scoped(pattern: str) -> str:
    """`(?i)` is a global flag and is illegal mid-alternation — scope it to its own group."""
    return f"(?i:{pattern[4:]})" if pattern.startswith("(?i)") else pattern


_MASTER = re.compile(
    "|".join(f"(?P<{r.group}>{_scoped(r.pattern)})" for r in SECRET_RULES)
)
_BY_GROUP = {r.group: r for r in SECRET_RULES}


def scan_secrets(text: str):
    """Yields (rule, match). One regex pass for all rules."""
    for m in _MASTER.finditer(text):
        rule = _BY_GROUP[m.lastgroup] if m.lastgroup in _BY_GROUP else None
        if rule is None:
            for g, r in _BY_GROUP.items():
                if m.groupdict().get(g):
                    rule = r
                    break
        if rule:
            yield rule, m


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = value.strip()
    if not v or len(v) < 8:
        return True
    if PLACEHOLDER_RE.search(v):
        return True
    if len(set(v)) <= 3:  # "aaaaaaaaaaaa", "xxxxxxxx"
        return True
    return False


# --- Config / IaC misconfiguration rules -----------------------------------
# (id, title, severity, filename glob, regex, remediation)
CONFIG_RULES = [
    ("docker-latest-tag", "Base image pinned to :latest", "low", "Dockerfile*",
     r"(?im)^\s*FROM\s+\S+:latest", "Pin to a digest or explicit version for reproducible, auditable builds."),
    ("docker-add-remote", "ADD used with a remote URL", "medium", "Dockerfile*",
     r"(?im)^\s*ADD\s+https?://", "Use COPY plus an explicit, checksum-verified download step."),
    ("docker-secret-arg", "Secret passed as build ARG/ENV", "high", "Dockerfile*",
     r"(?im)^\s*(?:ARG|ENV)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_?KEY)\w*\s*[= ]\s*\S+",
     "Build ARGs persist in image layers — use BuildKit `--mount=type=secret` or runtime env."),
    ("compose-privileged", "Privileged container", "high", "docker-compose*.y*ml",
     r"(?im)^\s*privileged:\s*true", "Drop `privileged` and grant only the specific capabilities needed."),
    ("compose-host-network", "Host network mode", "medium", "docker-compose*.y*ml",
     r"(?im)^\s*network_mode:\s*[\"']?host", "Use a bridge network with explicit port mappings."),
    ("k8s-privileged", "Kubernetes privileged securityContext", "high", "*.y*ml",
     r"(?im)^\s*privileged:\s*true", "Set `privileged: false`, `allowPrivilegeEscalation: false`, and drop ALL capabilities."),
    ("k8s-host-path", "Kubernetes hostPath volume", "medium", "*.y*ml",
     r"(?im)^\s*hostPath:", "Use a PVC or emptyDir; hostPath breaks node isolation."),
    ("tf-open-ingress", "Security group open to 0.0.0.0/0", "critical", "*.tf",
     r"cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\"", "Restrict ingress to known CIDRs or put the service behind a load balancer/VPN."),
    ("tf-public-bucket", "Public-read S3 ACL", "critical", "*.tf",
     r"acl\s*=\s*\"public-read(?:-write)?\"", "Set the bucket private and serve via CloudFront OAC or presigned URLs."),
    ("tf-unencrypted", "Storage encryption disabled", "high", "*.tf",
     r"(?im)^\s*(?:encrypted|storage_encrypted)\s*=\s*false", "Enable encryption at rest (KMS-managed keys)."),
    ("ci-pull-request-target", "Workflow uses pull_request_target", "high", ".github/workflows/*.y*ml",
     r"(?im)^\s*pull_request_target:", "pull_request_target runs with repo secrets on fork code — use pull_request, or never check out the PR head."),
    ("ci-unpinned-action", "GitHub Action pinned to a mutable ref", "medium", ".github/workflows/*.y*ml",
     r"(?im)^\s*-?\s*uses:\s*[\w\-./]+@(?:main|master|v\d+(?:\.\d+)*)\s*$",
     "Pin third-party actions to a full commit SHA — tags are mutable and are a live supply-chain risk."),
    ("ci-script-injection", "Untrusted input interpolated into a run block", "high", ".github/workflows/*.y*ml",
     r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)[^}]*(?:title|body|head\.ref|login)[^}]*\}\}",
     "Pass the value through an `env:` var and reference \"$VAR\" — direct interpolation is shell injection."),
    ("cors-wildcard", "Wildcard CORS origin", "high", "*",
     r"(?i)(?:Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']\*|cors\(\s*\{[^}]*origin\s*:\s*[\"']\*|allow_origins\s*=\s*\[\s*[\"']\*)",
     "Echo an explicit allowlist of origins; `*` with credentials is rejected and without them still leaks APIs."),
    ("debug-enabled", "Debug mode enabled", "medium", "*",
     r"(?i)\b(?:DEBUG|FLASK_DEBUG|APP_DEBUG)\s*[:=]\s*(?:True|1|\"true\"|'true'|true)\b",
     "Force DEBUG off in production config — debug pages leak stack traces, env, and source."),
    ("tls-verify-off", "TLS verification disabled", "high", "*",
     r"(?i)(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|curl\s+[^\n]*(?:-k\b|--insecure))",
     "Never disable certificate verification; pin a CA bundle instead."),
    ("weak-hash", "Weak hash used for credentials", "medium", "*",
     r"(?i)(?:hashlib\.(?:md5|sha1)|createHash\(\s*[\"'](?:md5|sha1)[\"']\))[^\n]{0,80}(?:password|passwd|secret|token)",
     "Use bcrypt, scrypt, or Argon2id for passwords; SHA-256+ for integrity."),
    ("shell-injection", "Shell execution with interpolated input", "high", "*",
     r"(?i)(?:subprocess\.\w+\([^)]*shell\s*=\s*True|os\.system\(\s*[^)]*[+%f]|child_process\.exec\(\s*[`\"'][^`\"']*\$\{)",
     "Pass an argument list instead of a shell string; never interpolate user input into a command."),
    ("sql-injection", "SQL built by string concatenation", "high", "*",
     r"(?i)(?:execute|query|cursor\.execute)\s*\(\s*[f\"'`][^\"'`]*(?:SELECT|INSERT|UPDATE|DELETE)[^\"'`]*[\"'`]\s*(?:%|\+|\.format\(|,\s*\w+\s*\+)",
     "Use parameterized queries / bound placeholders."),
    ("eval-use", "Dynamic eval of application data", "medium", "*",
     r"(?i)(?:\beval\(|new Function\(|pickle\.loads\(|yaml\.load\((?!.*Loader\s*=\s*(?:yaml\.)?SafeLoader))",
     "Replace with JSON parsing / yaml.safe_load; eval and pickle are RCE primitives."),

    # --- frontend / browser ------------------------------------------------
    ("public-env-secret", "Secret exposed through a public build-time env var", "critical", "*",
     r"(?:NEXT_PUBLIC|VITE|REACT_APP|PUBLIC|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_\w*(?:SECRET|PRIVATE|API_?KEY|TOKEN|PASSWORD)\w*",
     "Anything with this prefix is compiled into the JS bundle and readable by every visitor — "
     "move it server-side (route handler / edge function) and rotate the value."),
    ("token-in-localstorage", "Auth token stored in localStorage", "high", "*",
     r"(?i)(?:localStorage|sessionStorage)\.setItem\(\s*[\"'`][^\"'`]*(?:token|jwt|auth|session|api[_\-]?key|password)",
     "Any XSS reads localStorage. Use an httpOnly, Secure, SameSite cookie for session material."),
    ("react-dangerous-html", "dangerouslySetInnerHTML with dynamic content", "medium", "*",
     r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:\s*(?!['\"`])",
     "Sanitize with DOMPurify before injecting, or render as text."),
    ("dom-innerhtml", "innerHTML assigned from a variable or template", "medium", "*",
     r"\.(?:innerHTML|outerHTML)\s*=\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*(?:\+|;|$))",
     "Use textContent, or sanitize with DOMPurify — innerHTML is the most common XSS sink."),
    ("postmessage-wildcard", "postMessage to any origin", "medium", "*",
     r"\.postMessage\([^)]*,\s*[\"']\*[\"']",
     "Pass the exact target origin, and validate `event.origin` on the receiving side."),
    ("jwt-none-alg", "JWT verification accepts the `none` algorithm", "critical", "*",
     r"(?i)(?:algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']|verify\s*[:=]\s*[Ff]alse[^\n]{0,40}jwt|jwt\.decode\([^)]*verify\s*=\s*False)",
     "Pin the expected algorithm (RS256/HS256) and always verify the signature."),

    # --- LLM / AI application risks ----------------------------------------
    ("llm-browser-key", "LLM API key shipped to the browser", "critical", "*",
     r"dangerouslyAllowBrowser\s*:\s*true",
     "This puts your provider key in client-side JS where anyone can drain it. "
     "Proxy the call through your own backend and rotate the key."),
    ("llm-prompt-injection", "Untrusted input concatenated into a prompt", "medium", "*",
     r"(?i)(?:prompt|messages|system)\s*[:=]\s*f?[\"'`][^\"'`]{0,200}\$?\{(?:user|req|input|query|body|params|message|msg|text|content|comment|email)\w*",
     "Keep untrusted text in a separate user-role message with explicit delimiters, never inside "
     "the system prompt, and treat model output as untrusted."),
    ("llm-unbounded-exec", "Model output passed to an executor", "high", "*",
     r"(?i)(?:exec|eval|subprocess\.\w+|os\.system|child_process\.\w+)\s*\([^)]*(?:completion|response|llm|model|choices\[0\]|message\.content)",
     "Never execute model output directly — constrain it to a whitelisted action schema and validate before dispatch."),

    # --- cloud / platform --------------------------------------------------
    ("firebase-open-rules", "Firebase rules allow public read/write", "critical", "*",
     r"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true",
     "Scope rules to `request.auth.uid`; `if true` exposes the whole database to the internet."),
    ("iam-wildcard-principal", "IAM policy grants access to any principal", "critical", "*",
     r"[\"']Principal[\"']\s*:\s*(?:[\"']\*[\"']|\{\s*[\"']AWS[\"']\s*:\s*[\"']\*[\"'])",
     "Name explicit principals; `\"Principal\": \"*\"` is anonymous public access."),
    ("iam-wildcard-action", "IAM policy grants `*` actions on `*` resources", "high", "*",
     r"[\"']Action[\"']\s*:\s*[\"']\*[\"'][^}]{0,200}[\"']Resource[\"']\s*:\s*[\"']\*[\"']",
     "Grant least privilege — enumerate the actions and ARNs the role actually needs."),
    ("gcp-allusers", "GCP IAM binding to allUsers/allAuthenticatedUsers", "critical", "*",
     # Requires real binding context — a bare substring match fires on any prose mentioning it.
     r"(?im)(?:^\s*-\s*|members?\s*[:=]\s*\[?\s*[\"']|[\"']members?[\"']\s*:\s*\[?\s*[\"'])(?:allUsers|allAuthenticatedUsers)\b",
     "Remove the public binding unless this resource is intentionally anonymous."),
    ("curl-pipe-shell", "Remote script piped straight into a shell", "high", "*",
     r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|s)?sh",
     "Download, checksum, review, then execute — a piped installer is a one-line supply-chain compromise."),
]

CODE_RULE_IDS = {
    "cors-wildcard", "debug-enabled", "tls-verify-off", "weak-hash",
    "shell-injection", "sql-injection", "eval-use", "public-env-secret",
    "token-in-localstorage", "react-dangerous-html", "dom-innerhtml",
    "postmessage-wildcard", "jwt-none-alg", "llm-browser-key",
    "llm-prompt-injection", "llm-unbounded-exec", "firebase-open-rules",
    "iam-wildcard-principal", "iam-wildcard-action", "gcp-allusers",
    "curl-pipe-shell",
}

# Files that must never be committed.
DANGEROUS_FILES = [
    (".env", "critical", "Environment file committed to the repo"),
    (".env.local", "critical", "Environment file committed to the repo"),
    (".env.production", "critical", "Production environment file committed to the repo"),
    ("id_rsa", "critical", "SSH private key committed to the repo"),
    ("id_ed25519", "critical", "SSH private key committed to the repo"),
    (".npmrc", "high", "npmrc may contain a registry auth token"),
    (".pypirc", "high", "pypirc may contain PyPI credentials"),
    ("credentials", "high", "Cloud credentials file committed to the repo"),
    ("service-account.json", "critical", "GCP service-account key committed to the repo"),
    ("terraform.tfstate", "high", "Terraform state contains resource secrets in plaintext"),
    ("*.pem", "high", "Certificate/key material committed to the repo"),
    ("*.p12", "high", "PKCS#12 keystore committed to the repo"),
    ("*.keystore", "high", "Android keystore committed to the repo"),
]
