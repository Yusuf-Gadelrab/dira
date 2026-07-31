"""Detection rules. Secret patterns compile into ONE alternation so each file is
scanned in a single pass instead of once per rule."""

from __future__ import annotations

import math
import re

RULESET_VERSION = "1.5.0"


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
    # Anthropic keys are also "sk-…", so the OpenAI pattern must not swallow them —
    # alternation is leftmost-first and OpenAI's rule sits earlier in this list, so
    # without the lookahead every Anthropic key was misreported as an OpenAI key.
    SecretRule("openai-key", "OpenAI API key", "critical",
               r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,})\b", ROTATE),
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
    SecretRule("github-fine-grained-pat", "GitHub fine-grained personal access token", "critical",
               r"\b(github_pat_[A-Za-z0-9_]{82})\b", ROTATE, entropy=3.0),
    SecretRule("supabase-secret-key", "Supabase secret API key", "critical",
               r"\b(sb_secret_[A-Za-z0-9_\-]{20,})\b",
               "This key bypasses Row Level Security. " + ROTATE, entropy=3.0),
    SecretRule("azure-storage-key", "Azure Storage account key", "critical",
               r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)", ROTATE),
    SecretRule("digitalocean-token", "DigitalOcean personal access token", "critical",
               r"\b(dop_v1_[a-f0-9]{64})\b", ROTATE, entropy=2.5),
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
               r"(?i)\b(?:api[_\-]?key|apikey|secret|passwd|password|pwd|token"
               r"|(?:client|api|app|shared|signing|webhook)[_\-]?secret"
               r"|(?:auth|access|refresh|bearer)[_\-]?token|private[_\-]?key)\b"
               r"\s*[:=]\s*[\"']([^\"'\s]{12,120})[\"']",
               ROTATE, entropy=3.4),
]

# Markers that mean "not a real credential" even when embedded in a longer value.
PLACEHOLDER_RE = re.compile(
    r"^(?:\$|\{\{|<|%|process\.env|os\.environ|env\[|import\.meta|null|none|true|false)"
    r"|\byour[_\-]?\w*|[_\-]here\b|\bhere\b"
    r"|(?:example|sample|placeholder|changeme|change[_\-]?me|redacted|not[_\-]?real"
    r"|xxx+|todo|abcdef|123456|insert[_\-]?\w*|replace[_\-]?(?:me|this|with|your))",
    re.IGNORECASE,
)

# Words that only mean "placeholder" when they ARE the whole value. Matching these as
# substrings is a silent false-negative machine: `test` lives inside "MyFastestToken",
# `secret` inside "ProdSecretKey9f2x", `bar` inside "barbaraDbPass" — every one of those
# is a real credential that a substring rule throws away without ever reporting it.
WEAK_PLACEHOLDER_RE = re.compile(
    r"^[\W_]*(?:my[_\-]?|the[_\-]?|a[_\-]?)?"
    r"(?:password|passwd|pwd|secret|s3cret|token|apikey|api[_\-]?key|key|credential"
    r"|test|testing|foo|bar|baz|qux|fake|mock|demo|dummy|value|string|somevalue"
    r"|abc|asdf|qwerty|letmein|hunter)"
    r"(?:[_\-]?(?:key|secret|token|password|value|here|123))?"
    r"[\W_]*\d{0,6}[\W_]*$",
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
# Alternation is leftmost-first and finditer consumes non-overlapping spans, so a
# broad rule that starts earlier on the line (`API_KEY = "sk_live_…"`) hides the
# specific one that would classify the same value as critical. A second pass over
# the provider-specific rules alone guarantees they are never shadowed.
_SPECIFIC_RULES = [r for r in SECRET_RULES if r.id != "generic-secret"]
_MASTER_SPECIFIC = re.compile(
    "|".join(f"(?P<{r.group}>{_scoped(r.pattern)})" for r in _SPECIFIC_RULES)
)
_BY_GROUP = {r.group: r for r in SECRET_RULES}


def _rule_for(m) -> "SecretRule | None":
    rule = _BY_GROUP.get(m.lastgroup)
    if rule is None:
        for g, r in _BY_GROUP.items():
            if m.groupdict().get(g):
                return r
    return rule


def scan_secrets(text: str):
    """Yields (rule, match) for every rule that fires, specific rules included even
    when a broader rule matched an overlapping span."""
    seen: set[tuple[str, int, int]] = set()
    for pattern in (_MASTER, _MASTER_SPECIFIC):
        for m in pattern.finditer(text):
            rule = _rule_for(m)
            if not rule:
                continue
            key = (rule.id, m.start(), m.end())
            if key in seen:
                continue
            seen.add(key)
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
    if WEAK_PLACEHOLDER_RE.match(v):
        return True
    if len(set(v)) <= 3:  # "aaaaaaaaaaaa", "xxxxxxxx"
        return True
    return False


# Generated/minified artifacts: one enormous line of mangled identifiers. Entropy-based
# rules fire constantly on the random-looking symbol names, and code rules (innerHTML,
# eval) fire on library internals nobody can act on. Precise, fixed-prefix provider
# rules still run here, because a build-time key baked into a bundle is a real leak.
MINIFIED_NAME_RE = re.compile(
    r"(?i)[.\-](?:min|bundle|chunk|pack|vendor|polyfills?|runtime)\.(?:js|mjs|cjs|css)$"
    r"|\.min\.\w+$|^[a-f0-9]{8,}\.(?:js|css)$")
MINIFIED_MIN_BYTES = 20_000
MINIFIED_LINE_LEN = 1_000


def is_minified(name: str, text: str) -> bool:
    if MINIFIED_NAME_RE.search(name):
        return True
    if len(text) < MINIFIED_MIN_BYTES:
        return False
    lines = text.split("\n", 400)[:400]
    if not lines:
        return False
    longest = max(len(x) for x in lines)
    avg = sum(len(x) for x in lines) / len(lines)
    return longest > MINIFIED_LINE_LEN and avg > 200


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
     r"(?i)(?:prompt|messages|system)\s*[:=]\s*f?[\"'`][^\"'`]{0,200}\$?\{(?:user|req|input|query|body|params|message|msg|text|content|comment|email"
     r"|context\w*|docs?\b|document\w*|retrieved\w*|chunk\w*|history|search_results?|tool_(?:result|output)\w*)\w*",
     "Keep untrusted text — including retrieved/RAG context, which is just as attacker-influenceable as "
     "direct user input — in a separate user-role message with explicit delimiters, never inside the "
     "system prompt, and treat model output as untrusted."),
    ("llm-unbounded-exec", "Model output passed to an executor", "high", "*",
     r"(?i)(?:exec|eval|subprocess\.\w+|os\.system|child_process\.\w+)\s*\([^)]*(?:completion|response|llm|model|choices\[0\]|message\.content)",
     "Never execute model output directly — constrain it to a whitelisted action schema and validate before dispatch."),
    ("llm-tool-args-eval", "Tool/function-call arguments passed to eval/exec", "critical", "*",
     r"(?i)(?:\beval\(|\bexec\(|new\s+Function\()[^)\n]{0,120}(?:tool_call|function_call|\.arguments\b)",
     "The model chose these arguments — treat them exactly like untrusted user input. Parse them into a "
     "typed schema and dispatch through an explicit allowlist of functions, never through eval/exec."),
    ("llm-secret-in-prompt", "Credential-shaped value interpolated into an LLM prompt", "high", "*",
     r"(?i)(?:prompt|system|messages)\s*[:=]\s*f[\"'`][^\"'`]{0,300}\{[^}]{0,60}"
     r"(?:api[_\-]?key|apikey|secret|password|token|credential)[^}]{0,60}\}",
     "Prompts are logged and cached by providers and can be exfiltrated back out via prompt injection — "
     "call the API with the credential separately, never interpolate it into text sent to the model."),
    ("llm-output-unsanitized-render", "LLM output rendered into the DOM without sanitization", "high", "*",
     r"(?i)(?:dangerouslySetInnerHTML\s*=\s*\{\{\s*__html:|\.innerHTML\s*=)\s*[^;\n]{0,80}"
     r"(?:completion|response\.choices|message\.content|llm[_A-Z]?[Oo]utput|ai[_A-Z]?[Rr]esponse|model[_A-Z]?[Oo]utput|chat[Rr]esponse|bot[Rr]eply|assistant[Mm]essage)",
     "Model output can carry injected markup from the prompt/training context (indirect prompt injection) — "
     "sanitize with DOMPurify before rendering, or render as text."),
    ("llm-unbounded-tokens", "LLM call has no visible token limit", "low", "*",
     r"(?i)\.(?:chat\.completions|completions|messages)\.create\(\s*"
     r"(?:(?!max_tokens|maxOutputTokens|max_output_tokens|max_completion_tokens)[\s\S]){0,300}\)",
     "No max_tokens / max_output_tokens found near this call. An unbounded or looping generation is a "
     "real cost/DoS vector — set an explicit ceiling, even a generous one, on every completion call."),

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
    "llm-prompt-injection", "llm-unbounded-exec", "llm-tool-args-eval",
    "llm-secret-in-prompt", "llm-output-unsanitized-render", "llm-unbounded-tokens",
    "firebase-open-rules", "iam-wildcard-principal", "iam-wildcard-action",
    "gcp-allusers", "curl-pipe-shell",
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
