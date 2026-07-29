"""Live surface check: TLS, redirects, security headers, cookie flags, exposed paths."""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

from ..core import Finding

NAME = "surface"
UA = {"User-Agent": "dira-scan/1.0 (+security audit)"}

REQUIRED = [
    ("strict-transport-security", "high", "Strict-Transport-Security missing",
     "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` at the edge."),
    ("content-security-policy", "high", "Content-Security-Policy missing",
     "Ship a CSP — start in report-only, then enforce `default-src 'self'` with explicit allowances."),
    ("x-content-type-options", "medium", "X-Content-Type-Options missing",
     "Add `X-Content-Type-Options: nosniff`."),
    ("referrer-policy", "low", "Referrer-Policy missing",
     "Add `Referrer-Policy: strict-origin-when-cross-origin`."),
    ("permissions-policy", "low", "Permissions-Policy missing",
     "Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`."),
    ("x-frame-options", "medium", "No clickjacking protection",
     "Add `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`."),
]

LEAKY = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

PROBE_PATHS = [
    ("/.env", "critical", "Environment file served publicly"),
    ("/.git/config", "critical", "Git directory exposed over HTTP"),
    ("/.aws/credentials", "critical", "AWS credentials exposed over HTTP"),
    ("/server-status", "medium", "Apache server-status exposed"),
    ("/actuator/env", "critical", "Spring Actuator env endpoint exposed"),
    ("/phpinfo.php", "high", "phpinfo() exposed"),
    ("/.well-known/security.txt", "info", "No security.txt published"),
]


def _fetch(url: str, timeout: float, method: str = "GET"):
    req = urllib.request.Request(url, headers=UA, method=method)
    return urllib.request.urlopen(req, timeout=timeout)


def scan(target: str, timeout: float = 12.0, probe: bool = True) -> list[Finding]:
    host = target.replace("https://", "").replace("http://", "").strip("/").split("/")[0]
    base = f"https://{host}"
    out: list[Finding] = []

    out.extend(_tls_check(host, timeout))

    try:
        resp = _fetch(base, timeout)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:
        out.append(Finding(
            id="surface/unreachable", title=f"Could not reach {base}", severity="info",
            scanner=NAME, path=base, evidence=e.__class__.__name__,
            remediation="Check the hostname, or pass the scheme-less domain."))
        return out

    hdrs = {k.lower(): v for k, v in resp.headers.items()}

    for key, sev, title, fix in REQUIRED:
        if key not in hdrs:
            out.append(Finding(id=f"surface/{key}", title=title, severity=sev, scanner=NAME,
                               path=base, evidence="header absent", remediation=fix,
                               reference="https://owasp.org/www-project-secure-headers/"))
        elif key == "strict-transport-security":
            try:
                age = int(hdrs[key].split("max-age=")[1].split(";")[0])
                if age < 15552000:
                    out.append(Finding(
                        id="surface/hsts-short", title="HSTS max-age below 180 days",
                        severity="low", scanner=NAME, path=base, evidence=hdrs[key],
                        remediation="Raise max-age to 31536000 once you are confident in HTTPS coverage."))
            except (IndexError, ValueError):
                pass
        elif key == "content-security-policy" and "unsafe-inline" in hdrs[key]:
            out.append(Finding(
                id="surface/csp-unsafe-inline", title="CSP allows 'unsafe-inline'",
                severity="medium", scanner=NAME, path=base, evidence=hdrs[key][:140],
                remediation="Replace 'unsafe-inline' with per-request nonces or hashes."))

    for leak in LEAKY:
        if leak in hdrs and hdrs[leak].strip():
            out.append(Finding(
                id="surface/version-disclosure", title=f"Server version disclosed via `{leak}`",
                severity="low", scanner=NAME, path=base, evidence=f"{leak}: {hdrs[leak]}",
                remediation=f"Strip the `{leak}` header at the proxy/CDN."))

    if hdrs.get("access-control-allow-origin") == "*":
        out.append(Finding(
            id="surface/cors-wildcard", title="Live response sends Access-Control-Allow-Origin: *",
            severity="medium", scanner=NAME, path=base, evidence="ACAO: *",
            remediation="Restrict to an explicit origin allowlist."))

    for cookie in resp.headers.get_all("set-cookie") or []:
        low = cookie.lower()
        missing = [f for f in ("secure", "httponly") if f not in low]
        if "samesite" not in low:
            missing.append("samesite")
        if missing:
            out.append(Finding(
                id="surface/cookie-flags",
                title=f"Cookie missing {', '.join(missing)}", severity="medium", scanner=NAME,
                path=base, evidence=cookie.split("=")[0][:40],
                remediation="Set Secure; HttpOnly; SameSite=Lax on session cookies.",
                reference="https://cwe.mitre.org/data/definitions/1004.html"))

    try:
        r = _fetch(f"http://{host}", timeout)
        if not r.url.startswith("https://"):
            out.append(Finding(
                id="surface/no-https-redirect", title="HTTP does not redirect to HTTPS",
                severity="high", scanner=NAME, path=f"http://{host}", evidence=r.url,
                remediation="301 all HTTP traffic to HTTPS at the edge."))
    except Exception:
        pass

    if probe:
        out.extend(_probe(base, timeout))
    return out


def _probe(base: str, timeout: float) -> list[Finding]:
    out = []
    for path, sev, title in PROBE_PATHS:
        url = base + path
        try:
            r = _fetch(url, timeout)
            code, body = r.status, r.read(400)
        except urllib.error.HTTPError as e:
            code, body = e.code, b""
        except Exception:
            continue
        found = code == 200 and len(body) > 0
        if path.endswith("security.txt"):
            if not found:
                out.append(Finding(
                    id="surface/no-security-txt", title=title, severity="info", scanner=NAME,
                    path=url, evidence=f"HTTP {code}",
                    remediation="Publish /.well-known/security.txt with a contact address — "
                                "enterprise security reviews look for it."))
            continue
        if found and b"<!doctype html" not in body.lower()[:60]:
            out.append(Finding(
                id="surface/exposed-path", title=title, severity=sev, scanner=NAME,
                path=url, evidence=f"HTTP 200, {len(body)}+ bytes",
                remediation="Block this path at the web server/CDN and rotate anything it exposed."))
    return out


def _tls_check(host: str, timeout: float) -> list[Finding]:
    out = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                version = ss.version() or ""
    except ssl.SSLCertVerificationError as e:
        return [Finding(id="surface/tls-invalid", title="TLS certificate does not validate",
                        severity="critical", scanner=NAME, path=host, evidence=str(e)[:140],
                        remediation="Fix the chain/hostname mismatch or renew the certificate.")]
    except Exception:
        return []

    if version in ("TLSv1", "TLSv1.1"):
        out.append(Finding(id="surface/tls-old", title=f"Negotiated {version}", severity="high",
                           scanner=NAME, path=host, evidence=version,
                           remediation="Disable TLS < 1.2 at the load balancer."))
    if cert and cert.get("notAfter"):
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 21:
                out.append(Finding(
                    id="surface/cert-expiring",
                    title=f"TLS certificate expires in {days} days",
                    severity="high" if days < 8 else "medium", scanner=NAME, path=host,
                    evidence=cert["notAfter"],
                    remediation="Renew now and set up automated renewal + expiry alerting."))
        except ValueError:
            pass
    return out
