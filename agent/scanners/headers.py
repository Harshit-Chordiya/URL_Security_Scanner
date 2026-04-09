"""
Scanner: HTTP Security Headers
Checks for presence and correct configuration of security-related HTTP headers.
OWASP: A05 Security Misconfiguration
"""
import re
from typing import List

# Matches version numbers in Server/X-Powered-By values (e.g. "nginx/1.14.0", "PHP/8.1.2")
_VERSION_RE = re.compile(r"/\d+\.\d+|v\d+\.\d+|\d+\.\d+\.\d+", re.I)


REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "owasp": "A05",
        "cwe": "CWE-693",
        "description": "Content-Security-Policy header is absent. CSP is a defence-in-depth control — it reduces the impact of XSS by restricting which scripts and resources browsers may execute, but its absence does not directly create a vulnerability.",
        "fix": "Add a strict CSP header: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`",
    },
    "Strict-Transport-Security": {
        "severity": "high",
        "owasp": "A02",
        "cwe": "CWE-319",
        "description": "Missing HSTS header allows downgrade attacks and cookie hijacking over HTTP.",
        "fix": "Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "owasp": "A05",
        "cwe": "CWE-1021",
        "description": "Missing X-Frame-Options exposes the site to Clickjacking attacks.",
        "fix": "Add: `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'`",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "owasp": "A05",
        "cwe": "CWE-430",
        "description": "Missing X-Content-Type-Options allows MIME-sniffing attacks.",
        "fix": "Add: `X-Content-Type-Options: nosniff`",
    },
    "Referrer-Policy": {
        "severity": "low",
        "owasp": "A05",
        "cwe": "CWE-200",
        "description": "Missing Referrer-Policy leaks URL data to third parties.",
        "fix": "Add: `Referrer-Policy: strict-origin-when-cross-origin`",
    },
    "Permissions-Policy": {
        "severity": "info",
        "owasp": "A05",
        "cwe": "CWE-693",
        "description": "Missing Permissions-Policy allows unrestricted access to browser features (camera, mic, geolocation). This is a defence-in-depth header.",
        "fix": "Add: `Permissions-Policy: geolocation=(), microphone=(), camera=()`",
    },
}

DANGEROUS_HEADERS = {
    "Server": {
        "severity": "info",
        "owasp": "A05",
        "cwe": "CWE-200",
        "description": "Server header discloses software version, aiding fingerprinting.",
        "fix": "Configure your web server to suppress or obscure the Server header.",
    },
    "X-Powered-By": {
        "severity": "info",
        "owasp": "A05",
        "cwe": "CWE-200",
        "description": "X-Powered-By reveals backend technology (e.g., PHP, Express), aiding attackers.",
        "fix": "Remove X-Powered-By header. In Express: `app.disable('x-powered-by')`",
    },
    "X-AspNet-Version": {
        "severity": "info",
        "owasp": "A05",
        "cwe": "CWE-200",
        "description": "X-AspNet-Version reveals the ASP.NET version in use.",
        "fix": "Remove by adding `<httpRuntime enableVersionHeader='false'/>` in web.config",
    },
}


def check_security_headers(page: dict) -> List[dict]:
    findings = []
    headers = {k.lower(): v for k, v in page.get("headers", {}).items()}
    url = page["url"]

    # Check for missing required headers
    for header, meta in REQUIRED_HEADERS.items():
        if header.lower() not in headers:
            findings.append({
                "category": "Security Headers",
                "type": f"missing_{header.lower().replace('-', '_')}",
                "title": f"Missing {header} Header",
                "description": meta["description"],
                "severity": meta["severity"],
                "affected_url": url,
                "evidence": f"Header '{header}' not present in response",
                "fix_suggestion": meta["fix"],
                "owasp": meta["owasp"],
                "cwe": meta["cwe"],
            })

    # Check CSP quality if present
    csp = headers.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            findings.append({
                "category": "Security Headers",
                "type": "weak_csp_unsafe_inline",
                "title": "Weak CSP: 'unsafe-inline' Allowed",
                "description": "CSP contains 'unsafe-inline' which defeats XSS protection.",
                "severity": "high",
                "affected_url": url,
                "evidence": f"CSP: {csp[:200]}",
                "fix_suggestion": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                "owasp": "A05",
                "cwe": "CWE-693",
            })
        if "unsafe-eval" in csp:
            findings.append({
                "category": "Security Headers",
                "type": "weak_csp_unsafe_eval",
                "title": "Weak CSP: 'unsafe-eval' Allowed",
                "description": "CSP contains 'unsafe-eval' which allows dynamic code execution.",
                "severity": "medium",
                "affected_url": url,
                "evidence": f"CSP: {csp[:200]}",
                "fix_suggestion": "Remove 'unsafe-eval'. Refactor code to avoid eval().",
                "owasp": "A05",
                "cwe": "CWE-693",
            })

    # Check HSTS quality if present
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        if "max-age" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip())
                if max_age < 31536000:
                    findings.append({
                        "category": "Security Headers",
                        "type": "weak_hsts_max_age",
                        "title": "Weak HSTS max-age (< 1 year)",
                        "description": f"HSTS max-age is only {max_age}s, below the recommended 1 year (31536000s).",
                        "severity": "low",
                        "affected_url": url,
                        "evidence": f"Strict-Transport-Security: {hsts}",
                        "fix_suggestion": "Set max-age to at least 31536000 (1 year).",
                        "owasp": "A02",
                        "cwe": "CWE-319",
                    })
            except (IndexError, ValueError):
                pass

    # Check for information-leaking headers
    for header, meta in DANGEROUS_HEADERS.items():
        if header.lower() in headers:
            value = headers[header.lower()]
            # For Server header: only flag when it discloses a version number.
            # "cloudflare", "nginx" (no version) etc. are not actionable disclosures.
            if header == "Server" and not _VERSION_RE.search(value):
                continue
            findings.append({
                "category": "Information Disclosure",
                "type": f"exposed_{header.lower().replace('-', '_')}",
                "title": f"Information Leakage via {header} Header",
                "description": meta["description"],
                "severity": meta["severity"],
                "affected_url": url,
                "evidence": f"{header}: {value}",
                "fix_suggestion": meta["fix"],
                "owasp": meta["owasp"],
                "cwe": meta["cwe"],
            })

    return findings
