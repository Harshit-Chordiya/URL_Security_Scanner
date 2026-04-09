"""
Scanner: HTTP Methods Security
Checks for dangerous HTTP methods: TRACE, PUT, DELETE.
No additional libraries required.
"""
import requests
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}


def check_http_methods(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    session = requests.Session()
    session.headers.update(HEADERS)

    if progress_callback:
        progress_callback("HTTP Methods: Testing for dangerous methods...")

    # ── 1. OPTIONS — discover advertised methods ───────────────────────────────
    allowed_methods = []
    try:
        resp = session.options(target_url, timeout=8, allow_redirects=False)
        allow_header = resp.headers.get("Allow", "") or resp.headers.get("Public", "")
        if allow_header:
            allowed_methods = [m.strip().upper() for m in allow_header.split(",")]
    except Exception:
        pass

    dangerous = {"TRACE", "PUT", "DELETE", "CONNECT", "PATCH"}
    found_dangerous = dangerous.intersection(set(allowed_methods))
    if found_dangerous:
        findings.append({
            "category": "HTTP Methods",
            "type": "dangerous_methods_advertised",
            "title": f"Dangerous HTTP Methods Advertised: {', '.join(sorted(found_dangerous))}",
            "description": "The OPTIONS response advertises HTTP methods that should not be publicly accessible in production.",
            "severity": "medium",
            "affected_url": target_url,
            "evidence": f"Allow: {', '.join(allowed_methods)}",
            "fix_suggestion": "Restrict allowed methods in your server config to only GET, POST, HEAD. Deny all others at the load balancer or web server level.",
            "owasp": "A05",
            "cwe": "CWE-650",
        })

    # ── 2. TRACE — Cross-Site Tracing (XST) ──────────────────────────────────
    try:
        resp = session.request("TRACE", target_url, timeout=8, allow_redirects=False,
                               headers={**HEADERS, "X-Custom-Header": "bhk-trace-test"})
        if resp.status_code == 200 and "bhk-trace-test" in resp.text:
            findings.append({
                "category": "HTTP Methods",
                "type": "http_trace_enabled",
                "title": "HTTP TRACE Method Enabled (XST Risk)",
                "description": "TRACE echoes back the full request including headers. Attackers can use it to steal cookies via Cross-Site Tracing (XST), bypassing HttpOnly.",
                "severity": "high",
                "affected_url": target_url,
                "evidence": f"TRACE returned 200 and echoed custom header back",
                "fix_suggestion": "Disable TRACE in your server config.\nNginx: `limit_except GET POST HEAD { deny all; }`\nApache: `TraceEnable Off`",
                "owasp": "A05",
                "cwe": "CWE-693",
            })
    except Exception:
        pass

    # ── 3. PUT — unauthorized file upload ────────────────────────────────────
    try:
        resp = session.request("PUT", target_url + "/bhk-put-test.txt",
                               data="test", timeout=8, allow_redirects=False)
        if resp.status_code in (200, 201, 204):
            findings.append({
                "category": "HTTP Methods",
                "type": "http_put_enabled",
                "title": "HTTP PUT Method Enabled",
                "description": "PUT is enabled and accepted a request. An attacker could upload arbitrary files to the server.",
                "severity": "critical",
                "affected_url": target_url,
                "evidence": f"PUT /bhk-put-test.txt returned HTTP {resp.status_code}",
                "fix_suggestion": "Disable PUT in server config unless explicitly required. Restrict to authenticated endpoints only.",
                "owasp": "A01",
                "cwe": "CWE-650",
            })
    except Exception:
        pass

    # ── 4. DELETE — unauthorized resource deletion ────────────────────────────
    try:
        resp = session.request("DELETE", target_url + "/bhk-delete-test",
                               timeout=8, allow_redirects=False)
        if resp.status_code in (200, 202, 204):
            findings.append({
                "category": "HTTP Methods",
                "type": "http_delete_enabled",
                "title": "HTTP DELETE Method Enabled",
                "description": "DELETE is enabled and accepted a request. An attacker could delete resources on the server.",
                "severity": "critical",
                "affected_url": target_url,
                "evidence": f"DELETE returned HTTP {resp.status_code}",
                "fix_suggestion": "Disable DELETE in server config unless required. Restrict to authenticated, authorized endpoints only.",
                "owasp": "A01",
                "cwe": "CWE-650",
            })
    except Exception:
        pass

    if progress_callback:
        progress_callback(f"HTTP Methods: {len(findings)} finding(s)")
    return findings
