"""
Scanner: CORS Misconfiguration
Tests for overly permissive Access-Control-Allow-Origin policies.
OWASP: A05 Security Misconfiguration
"""
import requests
from typing import List, Callable

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"
}

TEST_ORIGINS = [
    "https://evil-cors-test.com",
    "null",
]


def check_cors(target_url: str, pages: List[dict], progress_callback: Callable = None) -> List[dict]:
    findings = []
    session = requests.Session()
    session.headers.update(HEADERS)

    # Test on up to 5 unique URLs
    urls_to_test = list({p["url"] for p in pages})[:5]

    for url in urls_to_test:
        for origin in TEST_ORIGINS:
            try:
                resp = session.options(
                    url,
                    headers={**HEADERS, "Origin": origin, "Access-Control-Request-Method": "GET"},
                    timeout=8,
                    allow_redirects=False,
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if acao == "*":
                    findings.append({
                        "category": "CORS Misconfiguration",
                        "type": "cors_wildcard",
                        "title": "CORS Wildcard Origin Allowed (Access-Control-Allow-Origin: *)",
                        "description": "The server allows any origin. This is dangerous when combined with authenticated endpoints.",
                        "severity": "medium",
                        "affected_url": url,
                        "evidence": f"Access-Control-Allow-Origin: {acao}",
                        "fix_suggestion": "Replace '*' with a specific trusted origin whitelist. Never combine '*' with credentials.",
                        "owasp": "A05",
                        "cwe": "CWE-942",
                    })
                    break

                if acao == origin and origin != "null":
                    severity = "critical" if acac == "true" else "high"
                    findings.append({
                        "category": "CORS Misconfiguration",
                        "type": "cors_arbitrary_origin_reflected",
                        "title": "CORS Reflects Arbitrary Origin",
                        "description": f"The server reflects any provided Origin header ('{origin}') back in ACAO. This allows cross-origin requests from attacker domains.",
                        "severity": severity,
                        "affected_url": url,
                        "evidence": f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac}",
                        "fix_suggestion": "Maintain a strict server-side whitelist of allowed origins. Validate the Origin header against this list before reflecting it.",
                        "owasp": "A05",
                        "cwe": "CWE-942",
                    })
                    break

                if acao == "null":
                    findings.append({
                        "category": "CORS Misconfiguration",
                        "type": "cors_null_origin",
                        "title": "CORS Allows 'null' Origin",
                        "description": "Allowing 'null' origin permits requests from sandboxed iframes or local files, which attackers can exploit.",
                        "severity": "high",
                        "affected_url": url,
                        "evidence": f"Access-Control-Allow-Origin: null",
                        "fix_suggestion": "Remove 'null' from allowed origins. Only whitelist specific HTTPS domains.",
                        "owasp": "A05",
                        "cwe": "CWE-942",
                    })
                    break

            except Exception:
                pass

    if progress_callback:
        progress_callback(f"CORS check complete — {len(findings)} issue(s) found")

    # Deduplicate by type
    seen = set()
    unique = []
    for f in findings:
        key = f["type"]
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique
