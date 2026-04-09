"""
Scanner: Cookie Security
Analyzes Set-Cookie headers for missing security attributes.
OWASP: A02, A05 — Session Management
"""
from typing import List

# Cookie names that indicate session/auth tokens — missing HttpOnly is HIGH risk
_SESSION_KEYWORDS = {
    "session", "sess", "auth", "token", "jwt", "access", "refresh",
    "sid", "uid", "userid", "user_id", "login", "credential", "secret",
    "csrftoken", "xsrf", "identity", "remember",
}

def _is_session_cookie(name: str) -> bool:
    n = name.lower()
    return any(kw in n for kw in _SESSION_KEYWORDS)


def _parse_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie string into a dict of attributes."""
    parts = [p.strip() for p in raw.split(";")]
    cookie = {"name": "", "value": "", "httponly": False, "secure": False, "samesite": None, "raw": raw}
    if parts:
        name_val = parts[0].split("=", 1)
        cookie["name"] = name_val[0].strip()
        cookie["value"] = name_val[1].strip() if len(name_val) > 1 else ""
    for part in parts[1:]:
        lower = part.lower()
        if lower == "httponly":
            cookie["httponly"] = True
        elif lower == "secure":
            cookie["secure"] = True
        elif lower.startswith("samesite="):
            cookie["samesite"] = part.split("=", 1)[1].strip().lower()
    return cookie


def check_cookies(page: dict) -> List[dict]:
    findings = []
    raw_cookies = page.get("raw_cookies", [])
    url = page["url"]

    for raw in raw_cookies:
        c = _parse_cookie(raw)
        name = c["name"] or "<unnamed>"

        if not c["httponly"]:
            # Session/auth cookies without HttpOnly are HIGH — JS can steal them via XSS.
            # Preference/tracking cookies (e.g. CountryCode, theme, lang) are MEDIUM —
            # JavaScript access is bad practice but not a direct session-theft vector.
            sev = "high" if _is_session_cookie(name) else "medium"
            desc = (
                "Without HttpOnly, JavaScript can read this cookie — enabling session theft via XSS."
                if sev == "high"
                else f"Without HttpOnly, JavaScript can read this cookie. '{name}' appears to be a preference/tracking cookie rather than a session token, but it is still best practice to set HttpOnly on all cookies."
            )
            findings.append({
                "category": "Cookie Security",
                "type": "cookie_missing_httponly",
                "title": f"Cookie '{name}' Missing HttpOnly Flag",
                "description": desc,
                "severity": sev,
                "affected_url": url,
                "evidence": f"Set-Cookie: {raw[:120]}",
                "fix_suggestion": f"Add HttpOnly to the cookie: `Set-Cookie: {name}=...; HttpOnly; ...`",
                "owasp": "A07",
                "cwe": "CWE-1004",
            })

        if not c["secure"]:
            findings.append({
                "category": "Cookie Security",
                "type": "cookie_missing_secure",
                "title": f"Cookie '{name}' Missing Secure Flag",
                "description": "Without Secure flag, the cookie is transmitted over plain HTTP, exposing it to interception.",
                "severity": "high",
                "affected_url": url,
                "evidence": f"Set-Cookie: {raw[:120]}",
                "fix_suggestion": f"Add Secure to the cookie: `Set-Cookie: {name}=...; Secure; ...`",
                "owasp": "A02",
                "cwe": "CWE-614",
            })

        if not c["samesite"]:
            findings.append({
                "category": "Cookie Security",
                "type": "cookie_missing_samesite",
                "title": f"Cookie '{name}' Missing SameSite Attribute",
                "description": "Without SameSite, the cookie is sent with cross-site requests, enabling CSRF attacks.",
                "severity": "medium",
                "affected_url": url,
                "evidence": f"Set-Cookie: {raw[:120]}",
                "fix_suggestion": f"Add SameSite: `Set-Cookie: {name}=...; SameSite=Strict` or `SameSite=Lax`",
                "owasp": "A01",
                "cwe": "CWE-352",
            })
        elif c["samesite"] == "none" and not c["secure"]:
            findings.append({
                "category": "Cookie Security",
                "type": "cookie_samesite_none_without_secure",
                "title": f"Cookie '{name}' Has SameSite=None Without Secure",
                "description": "SameSite=None requires Secure flag to be valid. Without it, the combination is insecure.",
                "severity": "high",
                "affected_url": url,
                "evidence": f"Set-Cookie: {raw[:120]}",
                "fix_suggestion": "Add the Secure flag when using SameSite=None.",
                "owasp": "A02",
                "cwe": "CWE-614",
            })

    return findings
