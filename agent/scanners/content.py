"""
Scanner: Content Analysis
Checks HTML/JS for: sensitive data exposure, outdated JS libraries,
CSRF missing tokens, insecure form fields, hardcoded secrets, meta tags.
OWASP: A03, A06, A08
"""
import re
from bs4 import BeautifulSoup
from typing import List


# Known vulnerable JS library patterns {lib_name: (version_regex, min_safe_version)}
JS_LIBRARIES = {
    "jquery": (r"jquery[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "3.7.0"),
    "angular": (r"angular[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "17.0.0"),
    "bootstrap": (r"bootstrap[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "5.3.0"),
    "lodash": (r"lodash[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "4.17.21"),
    "moment": (r"moment[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "2.29.4"),
    "react": (r"react[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "18.0.0"),
    "vue": (r"vue[.\-](\d+\.\d+\.?\d*)(\.min)?\.js", "3.3.0"),
}

# Regex patterns for sensitive data in HTML/JS source
SENSITIVE_PATTERNS = [
    # Must be assigned as a string literal (in quotes) — not a JS variable reference
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "API Key Exposure"),
    (r'(?i)(secret[_-]?key|secret)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Secret Key Exposure"),
    # Password hardcoded as a literal string value (not a variable or placeholder)
    (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\'${}]{6,})["\']', "Hardcoded Password"),
    # AWS keys — very specific high-entropy formats
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)(aws_secret_access_key)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key"),
    # Google API key — very specific format
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
    # GitHub PAT — very specific format
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    # Bearer token: real JWTs are 100+ chars. Variable names and short strings are not tokens.
    # This catches `Authorization: Bearer eyJhbGci...` hardcoded in source.
    (r'(?i)bearer\s+([A-Za-z0-9\-._~+/]{80,})', "Bearer Token in Source"),
    # Email: only flagged if NOT on a public contact/legal/about page (handled below)
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "Email Address Exposed"),
    # Database connection strings with credentials embedded
    (r'(?i)(mongodb|mysql|postgresql|redis):\/\/[^:]+:[^@]+@[^\s"\'<>]+', "Database Connection String"),
    (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', "Private Key in Source"),
]

SENSITIVE_INPUT_TYPES = {"password", "credit-card", "card", "ssn", "cvv", "pin"}


def _version_tuple(v: str):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


def check_content(page: dict) -> List[dict]:
    findings = []
    html = page.get("content", "")
    url = page["url"]

    if not html or "text/html" not in page.get("content_type", ""):
        return findings

    soup = BeautifulSoup(html, "lxml")

    # --- 1. Outdated JS Libraries ---
    script_tags = soup.find_all("script", src=True)
    for tag in script_tags:
        src = tag.get("src", "")
        for lib, (pattern, min_ver) in JS_LIBRARIES.items():
            match = re.search(pattern, src, re.IGNORECASE)
            if match:
                found_ver = match.group(1)
                if _version_tuple(found_ver) < _version_tuple(min_ver):
                    findings.append({
                        "category": "Vulnerable Components",
                        "type": f"outdated_{lib}",
                        "title": f"Outdated {lib.title()} Library (v{found_ver})",
                        "description": f"{lib.title()} v{found_ver} has known security vulnerabilities. Minimum safe version: {min_ver}.",
                        "severity": "high",
                        "affected_url": url,
                        "evidence": f"Script src: {src}",
                        "fix_suggestion": f"Upgrade {lib.title()} to v{min_ver} or later.",
                        "owasp": "A06",
                        "cwe": "CWE-1035",
                    })

    # Pages where contact emails are intentional — skip email check entirely
    PUBLIC_CONTACT_PATHS = ("/contact", "/about", "/terms", "/privacy", "/legal",
                            "/help", "/support", "/faq", "/imprint")
    is_contact_page = any(p in url.lower() for p in PUBLIC_CONTACT_PATHS)

    # --- 2. Sensitive Data in Source ---
    for pattern, label in SENSITIVE_PATTERNS:
        # Skip email check on public contact/legal pages — intentional exposure
        if label == "Email Address Exposed" and is_contact_page:
            continue

        matches = re.findall(pattern, html)
        if not matches:
            continue

        evidence = str(matches[0])[:100]

        is_secret = any(k in label.lower() for k in ("key", "token", "password", "secret", "aws", "private"))
        severity = "critical" if is_secret else ("low" if label == "Email Address Exposed" else "medium")

        fix = (
            "Remove credentials from client-side code. Store secrets server-side via environment variables."
            if is_secret else
            "Use a contact form or encode the email address to prevent automated harvesting."
            if label == "Email Address Exposed" else
            "Remove sensitive data from client-side source."
        )

        findings.append({
            "category": "Sensitive Data Exposure",
            "type": f"exposed_{label.lower().replace(' ', '_')}",
            "title": f"{label} Found in Page Source",
            "description": f"Sensitive data ({label}) was detected in the HTML/JS source of the page.",
            "severity": severity,
            "affected_url": url,
            "evidence": f"Pattern match: {evidence}",
            "fix_suggestion": fix,
            "owasp": "A02",
            "cwe": "CWE-312",
        })

    # --- 3. CSRF Token Check on Forms ---
    # Only flag forms that:
    #  a) Use POST
    #  b) Contain sensitive fields (password, email+submit = login/register)
    #  c) Have no hidden inputs (hidden inputs are the most common CSRF token carrier)
    # Modern sites use SameSite=Strict/Lax cookies or custom headers — we can't
    # detect those from HTML alone, so we require at least one hidden input.
    forms = soup.find_all("form")
    page_cookies = page.get("raw_cookies", [])
    has_samesite_protection = any(
        "samesite=strict" in c.lower() or "samesite=lax" in c.lower()
        for c in page_cookies
    )

    for form in forms:
        method = form.get("method", "get").lower()
        if method != "post":
            continue

        inputs = form.find_all("input")
        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = [i.get("name", "").lower() for i in inputs]

        # Only flag forms that appear to handle authentication or sensitive data
        is_sensitive_form = (
            "password" in input_types
            or any(n in ("email", "username", "user", "login", "phone") for n in input_names)
        )
        if not is_sensitive_form:
            continue

        # Check for any CSRF protection signal in the form
        has_csrf = any(
            i.get("name", "").lower() in (
                "csrf_token", "csrftoken", "_token", "authenticity_token",
                "__requestverificationtoken", "csrf", "_csrf", "xsrf_token"
            )
            or i.get("type", "").lower() == "hidden"
            for i in inputs
        )

        # If the site uses SameSite=Lax or Strict cookies globally, CSRF risk is reduced
        if has_csrf or has_samesite_protection:
            continue

        action = form.get("action", url)
        findings.append({
            "category": "CSRF",
            "type": "missing_csrf_token",
            "title": "POST Form Missing CSRF Token",
            "description": "A sensitive POST form (login/register) has no visible CSRF token or hidden input, and the site does not appear to use SameSite cookie protection.",
            "severity": "high",
            "affected_url": url,
            "evidence": f"Form action: {action} — no hidden inputs or known CSRF field names found",
            "fix_suggestion": "Add a server-generated CSRF token to all state-changing forms and validate it server-side.",
            "owasp": "A01",
            "cwe": "CWE-352",
        })

    # --- 4. Autocomplete on Sensitive Fields ---
    inputs = soup.find_all("input")
    for inp in inputs:
        input_type = inp.get("type", "text").lower()
        input_name = inp.get("name", "").lower()
        autocomplete = inp.get("autocomplete", "").lower()

        if input_type == "password" and autocomplete not in ("off", "new-password", "current-password"):
            findings.append({
                "category": "Insecure Form",
                "type": "autocomplete_on_password",
                "title": "Autocomplete Enabled on Password Field",
                "description": "Browser autocomplete on password fields can expose credentials on shared devices.",
                "severity": "low",
                "affected_url": url,
                "evidence": f"Input name: {inp.get('name', 'unknown')}",
                "fix_suggestion": "Add `autocomplete='current-password'` or `autocomplete='off'` to password fields.",
                "owasp": "A07",
                "cwe": "CWE-522",
            })

    # --- 5. Mixed Content Check ---
    if page.get("final_url", "").startswith("https://"):
        mixed = re.findall(r'src=["\']http://[^"\']+["\']', html)
        if mixed:
            findings.append({
                "category": "SSL/TLS",
                "type": "mixed_content",
                "title": "Mixed Content Detected (HTTP Resources on HTTPS Page)",
                "description": f"Found {len(mixed)} resource(s) loaded over HTTP on an HTTPS page. Allows interception.",
                "severity": "medium",
                "affected_url": url,
                "evidence": "; ".join(mixed[:3]),
                "fix_suggestion": "Change all resource URLs to HTTPS or protocol-relative (//example.com/...).",
                "owasp": "A02",
                "cwe": "CWE-319",
            })

    # --- 6. Inline JavaScript with Dangerous Patterns ---
    # Only flag document.write/eval when user-controlled input is plausibly flowing into it.
    # Skip third-party loader snippets (Google Analytics, GTM, ads) which legitimately use these.
    THIRD_PARTY_INDICATORS = [
        "google-analytics", "googletagmanager", "gtag", "fbq", "adsbygoogle",
        "hotjar", "intercom", "mixpanel", "segment", "amplitude", "clarity",
        "doubleclick", "googlesyndication", "chartbeat", "quantcast",
    ]

    scripts = soup.find_all("script", src=False)
    for script in scripts:
        code = script.string or ""
        if not code.strip():
            continue

        # Skip scripts that are clearly third-party analytics/ad loaders
        code_lower = code.lower()
        if any(ind in code_lower for ind in THIRD_PARTY_INDICATORS):
            continue

        if re.search(r'\bdocument\.write\s*\(', code):
            # Only flag if document.write receives something that could carry user input
            # (URL params, location.href, etc.) — not static string writes
            if re.search(r'document\.write\s*\(\s*["\']', code) and not re.search(
                r'document\.write\s*\(.*(?:location|search|hash|param|query|input|value)', code
            ):
                # Purely static write — low risk, skip
                continue
            findings.append({
                "category": "XSS Risk",
                "type": "document_write_usage",
                "title": "Use of document.write() Detected in Inline Script",
                "description": "document.write() can be exploited for DOM-based XSS if any user-controlled input flows into it.",
                "severity": "low",
                "affected_url": url,
                "evidence": "document.write() found in inline script (non-analytics context)",
                "fix_suggestion": "Replace document.write() with safer DOM manipulation (createElement, textContent). Ensure no user input flows into it.",
                "owasp": "A03",
                "cwe": "CWE-79",
            })
            break

        if re.search(r'\beval\s*\(', code):
            # Skip eval() used only on JSON.parse-equivalent static data
            if re.search(r'eval\s*\(\s*["\']', code):
                continue
            findings.append({
                "category": "XSS Risk",
                "type": "eval_usage",
                "title": "Use of eval() Detected in JavaScript",
                "description": "eval() executes arbitrary code and is a frequent XSS target if user-controlled data reaches it.",
                "severity": "medium",
                "affected_url": url,
                "evidence": "eval() found in inline script (non-static argument)",
                "fix_suggestion": "Remove eval(). Use JSON.parse() for JSON, or restructure logic to avoid dynamic code execution.",
                "owasp": "A03",
                "cwe": "CWE-95",
            })
            break

    return findings
