"""
Scanner: Active Probes
Non-destructive active checks: reflected XSS probes, common sensitive paths,
open redirects, SQL error detection.
OWASP: A01, A03
"""
import requests
import re
import time
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import List, Callable

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"
}

# Genuinely dangerous paths — these should NEVER be publicly accessible
# Excludes: robots.txt, sitemap.xml, security.txt — those are public by design
SENSITIVE_PATHS = [
    # Secrets / config
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/config.php", "/wp-config.php", "/configuration.php",
    "/.htaccess", "/web.config",
    "/.DS_Store",
    # Backups / dumps
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    # Admin panels
    "/admin", "/admin/", "/administrator",
    "/wp-admin", "/wp-login.php", "/phpmyadmin",
    # Debug / monitoring (should never be public in prod)
    "/debug", "/console",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/beans",
    "/server-status", "/server-info",
    # Exposed API / docs
    "/api/v1/users", "/api/users", "/api/admin",
    "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql",
]

# Paths that are only a finding if they contain dangerous content
CONDITIONAL_PATHS = {
    "/crossdomain.xml": "allow-access-from domain",
    "/clientaccesspolicy.xml": "<domain uri=",
}

# XSS probe — clearly benign, easily detectable if reflected
XSS_PROBE = "<bhk-xss-test>"
# SQLi probe
SQLI_PROBE = "'"
SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"pg_query\(\)",
    r"sqlite3\.operationalerror",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"syntax error.*sql",
    r"invalid query",
]


def _probe_url(url: str, params: dict, session: requests.Session) -> requests.Response:
    try:
        return session.get(url, params=params, timeout=8, allow_redirects=True)
    except Exception:
        return None


def check_active(target_url: str, pages: List[dict], progress_callback: Callable = None) -> List[dict]:
    findings = []
    session = requests.Session()
    session.headers.update(HEADERS)
    parsed_base = urlparse(target_url)
    base = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # --- 1. Sensitive Path Probe ---
    if progress_callback:
        progress_callback("Active: Probing sensitive paths...")

    CRITICAL_PATHS = {"/.env", "/.env.local", "/.env.production",
                      "/.git/config", "/.git/HEAD",
                      "/wp-config.php", "/config.php", "/configuration.php"}

    for path in SENSITIVE_PATHS:
        probe_url = urljoin(base, path)
        try:
            resp = session.get(probe_url, timeout=6, allow_redirects=False)
            if resp.status_code == 200:
                content_len = len(resp.content)
                if content_len == 0:
                    continue
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                title = title_match.group(1) if title_match else ""
                # Skip generic 404-in-disguise pages
                if "404" in title or "not found" in title.lower() or "error" in title.lower():
                    continue
                severity = "critical" if path in CRITICAL_PATHS else "high"
                findings.append({
                    "category": "Information Disclosure",
                    "type": "exposed_sensitive_path",
                    "title": f"Sensitive Path Exposed: {path}",
                    "description": f"The path '{path}' is publicly accessible and should not be reachable in production.",
                    "severity": severity,
                    "affected_url": probe_url,
                    "evidence": f"HTTP 200, Content-Length: {content_len}",
                    "fix_suggestion": (
                        f"Block access to '{path}' at the server/CDN level. "
                        f"For .env and .git, add explicit deny rules and ensure they are never deployed to a public web root."
                    ),
                    "owasp": "A01",
                    "cwe": "CWE-538",
                })
        except Exception:
            pass
        time.sleep(0.3)

    # --- 1b. Conditional paths (only flag if content is dangerous) ---
    for path, danger_string in CONDITIONAL_PATHS.items():
        probe_url = urljoin(base, path)
        try:
            resp = session.get(probe_url, timeout=6, allow_redirects=False)
            if resp.status_code == 200 and danger_string.lower() in resp.text.lower():
                findings.append({
                    "category": "Security Misconfiguration",
                    "type": f"dangerous_{path.strip('/').replace('.','_')}",
                    "title": f"Permissive Cross-Domain Policy: {path}",
                    "description": f"'{path}' exists and contains a permissive cross-domain access rule.",
                    "severity": "high",
                    "affected_url": probe_url,
                    "evidence": f"Contains: '{danger_string}'",
                    "fix_suggestion": "Restrict cross-domain access to only trusted domains. Never use wildcard (*) in crossdomain.xml.",
                    "owasp": "A05",
                    "cwe": "CWE-942",
                })
        except Exception:
            pass
        time.sleep(0.3)

    # --- 2. Reflected XSS Probe on URL Parameters ---
    if progress_callback:
        progress_callback("Active: Testing for reflected XSS in URL parameters...")

    xss_tested = set()
    for page in pages[:15]:  # Limit to first 15 pages
        url = page["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            continue
        for param in qs:
            key = f"{parsed.path}:{param}"
            if key in xss_tested:
                continue
            xss_tested.add(key)
            probe_params = {k: (XSS_PROBE if k == param else v[0]) for k, v in qs.items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = _probe_url(base_url, probe_params, session)
            if resp and XSS_PROBE in resp.text:
                findings.append({
                    "category": "XSS",
                    "type": "reflected_xss",
                    "title": f"Reflected XSS in Parameter '{param}'",
                    "description": f"The value of URL parameter '{param}' is reflected unescaped in the HTML response.",
                    "severity": "critical",
                    "affected_url": url,
                    "evidence": f"Probe '{XSS_PROBE}' reflected in response for param '{param}'",
                    "fix_suggestion": "Encode all user-controlled output using HTML entity encoding. Use a templating engine with auto-escaping. Implement a strict CSP.",
                    "owasp": "A03",
                    "cwe": "CWE-79",
                })
            time.sleep(0.3)

    # --- 3. SQL Injection Error Detection ---
    if progress_callback:
        progress_callback("Active: Testing for SQL injection errors...")

    sqli_tested = set()
    for page in pages[:15]:
        url = page["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            continue
        for param in qs:
            key = f"sqli:{parsed.path}:{param}"
            if key in sqli_tested:
                continue
            sqli_tested.add(key)
            probe_params = {k: (v[0] + SQLI_PROBE if k == param else v[0]) for k, v in qs.items()}
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            resp = _probe_url(base_url, probe_params, session)
            if resp:
                body_lower = resp.text.lower()
                for err_pattern in SQLI_ERROR_PATTERNS:
                    if re.search(err_pattern, body_lower):
                        findings.append({
                            "category": "SQL Injection",
                            "type": "sqli_error_based",
                            "title": f"Possible SQL Injection in Parameter '{param}'",
                            "description": f"A SQL error message was detected in the response when a single quote was injected into '{param}'.",
                            "severity": "critical",
                            "affected_url": url,
                            "evidence": f"SQL error pattern detected: '{err_pattern}'",
                            "fix_suggestion": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Use an ORM.",
                            "owasp": "A03",
                            "cwe": "CWE-89",
                        })
                        break
            time.sleep(0.3)

    # --- 4. Open Redirect Check ---
    if progress_callback:
        progress_callback("Active: Checking for open redirects...")

    redirect_params = ["redirect", "url", "next", "return", "returnUrl", "continue", "goto", "dest", "destination"]
    for page in pages[:10]:
        url = page["url"]
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param in qs:
            if param.lower() in [r.lower() for r in redirect_params]:
                probe_params = dict(qs)
                probe_params[param] = ["https://evil-redirect-test.com"]
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                try:
                    resp = session.get(base_url, params=probe_params, timeout=6, allow_redirects=False)
                    location = resp.headers.get("Location", "")
                    if "evil-redirect-test.com" in location:
                        findings.append({
                            "category": "Open Redirect",
                            "type": "open_redirect",
                            "title": f"Open Redirect via Parameter '{param}'",
                            "description": f"The parameter '{param}' can redirect users to arbitrary external URLs, enabling phishing attacks.",
                            "severity": "high",
                            "affected_url": url,
                            "evidence": f"Redirect to: {location}",
                            "fix_suggestion": "Validate redirect URLs against an allowlist of trusted domains. Reject or sanitize any URL not on the list.",
                            "owasp": "A01",
                            "cwe": "CWE-601",
                        })
                except Exception:
                    pass
                time.sleep(0.3)

    return findings
