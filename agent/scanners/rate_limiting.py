"""
Scanner: Rate Limiting
Tests whether login and API endpoints implement rate limiting.
No additional libraries required.
"""
import time
import requests
from typing import List, Callable
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Paths that commonly implement rate limiting
LOGIN_PATH_KEYWORDS = ["login", "signin", "sign-in", "auth", "session", "token"]
API_PATH_KEYWORDS = ["api", "graphql", "rest", "v1", "v2", "v3", "search", "query"]

# Number of rapid requests to send
BURST_COUNT = 15
# Threshold: if none of N requests get 429, rate limiting is absent
RATE_LIMIT_CODES = {429, 503, 420}
SLOWDOWN_RATIO = 0.8  # if 80%+ of burst requests succeed fast → no rate limiting


def _find_form_endpoints(pages: list) -> list:
    """Find form action URLs from crawled pages."""
    endpoints = []
    for page in pages:
        url = page.get("url", "")
        html = page.get("content", "")
        if not html:
            continue
        soup = BeautifulSoup(html, "lxml")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            if action:
                abs_url = urljoin(url, action)
            else:
                abs_url = url
            path = urlparse(abs_url).path.lower()
            if any(kw in path for kw in LOGIN_PATH_KEYWORDS):
                endpoints.append({"url": abs_url, "method": method, "type": "login"})
    return endpoints


def _burst_test(url: str, method: str = "POST", payload: dict = None) -> dict:
    """Send burst requests and check for rate limiting response."""
    session = requests.Session()
    session.headers.update(HEADERS)
    rate_limited = False
    success_count = 0
    status_codes = []

    for _ in range(BURST_COUNT):
        try:
            if method == "POST":
                resp = session.post(url, data=payload or {}, timeout=5, allow_redirects=False)
            else:
                resp = session.get(url, timeout=5, allow_redirects=False)
            status_codes.append(resp.status_code)
            if resp.status_code in RATE_LIMIT_CODES:
                rate_limited = True
                break
            # Only count as "accessible" if the server returns 2xx.
            # 3xx = redirect (likely to login/auth page — endpoint doesn't serve content).
            # 4xx = blocked/forbidden/not found — endpoint doesn't exist or rejects all traffic.
            # Neither indicates a missing rate limit.
            if 200 <= resp.status_code < 300:
                success_count += 1
            elif resp.status_code in (401, 403, 404, 405, 410):
                # Endpoint is blocked or nonexistent — mark rate-limited to skip this URL
                rate_limited = True
                break
        except Exception:
            break

    return {
        "rate_limited": rate_limited,
        "success_count": success_count,
        "status_codes": status_codes,
    }


def check_rate_limiting(target_url: str, pages: list, progress_callback: Callable = None) -> List[dict]:
    findings = []

    if progress_callback:
        progress_callback("Rate Limiting: Testing login and API endpoints...")

    # ── 1. Test login endpoints from crawled forms ────────────────────────────
    login_endpoints = _find_form_endpoints(pages)

    # Also try common login paths directly
    base = target_url.rstrip("/")
    for kw in ["login", "signin", "api/login", "api/auth/login", "api/token"]:
        login_endpoints.append({"url": f"{base}/{kw}", "method": "POST", "type": "login"})

    no_ratelimit_login = []
    tested_urls = set()

    for ep in login_endpoints[:5]:  # Limit to avoid too many requests
        url = ep["url"]
        if url in tested_urls:
            continue
        tested_urls.add(url)

        try:
            # Quick check if endpoint exists
            probe = requests.head(url, headers=HEADERS, timeout=5, allow_redirects=False)
            if probe.status_code in (404, 410):
                continue
        except Exception:
            continue

        result = _burst_test(
            url,
            method=ep["method"],
            payload={"username": "test@test.com", "password": "wrongpassword"}
        )

        if not result["rate_limited"] and result["success_count"] >= int(BURST_COUNT * SLOWDOWN_RATIO):
            no_ratelimit_login.append({
                "url": url,
                "evidence": (
                    f"{result['success_count']}/{BURST_COUNT} rapid requests succeeded without rate limiting. "
                    f"Status codes: {list(set(result['status_codes']))}"
                )
            })

    # ── 2. Test API endpoints ─────────────────────────────────────────────────
    api_paths = []
    for page in pages:
        path = urlparse(page.get("url", "")).path.lower()
        if any(kw in path for kw in API_PATH_KEYWORDS):
            api_paths.append(page["url"])

    # Also probe common API paths
    for kw in ["api", "api/v1", "api/v2", "graphql", "search"]:
        api_paths.append(f"{base}/{kw}")

    no_ratelimit_api = []

    for url in list(dict.fromkeys(api_paths))[:3]:  # Deduplicate, limit to 3
        if url in tested_urls:
            continue
        tested_urls.add(url)

        try:
            probe = requests.head(url, headers=HEADERS, timeout=5, allow_redirects=False)
            if probe.status_code in (404, 410):
                continue
        except Exception:
            continue

        result = _burst_test(url, method="GET")

        if not result["rate_limited"] and result["success_count"] >= int(BURST_COUNT * SLOWDOWN_RATIO):
            no_ratelimit_api.append({
                "url": url,
                "evidence": (
                    f"{result['success_count']}/{BURST_COUNT} rapid requests succeeded without 429 response. "
                    f"Status codes: {list(set(result['status_codes']))}"
                )
            })

    if no_ratelimit_login:
        findings.append({
            "category": "Rate Limiting",
            "type": "rate_limiting_missing_login",
            "title": "No Rate Limiting on Login Endpoint(s)",
            "description": (
                f"{len(no_ratelimit_login)} login endpoint(s) accepted {BURST_COUNT} rapid consecutive "
                "requests without throttling. Attackers can brute-force credentials without restriction."
            ),
            "severity": "high",
            "affected_url": no_ratelimit_login[0]["url"],
            "evidence": no_ratelimit_login[0]["evidence"],
            "occurrences": no_ratelimit_login,
            "fix_suggestion": (
                "Implement rate limiting on authentication endpoints:\n"
                "- Limit to 5-10 attempts per IP per minute\n"
                "- Add exponential backoff after failures\n"
                "- Implement account lockout after N failures\n"
                "- Add CAPTCHA after repeated failures\n"
                "- Use fail2ban or WAF rules for IP-level throttling"
            ),
            "owasp": "A07",
            "cwe": "CWE-307",
        })

    if no_ratelimit_api:
        findings.append({
            "category": "Rate Limiting",
            "type": "rate_limiting_missing_api",
            "title": "No Rate Limiting on API Endpoint(s)",
            "description": (
                f"{len(no_ratelimit_api)} API endpoint(s) have no rate limiting. "
                "Attackers can scrape data, perform enumeration, or launch DoS attacks without restriction."
            ),
            "severity": "medium",
            "affected_url": no_ratelimit_api[0]["url"],
            "evidence": no_ratelimit_api[0]["evidence"],
            "occurrences": no_ratelimit_api,
            "fix_suggestion": (
                "Implement API rate limiting:\n"
                "- Use a per-IP and per-user token bucket or sliding window\n"
                "- Return HTTP 429 with `Retry-After` header when limit exceeded\n"
                "- Frameworks: express-rate-limit (Node), django-ratelimit (Django), slowapi (FastAPI)"
            ),
            "owasp": "A04",
            "cwe": "CWE-770",
        })

    if progress_callback:
        progress_callback(f"Rate Limiting: {len(findings)} finding(s)")
    return findings
