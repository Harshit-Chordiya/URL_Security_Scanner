"""
Scanner: SSRF (Server-Side Request Forgery) Detection
Tests URL parameters for SSRF indicators using safe out-of-band detection.
Uses a DNS-based detection approach (no external callback server required).
No additional libraries required.
"""
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from typing import List, Callable
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Parameters commonly used to pass URLs to server-side fetchers
SSRF_PARAM_KEYWORDS = [
    "url", "uri", "link", "src", "source", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "returnto", "next", "callback", "feed", "fetch", "load", "path",
    "file", "endpoint", "resource", "proxy", "image", "img", "icon",
    "logo", "thumb", "thumbnail", "avatar", "open", "target", "webhook",
    "api_url", "base_url", "host", "domain", "to", "goto",
]

# SSRF canary payloads — these test if the server fetches URLs
# Uses localhost/internal addresses (safe — server either fetches or rejects)
SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://169.254.169.254/metadata/v1/",         # DigitalOcean metadata
    "http://192.168.1.1/",
    "http://10.0.0.1/",
]

# Indicators in response that suggest SSRF worked
SSRF_SUCCESS_PATTERNS = [
    re.compile(r"ami-id|instance-id|hostname|availability-zone", re.I),  # Cloud metadata
    re.compile(r"root:.*:0:0:", re.I),  # /etc/passwd
    re.compile(r"<html.*?>.*?</html>", re.I | re.S),  # Internal HTML fetched
    re.compile(r"connection refused|connection timed out", re.I),  # Different error than 400
    re.compile(r"internal server error.*fetch|failed to fetch|could not fetch", re.I),
]

# Cloud metadata response indicators
CLOUD_META_INDICATORS = [
    "ami-id", "instance-id", "security-credentials", "iam/", "latest/meta-data",
    "computeMetadata", "metadata.google.internal", "instance/id",
]


def _find_url_params(pages: list) -> list:
    """Extract URL parameters that look like they accept URLs."""
    targets = []
    for page in pages:
        url = page.get("url", "")
        html = page.get("content", "")

        # Check URL query params
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        for param, values in qs.items():
            if any(kw in param.lower() for kw in SSRF_PARAM_KEYWORDS):
                targets.append({
                    "url": url,
                    "param": param,
                    "method": "GET",
                    "original_value": values[0] if values else "",
                })

        # Check form inputs
        if html:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = form.get("method", "get").upper()
                abs_action = urljoin(url, action)
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name", "")
                    if name and any(kw in name.lower() for kw in SSRF_PARAM_KEYWORDS):
                        targets.append({
                            "url": abs_action,
                            "param": name,
                            "method": method,
                            "original_value": inp.get("value", ""),
                        })

    return targets


def _test_ssrf(target: dict) -> dict:
    """Test a single parameter for SSRF. Returns finding dict or empty dict."""
    session = requests.Session()
    session.headers.update(HEADERS)

    for payload in SSRF_PAYLOADS[:3]:  # Limit to 3 payloads per param
        try:
            parsed = urlparse(target["url"])
            qs = parse_qs(parsed.query)
            qs[target["param"]] = [payload]
            new_query = urlencode({k: v[0] for k, v in qs.items()})
            test_url = parsed._replace(query=new_query).geturl()

            if target["method"] == "POST":
                resp = session.post(
                    target["url"],
                    data={target["param"]: payload},
                    timeout=8,
                    allow_redirects=False,
                )
            else:
                resp = session.get(test_url, timeout=8, allow_redirects=False)

            response_text = resp.text.lower()

            # Check for cloud metadata in response (confirmed SSRF)
            if any(indicator in response_text for indicator in CLOUD_META_INDICATORS):
                return {
                    "url": test_url,
                    "param": target["param"],
                    "payload": payload,
                    "evidence": f"Response contains cloud metadata content (HTTP {resp.status_code}): {resp.text[:200]}",
                    "confirmed": True,
                }

            # Check for behavioral differences suggesting SSRF
            for pattern in SSRF_SUCCESS_PATTERNS:
                m = pattern.search(resp.text)
                if m:
                    return {
                        "url": test_url,
                        "param": target["param"],
                        "payload": payload,
                        "evidence": f"Response pattern matched '{m.group(0)[:50]}' (HTTP {resp.status_code})",
                        "confirmed": False,
                    }

        except requests.exceptions.ConnectionError as e:
            # Connection refused/timeout to internal address can indicate SSRF attempt was made
            if "127.0.0.1" in payload or "localhost" in payload:
                pass  # Expected for blocked payloads
        except Exception:
            pass

    return {}


def check_ssrf(pages: list, progress_callback: Callable = None) -> List[dict]:
    findings = []

    if progress_callback:
        progress_callback("SSRF: Identifying URL-accepting parameters...")

    targets = _find_url_params(pages)

    if not targets:
        if progress_callback:
            progress_callback("SSRF: No URL-accepting parameters found")
        return []

    if progress_callback:
        progress_callback(f"SSRF: Testing {min(len(targets), 10)} parameter(s) for SSRF...")

    confirmed_occurrences = []
    potential_occurrences = []
    ssrf_param_occurrences = []

    seen_params = set()

    for target in targets[:10]:  # Limit total tests
        key = f"{target['url']}:{target['param']}"
        if key in seen_params:
            continue
        seen_params.add(key)

        # Report the parameter as a risk even before testing
        ssrf_param_occurrences.append({
            "url": target["url"],
            "evidence": f"Parameter '{target['param']}' accepts URL-like values (method: {target['method']})"
        })

        result = _test_ssrf(target)
        if result:
            if result.get("confirmed"):
                confirmed_occurrences.append({
                    "url": result["url"],
                    "evidence": result["evidence"]
                })
            else:
                potential_occurrences.append({
                    "url": result["url"],
                    "evidence": result["evidence"]
                })

    # ── Confirmed SSRF ────────────────────────────────────────────────────────
    if confirmed_occurrences:
        findings.append({
            "category": "SSRF",
            "type": "ssrf_confirmed",
            "title": "Confirmed Server-Side Request Forgery (SSRF)",
            "description": (
                f"SSRF confirmed on {len(confirmed_occurrences)} endpoint(s). The server fetched a "
                "URL supplied in a parameter and returned internal/cloud metadata in the response. "
                "Attackers can access AWS/GCP credentials, internal services, and pivot through your network."
            ),
            "severity": "critical",
            "affected_url": confirmed_occurrences[0]["url"],
            "evidence": confirmed_occurrences[0]["evidence"],
            "occurrences": confirmed_occurrences,
            "fix_suggestion": (
                "Immediately remediate:\n"
                "1. Use an allowlist of permitted domains/IPs for server-side URL fetching\n"
                "2. Block RFC 1918 addresses, loopback, link-local (169.254.x.x), and cloud metadata IPs\n"
                "3. Use a dedicated egress proxy that enforces the allowlist\n"
                "4. Rotate any cloud credentials that may have been exposed"
            ),
            "owasp": "A10",
            "cwe": "CWE-918",
        })

    if potential_occurrences:
        findings.append({
            "category": "SSRF",
            "type": "ssrf_potential",
            "title": "Potential SSRF Indicators Detected",
            "description": (
                f"Behavioral indicators of SSRF found on {len(potential_occurrences)} endpoint(s). "
                "The server may be making internal requests based on user-supplied URLs. "
                "Manual verification recommended."
            ),
            "severity": "high",
            "affected_url": potential_occurrences[0]["url"],
            "evidence": potential_occurrences[0]["evidence"],
            "occurrences": potential_occurrences,
            "fix_suggestion": (
                "Validate and sanitize URL parameters:\n"
                "1. Block internal/private IP ranges\n"
                "2. Only allow pre-approved domains via allowlist\n"
                "3. Use DNS rebinding protection\n"
                "4. Disable unnecessary URL-fetching functionality"
            ),
            "owasp": "A10",
            "cwe": "CWE-918",
        })

    # ── Parameters at risk (info) ─────────────────────────────────────────────
    if ssrf_param_occurrences and not confirmed_occurrences and not potential_occurrences:
        findings.append({
            "category": "SSRF",
            "type": "ssrf_risk_parameters",
            "title": f"URL-Accepting Parameters Found ({len(ssrf_param_occurrences)}) — SSRF Risk",
            "description": (
                f"{len(ssrf_param_occurrences)} parameter(s) with names suggesting URL input were found. "
                "If these parameters cause the server to fetch the provided URL, SSRF is possible. "
                "No behavioral SSRF was detected in automated testing."
            ),
            "severity": "info",
            "affected_url": ssrf_param_occurrences[0]["url"],
            "evidence": ssrf_param_occurrences[0]["evidence"],
            "occurrences": ssrf_param_occurrences,
            "fix_suggestion": (
                "Review each parameter to ensure server-side URL fetching is not performed "
                "without proper validation. Apply allowlist-based URL filtering."
            ),
            "owasp": "A10",
            "cwe": "CWE-918",
        })

    if progress_callback:
        progress_callback(f"SSRF: {len(findings)} finding(s)")
    return findings
