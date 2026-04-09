"""
Scanner: HSTS Preload
Checks whether the domain is on the HSTS preload list via hstspreload.org API.
Also validates HSTS header quality for preload eligibility.
No API key required.
"""
import requests
from urllib.parse import urlparse
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}


def _parse_hsts(hsts_value: str) -> dict:
    """Parse Strict-Transport-Security header into components."""
    result = {"max_age": 0, "include_subdomains": False, "preload": False}
    for part in hsts_value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                result["max_age"] = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass
        elif part == "includesubdomains":
            result["include_subdomains"] = True
        elif part == "preload":
            result["preload"] = True
    return result


def check_hsts_preload(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    domain = urlparse(target_url).netloc.split(":")[0].lstrip("www.")

    if not domain:
        return []

    if progress_callback:
        progress_callback(f"HSTS Preload: Checking {domain}...")

    # ── 1. Get current HSTS header ────────────────────────────────────────────
    hsts_value = ""
    try:
        resp = requests.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        hsts_value = resp.headers.get("Strict-Transport-Security", "")
    except Exception:
        pass

    # ── 2. Check preload list status via hstspreload.org ─────────────────────
    preload_status = {}
    try:
        api_resp = requests.get(
            f"https://hstspreload.org/api/v2/status?domain={domain}",
            headers=HEADERS,
            timeout=10,
        )
        if api_resp.status_code == 200:
            preload_status = api_resp.json()
    except Exception:
        pass

    status = preload_status.get("status", "unknown")

    # ── 3. Analyze HSTS header quality for preload eligibility ────────────────
    if hsts_value:
        parsed = _parse_hsts(hsts_value)

        # Check if eligible but not yet on list
        if status not in ("preloaded",):
            issues = []
            if parsed["max_age"] < 31536000:  # 1 year minimum
                issues.append(f"max-age={parsed['max_age']} (must be ≥ 31536000)")
            if not parsed["include_subdomains"]:
                issues.append("missing `includeSubDomains`")
            if not parsed["preload"]:
                issues.append("missing `preload` directive")

            if issues:
                findings.append({
                    "category": "HSTS Preload",
                    "type": "hsts_not_preload_eligible",
                    "title": "HSTS Header Not Eligible for Preload List",
                    "description": (
                        f"The Strict-Transport-Security header exists but is not eligible for browser preload lists. "
                        f"Preloading protects first-time visitors before they ever receive an HSTS response. "
                        f"Issues: {', '.join(issues)}."
                    ),
                    "severity": "low",
                    "affected_url": target_url,
                    "evidence": f"Strict-Transport-Security: {hsts_value}",
                    "fix_suggestion": (
                        "To be preload-eligible, the header must have:\n"
                        "`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`\n"
                        "Then submit at https://hstspreload.org/"
                    ),
                    "owasp": "A02",
                    "cwe": "CWE-319",
                })
            elif status not in ("preloaded",):
                findings.append({
                    "category": "HSTS Preload",
                    "type": "hsts_not_on_preload_list",
                    "title": "HSTS Header Is Preload-Eligible but Domain Not Yet Submitted",
                    "description": (
                        f"{domain} has a valid preload-eligible HSTS header but is not on the "
                        "browser preload list. First-time visitors are still vulnerable to SSL stripping."
                    ),
                    "severity": "info",
                    "affected_url": target_url,
                    "evidence": f"HSTS preload status: {status}. Header: {hsts_value}",
                    "fix_suggestion": (
                        f"Submit {domain} to the HSTS preload list at https://hstspreload.org/ "
                        "to ensure all browsers enforce HTTPS from the very first visit."
                    ),
                    "owasp": "A02",
                    "cwe": "CWE-319",
                })
    else:
        # No HSTS at all — already caught by headers scanner, but add preload context
        findings.append({
            "category": "HSTS Preload",
            "type": "hsts_missing_preload_context",
            "title": "No HSTS Header — Cannot be Added to Preload List",
            "description": (
                "No Strict-Transport-Security header found. The domain cannot be added to HSTS preload lists, "
                "leaving first-time visitors exposed to downgrade attacks."
            ),
            "severity": "info",
            "affected_url": target_url,
            "evidence": "Strict-Transport-Security header absent",
            "fix_suggestion": (
                "First configure HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`. "
                "Then submit at https://hstspreload.org/"
            ),
            "owasp": "A02",
            "cwe": "CWE-319",
        })

    if progress_callback:
        progress_callback(f"HSTS Preload: {len(findings)} finding(s)")
    return findings
