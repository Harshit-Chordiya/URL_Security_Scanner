"""
Scanner: Cache Control
Checks for missing or insecure cache headers on pages that may carry sensitive data.
No additional libraries required.
"""
import requests
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

SENSITIVE_INDICATORS = [
    "account", "profile", "dashboard", "admin", "login", "checkout",
    "cart", "order", "payment", "invoice", "password", "settings",
    "api", "user", "member",
]


def _looks_sensitive(url: str) -> bool:
    url_lower = url.lower()
    return any(word in url_lower for word in SENSITIVE_INDICATORS)


def check_cache_control(pages: list, progress_callback: Callable = None) -> List[dict]:
    findings = []

    if progress_callback:
        progress_callback("Cache Control: Checking cache headers...")

    # Deduplicate URLs
    urls = list({p["url"] for p in pages})

    no_cache_occurrences = []
    public_sensitive_occurrences = []
    missing_pragma_occurrences = []

    for url in urls:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        except Exception:
            continue

        cc = resp.headers.get("Cache-Control", "").lower()
        pragma = resp.headers.get("Pragma", "").lower()
        content_type = resp.headers.get("Content-Type", "")

        is_html = "text/html" in content_type

        # ── 1. No Cache-Control on sensitive HTML pages only ──────────────────
        # Public pages (home, deals, blog, about, terms) caching is fine.
        # Only flag pages where caching could expose user-specific data.
        if is_html and not cc and _looks_sensitive(url):
            no_cache_occurrences.append({
                "url": url,
                "evidence": "Cache-Control header absent"
            })

        # ── 2. Cache-Control: public on sensitive-looking pages ───────────────
        if is_html and "public" in cc and _looks_sensitive(url):
            public_sensitive_occurrences.append({
                "url": url,
                "evidence": f"Cache-Control: {resp.headers.get('Cache-Control', '')}"
            })

        # ── 3. Missing Pragma: no-cache on sensitive authenticated pages ──────
        if is_html and _looks_sensitive(url) and "no-store" not in cc and "no-cache" not in cc:
            if "no-cache" not in pragma:
                missing_pragma_occurrences.append({
                    "url": url,
                    "evidence": f"Cache-Control: '{resp.headers.get('Cache-Control', 'absent')}', Pragma: '{resp.headers.get('Pragma', 'absent')}'"
                })

    if no_cache_occurrences:
        findings.append({
            "category": "Cache Control",
            "type": "cache_control_missing",
            "title": "Cache-Control Header Missing on HTML Pages",
            "description": (
                f"{len(no_cache_occurrences)} HTML page(s) have no Cache-Control header. "
                "Browsers and proxies may cache sensitive responses indefinitely."
            ),
            "severity": "low",
            "affected_url": no_cache_occurrences[0]["url"],
            "evidence": no_cache_occurrences[0]["evidence"],
            "occurrences": no_cache_occurrences,
            "fix_suggestion": (
                "Add `Cache-Control: no-store, no-cache, must-revalidate` on pages that return "
                "authenticated or sensitive content."
            ),
            "owasp": "A04",
            "cwe": "CWE-525",
        })

    if public_sensitive_occurrences:
        findings.append({
            "category": "Cache Control",
            "type": "cache_control_public_sensitive",
            "title": "Cache-Control: public on Sensitive Pages",
            "description": (
                f"{len(public_sensitive_occurrences)} sensitive-looking page(s) use "
                "`Cache-Control: public`, which allows CDNs and shared caches to store potentially private data."
            ),
            "severity": "medium",
            "affected_url": public_sensitive_occurrences[0]["url"],
            "evidence": public_sensitive_occurrences[0]["evidence"],
            "occurrences": public_sensitive_occurrences,
            "fix_suggestion": (
                "Use `Cache-Control: private, no-store` on pages that serve authenticated or user-specific content."
            ),
            "owasp": "A04",
            "cwe": "CWE-525",
        })

    if missing_pragma_occurrences:
        findings.append({
            "category": "Cache Control",
            "type": "cache_control_no_store_missing",
            "title": "Sensitive Pages Lack no-store / no-cache Directives",
            "description": (
                f"{len(missing_pragma_occurrences)} sensitive page(s) are missing both "
                "`no-store` and `no-cache` directives. Cached copies may be accessed by other "
                "users on shared computers or via browser back-button attacks."
            ),
            "severity": "medium",
            "affected_url": missing_pragma_occurrences[0]["url"],
            "evidence": missing_pragma_occurrences[0]["evidence"],
            "occurrences": missing_pragma_occurrences,
            "fix_suggestion": (
                "Return `Cache-Control: no-store, no-cache, must-revalidate` and `Pragma: no-cache` "
                "on all authenticated pages."
            ),
            "owasp": "A04",
            "cwe": "CWE-525",
        })

    if progress_callback:
        progress_callback(f"Cache Control: {len(findings)} finding(s)")
    return findings
