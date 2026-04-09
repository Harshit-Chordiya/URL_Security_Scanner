"""
Scanner: Directory Listing
Checks whether directory listing is enabled on common paths.
No additional libraries required.
"""
import requests
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Paths where directory listing is commonly left enabled
CHECK_PATHS = [
    "/",
    "/images/",
    "/img/",
    "/assets/",
    "/static/",
    "/uploads/",
    "/files/",
    "/media/",
    "/css/",
    "/js/",
    "/backup/",
    "/logs/",
    "/temp/",
    "/tmp/",
]

# Signatures that indicate directory listing is enabled
LISTING_SIGNATURES = [
    "index of /",
    "directory listing for",
    "parent directory",
    "<title>index of",
    "[to parent directory]",
    "apache server at",
]


def _is_listing(text: str) -> bool:
    t = text[:4000].lower()
    return any(sig in t for sig in LISTING_SIGNATURES)


def check_directory_listing(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    session = requests.Session()
    session.headers.update(HEADERS)

    if progress_callback:
        progress_callback("Directory Listing: Checking for exposed directory indexes...")

    base = target_url.rstrip("/")
    occurrences = []

    for path in CHECK_PATHS:
        url = base + path
        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            if resp.status_code == 200 and _is_listing(resp.text):
                # Grab a snippet for evidence
                idx = resp.text.lower().find("index of")
                if idx == -1:
                    idx = resp.text.lower().find("directory listing")
                snippet = resp.text[max(0, idx):idx + 200].replace("\n", " ").strip()
                occurrences.append({
                    "url": url,
                    "evidence": snippet[:200]
                })
        except Exception:
            continue

    if occurrences:
        findings.append({
            "category": "Directory Listing",
            "type": "directory_listing_enabled",
            "title": "Directory Listing Enabled",
            "description": (
                f"Directory browsing is enabled on {len(occurrences)} path(s). "
                "This exposes the full file tree, internal paths, backup files, and configuration "
                "files to any visitor — a direct aid to reconnaissance."
            ),
            "severity": "medium",
            "affected_url": occurrences[0]["url"],
            "evidence": occurrences[0]["evidence"],
            "occurrences": occurrences,
            "fix_suggestion": (
                "Disable directory listing in your web server config:\n"
                "- Apache: `Options -Indexes` in .htaccess or httpd.conf\n"
                "- Nginx: remove `autoindex on;` (default is off)\n"
                "- IIS: uncheck 'Directory Browsing' in site features\n"
                "Also ensure no sensitive files (backups, logs, .env) are in web-accessible directories."
            ),
            "owasp": "A01",
            "cwe": "CWE-548",
        })

    if progress_callback:
        progress_callback(f"Directory Listing: {len(findings)} finding(s)")
    return findings
