"""
Scanner: Subresource Integrity (SRI)
Checks external scripts and stylesheets for missing integrity attributes.
No additional libraries required.
"""
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import List


def check_sri(page: dict) -> List[dict]:
    findings = []
    html = page.get("content", "")
    url = page["url"]
    page_domain = urlparse(url).netloc

    if not html or "text/html" not in page.get("content_type", ""):
        return findings

    soup = BeautifulSoup(html, "lxml")

    # ── External <script> without integrity ───────────────────────────────────
    missing_scripts = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        if not src:
            continue
        parsed = urlparse(src)
        # Only flag truly external (different domain or protocol-relative CDN)
        if parsed.netloc and parsed.netloc != page_domain:
            if not tag.get("integrity"):
                missing_scripts.append(src[:120])

    if missing_scripts:
        findings.append({
            "category": "Subresource Integrity",
            "type": "sri_missing_script",
            "title": "External Scripts Missing Integrity Attribute (SRI)",
            "description": (
                f"{len(missing_scripts)} external <script> tag(s) load from third-party CDNs without an "
                "`integrity` attribute. If the CDN is compromised, malicious JS executes silently on your site."
            ),
            "severity": "high",
            "affected_url": url,
            "evidence": "Missing SRI on: " + "; ".join(missing_scripts[:5]),
            "fix_suggestion": (
                "Generate SRI hashes at https://www.srihash.org/ and add them:\n"
                '<script src="https://cdn.example.com/lib.js" '
                'integrity="sha384-<hash>" crossorigin="anonymous"></script>'
            ),
            "owasp": "A06",
            "cwe": "CWE-353",
        })

    # ── External <link rel="stylesheet"> without integrity ────────────────────
    missing_styles = []
    for tag in soup.find_all("link", rel=True):
        rels = tag.get("rel", [])
        if "stylesheet" not in rels:
            continue
        href = tag.get("href", "")
        parsed = urlparse(href)
        if parsed.netloc and parsed.netloc != page_domain:
            if not tag.get("integrity"):
                missing_styles.append(href[:120])

    if missing_styles:
        findings.append({
            "category": "Subresource Integrity",
            "type": "sri_missing_stylesheet",
            "title": "External Stylesheets Missing Integrity Attribute (SRI)",
            "description": (
                f"{len(missing_styles)} external stylesheet(s) load from third-party CDNs without an "
                "`integrity` attribute. Malicious CSS can exfiltrate data or perform UI redressing."
            ),
            "severity": "medium",
            "affected_url": url,
            "evidence": "Missing SRI on: " + "; ".join(missing_styles[:5]),
            "fix_suggestion": (
                "Generate SRI hashes at https://www.srihash.org/ and add them:\n"
                '<link rel="stylesheet" href="https://cdn.example.com/style.css" '
                'integrity="sha384-<hash>" crossorigin="anonymous">'
            ),
            "owasp": "A06",
            "cwe": "CWE-353",
        })

    return findings
