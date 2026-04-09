"""
Scanner: Technology Fingerprinting
Identifies the tech stack from headers, cookies, and HTML patterns.
Reports overly-verbose version disclosures that aid targeted attacks.
No additional libraries required.
"""
import re
import requests
from bs4 import BeautifulSoup
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# (pattern, technology_name, version_group_index_or_None)
HEADER_SIGNATURES = [
    (re.compile(r"WordPress/(\d[\d.]+)", re.I), "WordPress", 1),
    (re.compile(r"Drupal (\d[\d.]+)", re.I), "Drupal", 1),
    (re.compile(r"Joomla! (\d[\d.]+)", re.I), "Joomla", 1),
    (re.compile(r"PHP/(\d[\d.]+)", re.I), "PHP", 1),
    (re.compile(r"Apache/(\d[\d.]+)", re.I), "Apache", 1),
    (re.compile(r"nginx/(\d[\d.]+)", re.I), "Nginx", 1),
    (re.compile(r"Microsoft-IIS/(\d[\d.]+)", re.I), "IIS", 1),
    (re.compile(r"Tomcat/(\d[\d.]+)", re.I), "Apache Tomcat", 1),
    (re.compile(r"Express", re.I), "Express.js", None),
    (re.compile(r"Django/(\d[\d.]+)", re.I), "Django", 1),
    (re.compile(r"Rails/(\d[\d.]+)", re.I), "Ruby on Rails", 1),
    (re.compile(r"ASP\.NET", re.I), "ASP.NET", None),
    (re.compile(r"ASP\.NET MVC/(\d[\d.]+)", re.I), "ASP.NET MVC", 1),
    (re.compile(r"X-Powered-By:\s*(.+)", re.I), "X-Powered-By", None),
    (re.compile(r"OpenSSL/(\d[\d.]+)", re.I), "OpenSSL", 1),
    (re.compile(r"JBoss[/ ](\d[\d.]+)?", re.I), "JBoss", 1),
    (re.compile(r"WebLogic[/ ](\d[\d.]+)?", re.I), "WebLogic", 1),
]

COOKIE_SIGNATURES = [
    (re.compile(r"^PHPSESSID$"), "PHP"),
    (re.compile(r"^ASP\.NET_SessionId$", re.I), "ASP.NET"),
    (re.compile(r"^JSESSIONID$"), "Java/Servlet"),
    (re.compile(r"^_rails_session$"), "Ruby on Rails"),
    (re.compile(r"^django_session$|^sessionid$"), "Django"),
    (re.compile(r"^connect\.sid$"), "Express.js/Node.js"),
    (re.compile(r"^CFID$|^CFTOKEN$"), "ColdFusion"),
    (re.compile(r"^wp-settings"), "WordPress"),
]

HTML_SIGNATURES = [
    (re.compile(r'content="WordPress (\d[\d.]+)"', re.I), "WordPress", 1),
    (re.compile(r'generator.*?Joomla! (\d[\d.]+)', re.I), "Joomla", 1),
    (re.compile(r'generator.*?Drupal (\d[\d.]+)', re.I), "Drupal", 1),
    (re.compile(r'Powered by <a[^>]*>(.+?)</a>', re.I), "Powered-by", 1),
    (re.compile(r'/wp-content/|/wp-includes/'), "WordPress", None),
    (re.compile(r'Magento', re.I), "Magento", None),
    (re.compile(r'Shopify\.theme', re.I), "Shopify", None),
    (re.compile(r'ng-version="([\d.]+)"', re.I), "Angular", 1),
    (re.compile(r'__NEXT_DATA__'), "Next.js", None),
    (re.compile(r'__nuxt'), "Nuxt.js", None),
]


def check_tech_fingerprint(pages: list, progress_callback: Callable = None) -> List[dict]:
    findings = []

    if progress_callback:
        progress_callback("Tech Fingerprint: Analyzing technology stack...")

    detected = {}  # tech -> {versions, urls, sources}
    version_disclosed = {}  # tech -> {version, url, header}

    for page in pages[:5]:  # Limit to first 5 pages for efficiency
        url = page.get("url", "")
        html = page.get("content", "")

        # Fetch fresh response to get headers and cookies
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
        except Exception:
            resp = None

        # ── Check response headers ────────────────────────────────────────────
        if resp:
            all_headers = " ".join(f"{k}: {v}" for k, v in resp.headers.items())

            for pattern, tech, ver_group in HEADER_SIGNATURES:
                m = pattern.search(all_headers)
                if m:
                    version = m.group(ver_group) if ver_group and ver_group <= len(m.groups()) else None
                    if tech not in detected:
                        detected[tech] = {"versions": set(), "urls": [], "sources": set()}
                    detected[tech]["urls"].append(url)
                    detected[tech]["sources"].add("HTTP header")
                    if version:
                        detected[tech]["versions"].add(version)
                        version_disclosed[tech] = {
                            "version": version,
                            "url": url,
                            "evidence": f"Header: {m.group(0)[:100]}"
                        }

            # Check cookies
            for cookie_name in resp.cookies.keys():
                for pattern, tech in COOKIE_SIGNATURES:
                    if pattern.search(cookie_name):
                        if tech not in detected:
                            detected[tech] = {"versions": set(), "urls": [], "sources": set()}
                        detected[tech]["urls"].append(url)
                        detected[tech]["sources"].add(f"Cookie: {cookie_name}")

        # ── Check HTML ────────────────────────────────────────────────────────
        if html:
            for pattern, tech, ver_group in HTML_SIGNATURES:
                m = pattern.search(html)
                if m:
                    version = m.group(ver_group) if ver_group and ver_group <= len(m.groups()) else None
                    if tech not in detected:
                        detected[tech] = {"versions": set(), "urls": [], "sources": set()}
                    if url not in detected[tech]["urls"]:
                        detected[tech]["urls"].append(url)
                    detected[tech]["sources"].add("HTML source")
                    if version:
                        detected[tech]["versions"].add(version)
                        if tech not in version_disclosed:
                            version_disclosed[tech] = {
                                "version": version,
                                "url": url,
                                "evidence": f"HTML meta/generator: {m.group(0)[:100]}"
                            }

    if not detected:
        if progress_callback:
            progress_callback("Tech Fingerprint: No technology signatures detected")
        return []

    # Build stack summary
    stack_summary = []
    for tech, info in detected.items():
        versions = info["versions"]
        v_str = f" v{', '.join(sorted(versions))}" if versions else ""
        stack_summary.append(f"{tech}{v_str}")

    # ── Finding 1: Full stack enumeration (info) ──────────────────────────────
    findings.append({
        "category": "Technology Fingerprinting",
        "type": "tech_stack_exposed",
        "title": f"Technology Stack Identified: {', '.join(list(detected.keys())[:5])}",
        "description": (
            f"The following technologies were fingerprinted from public responses: "
            f"{', '.join(stack_summary)}. "
            "This is public information but significantly helps attackers target known CVEs."
        ),
        "severity": "info",
        "affected_url": pages[0]["url"] if pages else "",
        "evidence": "; ".join(stack_summary[:10]),
        "fix_suggestion": (
            "Reduce technology fingerprinting surface:\n"
            "- Remove generator meta tags from HTML\n"
            "- Suppress X-Powered-By headers (Express: `app.disable('x-powered-by')`)\n"
            "- Use generic session cookie names\n"
            "- Keep all software up to date to minimize known CVE exposure"
        ),
        "owasp": "A05",
        "cwe": "CWE-200",
    })

    # ── Finding 2: Specific version disclosures (low) ─────────────────────────
    if version_disclosed:
        version_occurrences = [
            {"url": info["url"], "evidence": f"{tech} {info['version']}: {info['evidence']}"}
            for tech, info in version_disclosed.items()
        ]
        findings.append({
            "category": "Technology Fingerprinting",
            "type": "tech_version_disclosed",
            "title": f"Specific Version Numbers Exposed for {len(version_disclosed)} Technology/ies",
            "description": (
                f"Exact version numbers are publicly visible for: "
                + ", ".join(f"{t} {i['version']}" for t, i in version_disclosed.items())
                + ". Attackers can look up CVEs for these exact versions and target known exploits."
            ),
            "severity": "low",
            "affected_url": version_occurrences[0]["url"],
            "evidence": version_occurrences[0]["evidence"],
            "occurrences": version_occurrences,
            "fix_suggestion": (
                "Remove or suppress version disclosures:\n"
                "- Apache: `ServerTokens Prod` + `ServerSignature Off`\n"
                "- Nginx: `server_tokens off;`\n"
                "- PHP: `expose_php = Off` in php.ini\n"
                "- WordPress: remove generator meta tag with `remove_action('wp_head', 'wp_generator')`"
            ),
            "owasp": "A05",
            "cwe": "CWE-200",
        })

    if progress_callback:
        progress_callback(f"Tech Fingerprint: {len(findings)} finding(s)")
    return findings
