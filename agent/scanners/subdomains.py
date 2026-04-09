"""
Scanner: Subdomain Discovery
Uses crt.sh (free Certificate Transparency log API) to enumerate subdomains.
Checks discovered subdomains for dangling/takeover risk.
No API key required.
"""
import requests
from urllib.parse import urlparse
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Services whose CNAMEs indicate potential subdomain takeover if the record exists but the service is unclaimed
TAKEOVER_SIGNATURES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "amazonaws.com": "NoSuchBucket",
    "azurewebsites.net": "404 Web Site not found",
    "fastly.net": "Fastly error: unknown domain",
    "wpengine.com": "The site you were looking for couldn't be found",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "bitbucket.io": "Repository not found",
    "unbounce.com": "The requested URL was not found",
    "tumblr.com": "There's nothing here",
    "zendesk.com": "Help Center Closed",
    "surge.sh": "project not found",
    "netlify.app": "Not Found",
}


def _crtsh_subdomains(domain: str) -> list:
    """Query crt.sh Certificate Transparency API."""
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers=HEADERS,
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        names = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for n in name_value.split("\n"):
                n = n.strip().lower().lstrip("*.")
                if n.endswith(f".{domain}") or n == domain:
                    names.add(n)
        return sorted(names)
    except Exception:
        return []


def _check_takeover(subdomain: str) -> tuple:
    """Returns (vulnerable: bool, service: str, evidence: str)"""
    for scheme in ("https://", "http://"):
        url = f"{scheme}{subdomain}"
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            text = resp.text.lower()
            # Check if CNAME points to a 3rd-party service with unclaimed page
            for service, signature in TAKEOVER_SIGNATURES.items():
                if service in subdomain or service in resp.url.lower():
                    if signature.lower() in text:
                        return True, service, f"HTTP {resp.status_code} — matched takeover signature for {service}"
            # Also check for generic 404/not-found patterns that point to external hosting
            final_url = resp.url.lower()
            for service, signature in TAKEOVER_SIGNATURES.items():
                if service in final_url and signature.lower() in text:
                    return True, service, f"Redirected to {resp.url} — unclaimed {service} resource"
        except Exception:
            pass
    return False, "", ""


def check_subdomains(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    domain = urlparse(target_url).netloc.split(":")[0].lstrip("www.")

    if not domain:
        return []

    if progress_callback:
        progress_callback(f"Subdomains: Querying crt.sh for {domain}...")

    subdomains = _crtsh_subdomains(domain)

    if not subdomains:
        if progress_callback:
            progress_callback("Subdomains: No subdomains found via crt.sh")
        return []

    if progress_callback:
        progress_callback(f"Subdomains: Found {len(subdomains)} subdomain(s), checking for takeover risk...")

    takeover_occurrences = []

    # Check up to 30 subdomains to avoid excessive requests
    for sub in subdomains[:30]:
        vulnerable, service, evidence = _check_takeover(sub)
        if vulnerable:
            takeover_occurrences.append({
                "url": f"https://{sub}",
                "evidence": evidence
            })

    # Always report the enumeration finding (info level)
    top_subs = subdomains[:20]
    findings.append({
        "category": "Subdomain Discovery",
        "type": "subdomain_enumeration",
        "title": f"{len(subdomains)} Subdomains Discovered via Certificate Transparency",
        "description": (
            f"Certificate Transparency logs (crt.sh) reveal {len(subdomains)} subdomain(s) for {domain}. "
            "This is public information but helps attackers map your attack surface."
        ),
        "severity": "info",
        "affected_url": target_url,
        "evidence": "Subdomains: " + ", ".join(top_subs) + ("..." if len(subdomains) > 20 else ""),
        "fix_suggestion": (
            "Review all discovered subdomains. Decommission unused subdomains and ensure all "
            "active subdomains are secured. Consider CAA records to control certificate issuance."
        ),
        "owasp": "A05",
        "cwe": "CWE-200",
    })

    if takeover_occurrences:
        findings.append({
            "category": "Subdomain Discovery",
            "type": "subdomain_takeover_risk",
            "title": f"Potential Subdomain Takeover on {len(takeover_occurrences)} Subdomain(s)",
            "description": (
                f"{len(takeover_occurrences)} subdomain(s) appear to point to unclaimed third-party services "
                "(GitHub Pages, Heroku, S3, etc.). An attacker can claim these services and serve malicious "
                "content on your subdomain."
            ),
            "severity": "critical",
            "affected_url": takeover_occurrences[0]["url"],
            "evidence": takeover_occurrences[0]["evidence"],
            "occurrences": takeover_occurrences,
            "fix_suggestion": (
                "Immediately remove the DNS records pointing to unclaimed external services, "
                "OR claim/redeploy the services to prevent takeover. "
                "Use tools like subjack or can-i-take-over-xyz to monitor for this continuously."
            ),
            "owasp": "A05",
            "cwe": "CWE-350",
        })

    if progress_callback:
        progress_callback(f"Subdomains: {len(findings)} finding(s)")
    return findings
