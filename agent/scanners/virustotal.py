"""
Scanner: VirusTotal Reputation
Checks domain reputation via VirusTotal public API v3.
Free tier: 4 requests/min, 500/day.
Requires: VIRUSTOTAL_API_KEY in environment.
"""
import os
import time
import requests
from urllib.parse import urlparse
from typing import List, Callable

VT_API_BASE = "https://www.virustotal.com/api/v3"


def _get_api_key() -> str:
    return os.environ.get("VIRUSTOTAL_API_KEY", "")


def _vt_get(endpoint: str, api_key: str) -> dict:
    """Single VT API call with rate-limit retry."""
    headers = {"x-apikey": api_key}
    url = f"{VT_API_BASE}{endpoint}"
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 429:
            # Rate limited — wait 15 s and retry once
            time.sleep(15)
            resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def check_virustotal(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    api_key = _get_api_key()

    if not api_key or api_key == "your_virustotal_api_key_here":
        if progress_callback:
            progress_callback("VirusTotal: Skipped — no API key configured")
        return []

    domain = urlparse(target_url).netloc.split(":")[0]
    if not domain:
        return []

    if progress_callback:
        progress_callback(f"VirusTotal: Checking reputation for {domain}...")

    # ── 1. Domain reputation ──────────────────────────────────────────────────
    domain_data = _vt_get(f"/domains/{domain}", api_key)
    if domain_data:
        attrs = domain_data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values()) if last_analysis else 0
        categories = attrs.get("categories", {})
        reputation = attrs.get("reputation", 0)

        if malicious > 0:
            sev = "critical" if malicious >= 3 else "high"
            findings.append({
                "category": "VirusTotal Reputation",
                "type": "vt_domain_malicious",
                "title": f"Domain Flagged as Malicious by {malicious} VirusTotal Engine(s)",
                "description": (
                    f"{malicious}/{total} security vendors flag {domain} as malicious. "
                    "This indicates the domain may be hosting malware, phishing pages, or has been compromised."
                ),
                "severity": sev,
                "affected_url": target_url,
                "evidence": f"VirusTotal stats: malicious={malicious}, suspicious={suspicious}, total engines={total}",
                "fix_suggestion": (
                    "Investigate and clean any malware or phishing content immediately. "
                    "Submit a review request to VirusTotal and security vendors to remove false positive flags if incorrect. "
                    "Check your server for unauthorized files, backdoors, and injected code."
                ),
                "owasp": "A08",
                "cwe": "CWE-912",
            })
        elif suspicious > 0:
            findings.append({
                "category": "VirusTotal Reputation",
                "type": "vt_domain_suspicious",
                "title": f"Domain Flagged as Suspicious by {suspicious} VirusTotal Engine(s)",
                "description": (
                    f"{suspicious}/{total} security vendors flag {domain} as suspicious. "
                    "This warrants investigation even if not yet confirmed malicious."
                ),
                "severity": "medium",
                "affected_url": target_url,
                "evidence": f"VirusTotal stats: suspicious={suspicious}, total engines={total}",
                "fix_suggestion": (
                    "Review recent changes to the site, scan for injected code or unauthorized files, "
                    "and monitor VirusTotal for escalation to malicious classification."
                ),
                "owasp": "A08",
                "cwe": "CWE-912",
            })

        if reputation < -10:
            findings.append({
                "category": "VirusTotal Reputation",
                "type": "vt_domain_low_reputation",
                "title": f"Domain Has Low VirusTotal Community Reputation (Score: {reputation})",
                "description": (
                    f"{domain} has a community reputation score of {reputation} (negative = distrust). "
                    "This is based on community votes from security researchers."
                ),
                "severity": "low",
                "affected_url": target_url,
                "evidence": f"VirusTotal reputation score: {reputation}",
                "fix_suggestion": (
                    "Review community feedback on VirusTotal. If the score is due to historical incidents, "
                    "ensure the site is clean and submit for re-evaluation."
                ),
                "owasp": "A08",
                "cwe": "CWE-912",
            })

    # ── 2. URL scan (direct URL check) ───────────────────────────────────────
    # VT URL ID is base64url of the URL without padding
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")
    url_data = _vt_get(f"/urls/{url_id}", api_key)
    if url_data:
        attrs = url_data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        total = sum(last_analysis.values()) if last_analysis else 0
        if malicious > 0:
            findings.append({
                "category": "VirusTotal Reputation",
                "type": "vt_url_malicious",
                "title": f"Target URL Flagged as Malicious by {malicious} VirusTotal Engine(s)",
                "description": (
                    f"The specific URL {target_url} is flagged as malicious by {malicious}/{total} engines. "
                    "This is more precise than a domain-level flag."
                ),
                "severity": "critical",
                "affected_url": target_url,
                "evidence": f"VirusTotal URL scan: malicious={malicious}/{total}",
                "fix_suggestion": (
                    "Immediately investigate the specific URL for injected content, phishing pages, "
                    "or malware downloads. Remove malicious content and request re-scan."
                ),
                "owasp": "A08",
                "cwe": "CWE-912",
            })

    if progress_callback:
        progress_callback(f"VirusTotal: {len(findings)} finding(s)")
    return findings
