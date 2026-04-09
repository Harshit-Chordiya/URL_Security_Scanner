"""
Scanner: DNS Security
Checks SPF, DMARC, DKIM, DNSSEC, CAA records.
Uses dnspython with a DNS-over-HTTPS fallback (Google/Cloudflare DoH)
so queries work even when system DNS resolution fails.
"""
import requests as _requests
from urllib.parse import urlparse
from typing import List, Callable

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# ── DNS-over-HTTPS fallback ────────────────────────────────────────────────

def _doh_query(name: str, rtype: str) -> list:
    """
    Query Google's DoH API. Returns a list of rdata strings, or [].
    Used as fallback when dnspython fails.
    """
    try:
        resp = _requests.get(
            "https://dns.google/resolve",
            params={"name": name, "type": rtype},
            headers=HEADERS,
            timeout=10,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        answers = data.get("Answer", [])
        return [a.get("data", "") for a in answers]
    except Exception:
        return []


def _txt_records(domain: str, resolver_fn) -> list:
    """Return list of TXT record strings for domain using resolver_fn."""
    try:
        result = resolver_fn(domain, "TXT")
        if result is None:
            return []
        # dnspython result set
        return [r.to_text().strip('"') for r in result]
    except Exception:
        return []


def _has_record(domain: str, rtype: str, resolver_fn) -> bool:
    """Return True if any record of rtype exists."""
    try:
        result = resolver_fn(domain, rtype)
        return result is not None
    except Exception:
        return False


def check_dns(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    domain = urlparse(target_url).netloc.split(":")[0]
    # Strip www. prefix properly (not lstrip which strips chars)
    if domain.startswith("www."):
        domain = domain[4:]

    def emit(msg):
        if progress_callback:
            progress_callback(msg)

    emit(f"DNS: Checking records for {domain}...")

    # ── Build resolver: prefer dnspython, fall back to DoH ────────────────────
    if DNS_AVAILABLE:
        def dns_query(name, rtype):
            try:
                return dns.resolver.resolve(name, rtype, lifetime=8)
            except Exception:
                return None

        def _query_txt(name):
            records = _txt_records(name, dns_query)
            if not records:
                # Fallback to DoH
                records = _doh_query(name, "TXT")
            return records

        def _query_exists(name, rtype):
            if _has_record(name, rtype, dns_query):
                return True
            # Fallback to DoH
            return len(_doh_query(name, rtype)) > 0
    else:
        def _query_txt(name):
            return _doh_query(name, "TXT")

        def _query_exists(name, rtype):
            return len(_doh_query(name, rtype)) > 0

    # ── 1. SPF ────────────────────────────────────────────────────────────────
    all_txt = _query_txt(domain)
    spf_records = [r for r in all_txt if "v=spf1" in r]

    if not spf_records:
        findings.append({
            "category": "DNS Security",
            "type": "dns_spf_missing",
            "title": "SPF Record Missing",
            "description": "No SPF TXT record found. Attackers can send emails that appear to come from your domain.",
            "severity": "high",
            "affected_url": target_url,
            "evidence": f"No v=spf1 TXT record found for {domain}",
            "fix_suggestion": 'Add a TXT record: `v=spf1 include:_spf.yourprovider.com -all` — the `-all` strictly rejects unauthorized senders.',
            "owasp": "A05",
            "cwe": "CWE-183",
        })
    else:
        spf = spf_records[0]
        if "+all" in spf:
            findings.append({
                "category": "DNS Security",
                "type": "dns_spf_plus_all",
                "title": "SPF Record Uses '+all' (Allows All Senders)",
                "description": "SPF `+all` means any server is authorized to send email as your domain — completely defeating SPF.",
                "severity": "critical",
                "affected_url": target_url,
                "evidence": f"SPF: {spf}",
                "fix_suggestion": "Replace `+all` with `-all` to strictly reject unauthorized senders.",
                "owasp": "A05",
                "cwe": "CWE-183",
            })
        elif "~all" in spf:
            findings.append({
                "category": "DNS Security",
                "type": "dns_spf_softfail",
                "title": "SPF Record Uses '~all' (SoftFail — Not Enforced)",
                "description": "SPF `~all` (softfail) marks unauthorized mail as suspicious but still delivers it. Not enforced.",
                "severity": "medium",
                "affected_url": target_url,
                "evidence": f"SPF: {spf}",
                "fix_suggestion": "Change `~all` to `-all` once you have confirmed all legitimate senders.",
                "owasp": "A05",
                "cwe": "CWE-183",
            })

    # ── 2. DMARC ──────────────────────────────────────────────────────────────
    dmarc_records = _query_txt(f"_dmarc.{domain}")
    dmarc_str = " ".join(dmarc_records)

    if not dmarc_records:
        findings.append({
            "category": "DNS Security",
            "type": "dns_dmarc_missing",
            "title": "DMARC Record Missing",
            "description": "No DMARC policy found. Your domain can be used in phishing emails with no enforcement or visibility.",
            "severity": "high",
            "affected_url": target_url,
            "evidence": f"No TXT record at _dmarc.{domain}",
            "fix_suggestion": 'Add: `v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; sp=reject; adkim=s; aspf=s`',
            "owasp": "A05",
            "cwe": "CWE-183",
        })
    else:
        if "p=none" in dmarc_str:
            findings.append({
                "category": "DNS Security",
                "type": "dns_dmarc_none_policy",
                "title": "DMARC Policy Set to 'none' (Monitor Only)",
                "description": "DMARC exists but `p=none` means no action is taken on failing emails — it only monitors.",
                "severity": "medium",
                "affected_url": target_url,
                "evidence": f"DMARC: {dmarc_str[:200]}",
                "fix_suggestion": "After reviewing DMARC reports, graduate to `p=quarantine` then `p=reject`.",
                "owasp": "A05",
                "cwe": "CWE-183",
            })
        elif "p=quarantine" in dmarc_str:
            findings.append({
                "category": "DNS Security",
                "type": "dns_dmarc_quarantine",
                "title": "DMARC Policy is 'quarantine' — Not Yet at 'reject'",
                "description": "DMARC quarantine sends failing emails to spam instead of rejecting. Phishing emails still reach recipients.",
                "severity": "low",
                "affected_url": target_url,
                "evidence": f"DMARC: {dmarc_str[:200]}",
                "fix_suggestion": "Upgrade to `p=reject` to block all unauthorized emails.",
                "owasp": "A05",
                "cwe": "CWE-183",
            })

    # ── 3. DKIM ───────────────────────────────────────────────────────────────
    # DKIM selectors are provider-specific and there is no standard way to enumerate them.
    # We check common selectors as a best-effort — a miss does NOT confirm DKIM is absent.
    dkim_selectors = [
        "default", "google", "mail", "smtp", "email", "k1",
        "selector1", "selector2",
        # Google Workspace date-based selectors
        "20161025", "20230601", "20240201", "20210112",
        # Common provider selectors
        "dkim", "dkim1", "s1", "s2", "key1", "key2",
        "elasticemail", "mandrill", "sendgrid", "mailgun",
        "pm", "mx", "postmaster",
    ]
    dkim_found = False
    for sel in dkim_selectors:
        recs = _query_txt(f"{sel}._domainkey.{domain}")
        if any("v=DKIM1" in r or "k=rsa" in r or "p=" in r for r in recs):
            dkim_found = True
            break

    if not dkim_found:
        findings.append({
            "category": "DNS Security",
            "type": "dns_dkim_missing",
            "title": "DKIM Not Detected on Common Selectors",
            "description": (
                "No DKIM TXT record was found on common selectors. "
                "Note: DKIM selectors are provider-specific — this may be a false positive if a "
                "non-standard selector name is in use. Verify in your email provider's dashboard."
            ),
            "severity": "info",
            "affected_url": target_url,
            "evidence": f"Checked {len(dkim_selectors)} selectors including Google Workspace date-based selectors",
            "fix_suggestion": "Verify DKIM is configured in your email provider (Google Workspace, Elastic Email, etc.) and the public key is published as a TXT record at `<selector>._domainkey.yourdomain.com`.",
            "owasp": "A05",
            "cwe": "CWE-183",
        })

    # ── 4. CAA ────────────────────────────────────────────────────────────────
    caa_records = _doh_query(domain, "CAA")  # Use DoH directly — CAA type support varies
    if not caa_records:
        findings.append({
            "category": "DNS Security",
            "type": "dns_caa_missing",
            "title": "CAA Records Missing",
            "description": "No CAA records found. Any Certificate Authority can issue SSL certificates for your domain.",
            "severity": "low",
            "affected_url": target_url,
            "evidence": f"No CAA record for {domain}",
            "fix_suggestion": 'Add CAA records: `0 issue "letsencrypt.org"` and `0 issuewild ";"` to block wildcard certs.',
            "owasp": "A02",
            "cwe": "CWE-295",
        })

    # ── 5. DNSSEC ─────────────────────────────────────────────────────────────
    ds_records = _doh_query(domain, "DS")
    dnskey_records = _doh_query(domain, "DNSKEY")
    if not ds_records and not dnskey_records:
        findings.append({
            "category": "DNS Security",
            "type": "dns_dnssec_missing",
            "title": "DNSSEC Not Enabled",
            "description": "DNSSEC is not configured. DNS responses can be forged by cache poisoning attacks.",
            "severity": "low",
            "affected_url": target_url,
            "evidence": f"No DS or DNSKEY record found for {domain}",
            "fix_suggestion": "Enable DNSSEC at your domain registrar. Most modern registrars support this in one click.",
            "owasp": "A05",
            "cwe": "CWE-346",
        })

    emit(f"DNS: {len(findings)} finding(s)")
    return findings
