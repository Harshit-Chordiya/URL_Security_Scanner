"""
Scanner: security.txt Validation
Checks for the presence and correctness of /.well-known/security.txt
Per RFC 9116.
No additional libraries required.
"""
import re
import requests
from urllib.parse import urlparse
from typing import List, Callable
from datetime import datetime, timezone

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

REQUIRED_FIELDS = ["contact", "expires"]
RECOMMENDED_FIELDS = ["encryption", "acknowledgments", "preferred-languages", "policy"]

EXPIRES_RE = re.compile(r"Expires:\s*(.+)", re.I)
CONTACT_RE = re.compile(r"Contact:\s*(.+)", re.I)


def _parse_security_txt(text: str) -> dict:
    result = {"fields": {}, "raw": text}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key not in result["fields"]:
                result["fields"][key] = []
            result["fields"][key].append(val)
    return result


def check_security_txt(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    base = target_url.rstrip("/")
    domain = urlparse(target_url).netloc

    if progress_callback:
        progress_callback("security.txt: Checking RFC 9116 compliance...")

    # Try both canonical locations
    security_txt_url = None
    content = ""
    for path in ["/.well-known/security.txt", "/security.txt"]:
        url = base + path
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            content_type = resp.headers.get("Content-Type", "").lower()
            # Must be a plain text response — if it returns HTML it's not a real security.txt
            if resp.status_code == 200 and "text/html" not in content_type and len(resp.text.strip()) > 10:
                security_txt_url = url
                content = resp.text
                break
        except Exception:
            continue

    # ── 1. File missing ───────────────────────────────────────────────────────
    if not security_txt_url:
        findings.append({
            "category": "security.txt",
            "type": "security_txt_missing",
            "title": "security.txt File Not Found",
            "description": (
                "No security.txt file found at /.well-known/security.txt or /security.txt. "
                "RFC 9116 defines this as the standard way for security researchers to report vulnerabilities. "
                "Without it, responsible disclosure reports may go unnoticed or reach the wrong contact."
            ),
            "severity": "low",
            "affected_url": target_url,
            "evidence": f"404 at {base}/.well-known/security.txt and {base}/security.txt",
            "fix_suggestion": (
                "Create /.well-known/security.txt with at minimum:\n"
                "```\n"
                "Contact: mailto:security@yourdomain.com\n"
                "Expires: 2026-12-31T23:59:59.000Z\n"
                "```\n"
                "Use https://securitytxt.org/ to generate a signed file."
            ),
            "owasp": "A05",
            "cwe": "CWE-200",
        })
        if progress_callback:
            progress_callback("security.txt: 1 finding")
        return findings

    # ── 2. Validate content ───────────────────────────────────────────────────
    parsed = _parse_security_txt(content)
    fields = parsed["fields"]

    # Check required fields
    missing_required = [f for f in REQUIRED_FIELDS if f not in fields]
    if missing_required:
        findings.append({
            "category": "security.txt",
            "type": "security_txt_missing_required_fields",
            "title": f"security.txt Missing Required Fields: {', '.join(missing_required)}",
            "description": (
                f"security.txt exists at {security_txt_url} but is missing RFC 9116 required field(s): "
                f"{', '.join(missing_required)}. Security researchers may not know how to contact you."
            ),
            "severity": "low",
            "affected_url": security_txt_url,
            "evidence": f"Present fields: {', '.join(fields.keys())}",
            "fix_suggestion": (
                "Add the missing required fields:\n"
                "- `Contact:` — email/URL/phone for vulnerability reports\n"
                "- `Expires:` — ISO 8601 datetime when this policy expires"
            ),
            "owasp": "A05",
            "cwe": "CWE-200",
        })

    # Check Expires date
    if "expires" in fields:
        expires_val = fields["expires"][0]
        try:
            # Parse ISO 8601
            expires_str = expires_val.rstrip("Z").replace("T", " ").split(".")[0]
            expires_dt = datetime.fromisoformat(expires_str).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            if expires_dt < now:
                findings.append({
                    "category": "security.txt",
                    "type": "security_txt_expired",
                    "title": "security.txt Has Expired",
                    "description": (
                        f"The security.txt Expires field ({expires_val}) is in the past. "
                        "Per RFC 9116, an expired security.txt should be treated as if it doesn't exist."
                    ),
                    "severity": "low",
                    "affected_url": security_txt_url,
                    "evidence": f"Expires: {expires_val} (now: {now.isoformat()})",
                    "fix_suggestion": "Update the Expires field to a future date and re-sign if using PGP.",
                    "owasp": "A05",
                    "cwe": "CWE-200",
                })
        except Exception:
            pass

    if progress_callback:
        progress_callback(f"security.txt: {len(findings)} finding(s)")
    return findings
