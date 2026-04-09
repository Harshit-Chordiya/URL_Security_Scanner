"""
Scanner: SSL/TLS Analysis
Checks certificate validity, TLS version support, and HTTPS enforcement.
OWASP: A02 Cryptographic Failures
"""
import ssl
import socket
import datetime
import requests
from urllib.parse import urlparse
from typing import List


def check_ssl(target_url: str, progress_callback=None) -> List[dict]:
    findings = []
    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(":")[0]
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # --- 1. HTTPS enforcement ---
    if parsed.scheme == "http":
        findings.append({
            "category": "SSL/TLS",
            "type": "no_https",
            "title": "Site Not Using HTTPS",
            "description": "The target URL uses plain HTTP, exposing all traffic to interception.",
            "severity": "critical",
            "affected_url": target_url,
            "evidence": f"URL scheme: {parsed.scheme}",
            "fix_suggestion": "Migrate to HTTPS. Obtain a TLS certificate (Let's Encrypt is free) and redirect all HTTP traffic to HTTPS.",
            "owasp": "A02",
            "cwe": "CWE-319",
        })
        return findings

    # --- 2. HTTP → HTTPS redirect check ---
    http_url = target_url.replace("https://", "http://", 1)
    try:
        resp = requests.get(http_url, timeout=8, allow_redirects=False)
        status = resp.status_code
        location = resp.headers.get("Location", "")

        # Cloudflare infrastructure errors (52x) mean the HTTP request never reached
        # the origin — Cloudflare is blocking it at the edge. Not a missing redirect.
        CLOUDFLARE_ERROR_CODES = {520, 521, 522, 523, 524, 525, 526, 527, 530}
        # 403/400/405 mean the server is actively rejecting HTTP — also not "allowing" access.
        REJECTED_CODES = {400, 403, 405}

        if status in CLOUDFLARE_ERROR_CODES or status in REJECTED_CODES:
            pass  # HTTP is blocked/down — not a missing redirect finding
        elif status in (301, 302, 307, 308) and "https" in location.lower():
            pass  # Correct redirect present
        else:
            # HTTP is reachable and not redirecting to HTTPS
            findings.append({
                "category": "SSL/TLS",
                "type": "no_http_redirect",
                "title": "HTTP Not Redirected to HTTPS",
                "description": "Plain HTTP requests are not redirected to HTTPS, allowing insecure access.",
                "severity": "high",
                "affected_url": http_url,
                "evidence": f"HTTP {status} — Location: {location or 'none'}",
                "fix_suggestion": (
                    "Configure the web server (Nginx/Apache) to force all traffic to HTTPS.\n"
                    "Nginx: `server { listen 80; return 301 https://$host$request_uri; }`\n"
                    "Apache: `Redirect permanent / https://yourdomain.com/`\n"
                    "Cloudflare: Enable 'Always Use HTTPS' in SSL/TLS → Edge Certificates."
                ),
                "owasp": "A02",
                "cwe": "CWE-319",
            })
    except Exception:
        pass  # HTTP port not open — not a finding

    # --- 3. Certificate analysis ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                tls_version = ssock.version()

        # Expiry check
        expire_str = cert.get("notAfter", "")
        if expire_str:
            expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_dt - datetime.datetime.utcnow()).days
            if days_left <= 0:
                findings.append({
                    "category": "SSL/TLS",
                    "type": "cert_expired",
                    "title": "SSL Certificate Has Expired",
                    "description": f"The TLS certificate expired on {expire_str}.",
                    "severity": "critical",
                    "affected_url": target_url,
                    "evidence": f"Expiry: {expire_str}",
                    "fix_suggestion": "Renew the TLS certificate immediately.",
                    "owasp": "A02",
                    "cwe": "CWE-298",
                })
            elif days_left <= 30:
                findings.append({
                    "category": "SSL/TLS",
                    "type": "cert_expiring_soon",
                    "title": f"SSL Certificate Expiring in {days_left} Days",
                    "description": "Certificate is close to expiry. Services will break when it expires.",
                    "severity": "medium",
                    "affected_url": target_url,
                    "evidence": f"Expires: {expire_str} ({days_left} days remaining)",
                    "fix_suggestion": "Renew the certificate before it expires. Automate with Let's Encrypt/Certbot.",
                    "owasp": "A02",
                    "cwe": "CWE-298",
                })

        # TLS version check
        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append({
                "category": "SSL/TLS",
                "type": "weak_tls_version",
                "title": f"Deprecated TLS Version in Use: {tls_version}",
                "description": f"The server negotiated {tls_version}, which has known vulnerabilities (POODLE, BEAST, etc.).",
                "severity": "high",
                "affected_url": target_url,
                "evidence": f"Negotiated TLS version: {tls_version}",
                "fix_suggestion": "Disable TLSv1.0 and TLSv1.1 on the server. Only allow TLSv1.2 and TLSv1.3.",
                "owasp": "A02",
                "cwe": "CWE-326",
            })

        # Weak cipher check
        if cipher:
            cipher_name = cipher[0]
            weak_keywords = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"]
            for kw in weak_keywords:
                if kw.upper() in cipher_name.upper():
                    findings.append({
                        "category": "SSL/TLS",
                        "type": "weak_cipher",
                        "title": f"Weak Cipher Suite in Use: {cipher_name}",
                        "description": f"The cipher suite '{cipher_name}' is considered weak or broken.",
                        "severity": "high",
                        "affected_url": target_url,
                        "evidence": f"Cipher: {cipher_name}",
                        "fix_suggestion": "Configure the server to only allow strong ciphers (AES-GCM, ChaCha20-Poly1305) with forward secrecy (ECDHE).",
                        "owasp": "A02",
                        "cwe": "CWE-326",
                    })
                    break

        if progress_callback:
            progress_callback(f"SSL check complete — TLS: {tls_version}, Cipher: {cipher[0] if cipher else 'unknown'}")

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "category": "SSL/TLS",
            "type": "invalid_cert",
            "title": "Invalid or Untrusted SSL Certificate",
            "description": f"Certificate validation failed: {e}",
            "severity": "critical",
            "affected_url": target_url,
            "evidence": str(e),
            "fix_suggestion": "Obtain a valid certificate from a trusted CA. Ensure the certificate chain is complete.",
            "owasp": "A02",
            "cwe": "CWE-295",
        })
    except Exception as e:
        if progress_callback:
            progress_callback(f"SSL probe error: {e}")

    return findings
