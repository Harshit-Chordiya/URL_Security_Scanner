"""
Scanner: JWT Security
Detects JWTs in responses and checks for weak algorithms, none-algorithm, and weak secrets.
Requires: PyJWT
"""
import re
import requests
from typing import List, Callable

try:
    import jwt as pyjwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Regex to find JWTs in response bodies, cookies, and headers
JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*"
)

# Common weak secrets to test
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "supersecret",
    "mysecret", "jwt_secret", "jwtSecret", "your_secret_key",
    "secret_key", "private_key", "abc123", "qwerty", "test",
    "development", "prod", "production", "", "null", "undefined",
    "key", "token", "jwt", "app_secret",
]


def _decode_header(token: str) -> dict:
    """Decode JWT header without verification."""
    try:
        return pyjwt.get_unverified_header(token)
    except Exception:
        return {}


def _check_none_alg(token: str) -> bool:
    """Check if token accepts 'none' algorithm."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        import base64
        import json
        # Build a 'none' version of this token
        header_bytes = base64.urlsafe_b64decode(parts[0] + "==")
        header = json.loads(header_bytes)
        header["alg"] = "none"
        new_header = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        # Try decoding with none algorithm
        none_token = f"{new_header}.{parts[1]}."
        pyjwt.decode(none_token, options={"verify_signature": False, "algorithms": ["none"]})
        return True  # Successfully decoded with none
    except Exception:
        return False


def _check_weak_secret(token: str) -> str:
    """Returns the weak secret if found, else empty string."""
    for secret in WEAK_SECRETS:
        try:
            header = _decode_header(token)
            alg = header.get("alg", "HS256")
            if alg.startswith("HS"):
                pyjwt.decode(token, secret, algorithms=[alg])
                return secret
        except pyjwt.InvalidSignatureError:
            continue
        except Exception:
            continue
    return ""


def check_jwt_security(pages: list, progress_callback: Callable = None) -> List[dict]:
    if not JWT_AVAILABLE:
        if progress_callback:
            progress_callback("JWT: Skipped — run: pip install PyJWT")
        return []

    findings = []

    if progress_callback:
        progress_callback("JWT: Scanning for tokens in responses...")

    weak_alg_occurrences = []
    none_alg_occurrences = []
    weak_secret_occurrences = []
    seen_tokens: set = set()

    for page in pages:
        url = page.get("url", "")
        html = page.get("content", "")

        # Also fetch with cookies to catch tokens in Set-Cookie headers
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            # Check response body + cookies + headers
            all_text = resp.text
            for cookie_val in resp.cookies.values():
                all_text += " " + cookie_val
            for h_val in resp.headers.values():
                all_text += " " + h_val
        except Exception:
            all_text = html

        tokens = JWT_RE.findall(all_text)

        for token in tokens:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)

            header = _decode_header(token)
            alg = header.get("alg", "").upper()

            # ── 1. Weak/insecure algorithms ─────────────────────────────────
            if alg in ("NONE", ""):
                none_alg_occurrences.append({
                    "url": url,
                    "evidence": f"JWT uses alg='{alg}': {token[:60]}..."
                })
            elif alg in ("HS256",) and len(token.split(".")[1]) < 40:
                # Very short payload may indicate test/dev token
                weak_alg_occurrences.append({
                    "url": url,
                    "evidence": f"JWT alg={alg}, short payload (dev token?): {token[:60]}..."
                })

            # ── 2. None algorithm acceptance ────────────────────────────────
            if alg not in ("NONE", "") and _check_none_alg(token):
                none_alg_occurrences.append({
                    "url": url,
                    "evidence": f"Token accepted with 'none' algorithm: {token[:60]}..."
                })

            # ── 3. Weak secret ──────────────────────────────────────────────
            if alg.startswith("HS"):
                found_secret = _check_weak_secret(token)
                if found_secret is not None and found_secret != "":
                    weak_secret_occurrences.append({
                        "url": url,
                        "evidence": f"JWT signed with weak secret '{found_secret}': {token[:60]}..."
                    })

    # ── 4. Check for RS256→HS256 confusion (if RS256 tokens found) ──────────
    # (Detect RS256 tokens — actual confusion attack requires server cooperation)
    rs256_occurrences = []
    for page in pages:
        all_text = page.get("content", "")
        for token in JWT_RE.findall(all_text):
            if token in seen_tokens:
                header = _decode_header(token)
                if header.get("alg", "").upper() == "RS256":
                    rs256_occurrences.append({
                        "url": page.get("url", ""),
                        "evidence": f"RS256 token found — verify server rejects HS256 re-signed tokens: {token[:60]}..."
                    })

    if none_alg_occurrences:
        findings.append({
            "category": "JWT Security",
            "type": "jwt_none_algorithm",
            "title": "JWT Uses or Accepts 'none' Algorithm",
            "description": (
                f"JWT token(s) found on {len(none_alg_occurrences)} page(s) with the 'none' algorithm "
                "or the server accepts none-signed tokens. This completely bypasses signature verification, "
                "allowing any attacker to forge arbitrary tokens."
            ),
            "severity": "critical",
            "affected_url": none_alg_occurrences[0]["url"],
            "evidence": none_alg_occurrences[0]["evidence"],
            "occurrences": none_alg_occurrences,
            "fix_suggestion": (
                "Explicitly whitelist allowed algorithms on the server (e.g., `algorithms=['HS256']`). "
                "Never accept 'none' as a valid algorithm.\n"
                "PyJWT: `jwt.decode(token, key, algorithms=['HS256'])`"
            ),
            "owasp": "A02",
            "cwe": "CWE-347",
        })

    if weak_secret_occurrences:
        findings.append({
            "category": "JWT Security",
            "type": "jwt_weak_secret",
            "title": "JWT Signed With a Weak/Common Secret Key",
            "description": (
                f"JWT token(s) on {len(weak_secret_occurrences)} page(s) could be verified using "
                "a common/weak secret. An attacker can forge valid tokens for any user including admins."
            ),
            "severity": "critical",
            "affected_url": weak_secret_occurrences[0]["url"],
            "evidence": weak_secret_occurrences[0]["evidence"],
            "occurrences": weak_secret_occurrences,
            "fix_suggestion": (
                "Use a cryptographically random secret of at least 256 bits:\n"
                "`import secrets; secret = secrets.token_hex(32)`\n"
                "Store it in environment variables, never in code or config files."
            ),
            "owasp": "A02",
            "cwe": "CWE-521",
        })

    if rs256_occurrences:
        findings.append({
            "category": "JWT Security",
            "type": "jwt_algorithm_confusion_risk",
            "title": "RS256 JWTs Found — Verify Algorithm Confusion Protection",
            "description": (
                f"RS256-signed JWT(s) detected on {len(rs256_occurrences)} page(s). "
                "If the server does not strictly enforce the algorithm, an attacker may reuse the "
                "public key as an HMAC secret (RS256→HS256 algorithm confusion attack)."
            ),
            "severity": "medium",
            "affected_url": rs256_occurrences[0]["url"],
            "evidence": rs256_occurrences[0]["evidence"],
            "occurrences": rs256_occurrences,
            "fix_suggestion": (
                "Explicitly specify allowed algorithms server-side. Never infer algorithm from the token header. "
                "PyJWT: `jwt.decode(token, public_key, algorithms=['RS256'])`"
            ),
            "owasp": "A02",
            "cwe": "CWE-347",
        })

    if progress_callback:
        progress_callback(f"JWT: {len(findings)} finding(s)")
    return findings
