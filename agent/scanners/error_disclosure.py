"""
Scanner: Error Disclosure
Checks whether the application leaks stack traces or verbose error messages.
No additional libraries required.
"""
import re
import requests
from typing import List, Callable

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)"}

# Payloads likely to trigger errors
ERROR_PROBES = [
    "?id='",
    "?id=1/0",
    "?foo[bar]=1",
    "?id=<invalid>",
    "/nonexistent-page-bhk-test-404",
]

# Patterns that indicate verbose error output
STACK_TRACE_PATTERNS = [
    re.compile(r"traceback \(most recent call last\)", re.I),
    re.compile(r"at\s+[\w\.$<>]+\([\w./]+\.java:\d+\)", re.I),  # Java stack trace
    re.compile(r"System\.Web\.HttpUnhandledException", re.I),      # ASP.NET
    re.compile(r"Microsoft\.CSharp\.", re.I),
    re.compile(r"phpmailer|PDOException|mysqli_connect_error|parse error.*on line \d+", re.I),
    re.compile(r"Fatal error.*in .+\.php on line", re.I),
    re.compile(r"Warning:.*in .+\.php on line", re.I),
    re.compile(r"Notice:.*in .+\.php on line", re.I),
    re.compile(r"<b>Warning</b>.*<br />", re.I),
    re.compile(r"SQL syntax.*MySQL|ORA-\d{4,}|PG::\w+Error|SqlException", re.I),
    re.compile(r"SQLSTATE\[", re.I),
    re.compile(r"unhandled exception.*\n.*at\s", re.I),
    re.compile(r"django\.core\.exceptions|django debug|django traceback", re.I),
]

VERSION_LEAK_PATTERNS = [
    re.compile(r"Apache/\d+\.\d+", re.I),
    re.compile(r"nginx/\d+\.\d+", re.I),
    re.compile(r"PHP/\d+\.\d+", re.I),
    re.compile(r"IIS/\d+\.\d+", re.I),
    re.compile(r"Tomcat/\d+\.\d+", re.I),
    re.compile(r"Express \d+\.\d+", re.I),
    re.compile(r"Ruby on Rails \d+\.\d+", re.I),
    re.compile(r"Django/\d+\.\d+", re.I),
    re.compile(r"Laravel v\d+\.\d+", re.I),
    re.compile(r"Spring Framework \d+\.\d+", re.I),
]


def _check_response(text: str):
    """Returns (has_stack_trace, has_version_leak, snippet)."""
    for p in STACK_TRACE_PATTERNS:
        m = p.search(text)
        if m:
            start = max(0, m.start() - 30)
            return True, False, text[start:start + 200].strip()
    for p in VERSION_LEAK_PATTERNS:
        m = p.search(text)
        if m:
            start = max(0, m.start() - 20)
            return False, True, text[start:start + 120].strip()
    return False, False, ""


def check_error_disclosure(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    session = requests.Session()
    session.headers.update(HEADERS)

    if progress_callback:
        progress_callback("Error Disclosure: Probing for stack traces and version leaks...")

    stack_trace_occurrences = []
    version_leak_occurrences = []
    seen_snippets: set = set()

    base = target_url.rstrip("/")

    for probe in ERROR_PROBES:
        if probe.startswith("/"):
            url = base + probe
        else:
            url = base + probe
        try:
            resp = session.get(url, timeout=8, allow_redirects=True)
            text = resp.text
        except Exception:
            continue

        has_trace, has_version, snippet = _check_response(text)

        if has_trace and snippet not in seen_snippets:
            seen_snippets.add(snippet)
            stack_trace_occurrences.append({
                "url": url,
                "evidence": snippet[:200]
            })

        if has_version and snippet not in seen_snippets:
            seen_snippets.add(snippet)
            version_leak_occurrences.append({
                "url": url,
                "evidence": snippet[:200]
            })

    if stack_trace_occurrences:
        findings.append({
            "category": "Error Disclosure",
            "type": "error_stack_trace_exposed",
            "title": "Stack Traces / Verbose Errors Exposed to Users",
            "description": (
                f"The application returns detailed stack traces or verbose error messages "
                f"on {len(stack_trace_occurrences)} probe(s). This leaks file paths, framework versions, "
                "and internal logic to attackers."
            ),
            "severity": "high",
            "affected_url": stack_trace_occurrences[0]["url"],
            "evidence": stack_trace_occurrences[0]["evidence"],
            "occurrences": stack_trace_occurrences,
            "fix_suggestion": (
                "Configure production error handling to show generic '500 Internal Server Error' pages. "
                "Log full traces server-side only.\n"
                "- PHP: `display_errors = Off` in php.ini\n"
                "- Django: `DEBUG = False` in settings.py\n"
                "- Node/Express: remove stack from error middleware responses"
            ),
            "owasp": "A05",
            "cwe": "CWE-209",
        })

    if version_leak_occurrences:
        findings.append({
            "category": "Error Disclosure",
            "type": "error_version_disclosure",
            "title": "Server / Framework Version Disclosed in Error Pages",
            "description": (
                f"Error responses on {len(version_leak_occurrences)} probe(s) include specific "
                "software version numbers. Attackers can use this to target known CVEs."
            ),
            "severity": "low",
            "affected_url": version_leak_occurrences[0]["url"],
            "evidence": version_leak_occurrences[0]["evidence"],
            "occurrences": version_leak_occurrences,
            "fix_suggestion": (
                "Suppress version info from error pages and response headers.\n"
                "- Nginx: `server_tokens off;`\n"
                "- Apache: `ServerTokens Prod` + `ServerSignature Off`\n"
                "- PHP: `expose_php = Off`"
            ),
            "owasp": "A05",
            "cwe": "CWE-200",
        })

    if progress_callback:
        progress_callback(f"Error Disclosure: {len(findings)} finding(s)")
    return findings
