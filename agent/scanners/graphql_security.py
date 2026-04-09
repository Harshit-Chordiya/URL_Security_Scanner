"""
Scanner: GraphQL Security
Detects GraphQL endpoints and checks for introspection and batching.
No additional libraries required.
"""
import json
import requests
from typing import List, Callable
from urllib.parse import urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BuyhatkeSecurityScanner/1.0)",
    "Content-Type": "application/json",
    "Accept": "application/json",
}

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/api/v1/graphql",
    "/query",
    "/gql",
    "/graph",
]

INTROSPECTION_QUERY = json.dumps({
    "query": "{ __schema { queryType { name } types { name kind } } }"
})

BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

FIELD_SUGGESTION_RE = __import__("re").compile(r'"Did you mean|suggestions|similar field', __import__("re").I)


def _is_graphql_response(text: str) -> bool:
    try:
        data = json.loads(text)
        return "data" in data or "errors" in data
    except Exception:
        return False


def _has_introspection(text: str) -> bool:
    try:
        data = json.loads(text)
        schema = data.get("data", {}).get("__schema", {})
        return bool(schema.get("types"))
    except Exception:
        return False


def check_graphql_security(target_url: str, progress_callback: Callable = None) -> List[dict]:
    findings = []
    base = target_url.rstrip("/")
    session = requests.Session()
    session.headers.update(HEADERS)

    if progress_callback:
        progress_callback("GraphQL: Detecting endpoints...")

    graphql_endpoints = []

    for path in GRAPHQL_PATHS:
        url = base + path
        try:
            resp = session.post(url, data=INTROSPECTION_QUERY, timeout=8)
            if resp.status_code in (200, 400) and "application/json" in resp.headers.get("Content-Type", ""):
                if _is_graphql_response(resp.text):
                    graphql_endpoints.append({"url": url, "resp": resp})
        except Exception:
            continue

    if not graphql_endpoints:
        if progress_callback:
            progress_callback("GraphQL: No endpoints detected")
        return []

    if progress_callback:
        progress_callback(f"GraphQL: Found {len(graphql_endpoints)} endpoint(s), checking security...")

    introspection_occurrences = []
    batching_occurrences = []
    suggestion_occurrences = []

    for ep in graphql_endpoints:
        url = ep["url"]
        resp = ep["resp"]

        # ── 1. Introspection enabled ──────────────────────────────────────────
        if _has_introspection(resp.text):
            introspection_occurrences.append({
                "url": url,
                "evidence": "Introspection query returned full schema with type list"
            })

        # ── 2. Query batching ─────────────────────────────────────────────────
        try:
            batch_resp = session.post(url, data=BATCH_QUERY, timeout=8)
            if batch_resp.status_code == 200:
                try:
                    batch_data = json.loads(batch_resp.text)
                    if isinstance(batch_data, list) and len(batch_data) >= 3:
                        batching_occurrences.append({
                            "url": url,
                            "evidence": f"Array batch of 5 queries returned {len(batch_data)} results"
                        })
                except Exception:
                    pass
        except Exception:
            pass

        # ── 3. Field suggestion leakage ───────────────────────────────────────
        try:
            typo_query = json.dumps({"query": "{ usr { id } }"})
            typo_resp = session.post(url, data=typo_query, timeout=8)
            if FIELD_SUGGESTION_RE.search(typo_resp.text):
                suggestion_occurrences.append({
                    "url": url,
                    "evidence": f"Error response suggests field names: {typo_resp.text[:200]}"
                })
        except Exception:
            pass

    if introspection_occurrences:
        findings.append({
            "category": "GraphQL Security",
            "type": "graphql_introspection_enabled",
            "title": "GraphQL Introspection Enabled in Production",
            "description": (
                f"GraphQL introspection is enabled on {len(introspection_occurrences)} endpoint(s). "
                "This exposes the full API schema — all types, queries, mutations, and fields — "
                "making it trivial for attackers to discover hidden endpoints and parameters."
            ),
            "severity": "medium",
            "affected_url": introspection_occurrences[0]["url"],
            "evidence": introspection_occurrences[0]["evidence"],
            "occurrences": introspection_occurrences,
            "fix_suggestion": (
                "Disable introspection in production:\n"
                "- Apollo Server: `introspection: false` in ApolloServer config\n"
                "- graphene-django: `GRAPHENE = {'MIDDLEWARE': [...], 'INTROSPECTION': False}`\n"
                "- Or use a GraphQL firewall to block introspection queries from untrusted sources"
            ),
            "owasp": "A01",
            "cwe": "CWE-200",
        })

    if batching_occurrences:
        findings.append({
            "category": "GraphQL Security",
            "type": "graphql_batching_enabled",
            "title": "GraphQL Query Batching Enabled",
            "description": (
                f"GraphQL endpoint(s) on {len(batching_occurrences)} URL(s) accept batched queries. "
                "Attackers can send thousands of queries in a single HTTP request, amplifying brute-force, "
                "enumeration, and rate-limit bypass attacks."
            ),
            "severity": "medium",
            "affected_url": batching_occurrences[0]["url"],
            "evidence": batching_occurrences[0]["evidence"],
            "occurrences": batching_occurrences,
            "fix_suggestion": (
                "Disable query batching if not required, or limit batch size to 3-5 operations.\n"
                "Also implement query complexity analysis and depth limiting to prevent DoS."
            ),
            "owasp": "A04",
            "cwe": "CWE-770",
        })

    if suggestion_occurrences:
        findings.append({
            "category": "GraphQL Security",
            "type": "graphql_field_suggestions",
            "title": "GraphQL Field Name Suggestions Enabled",
            "description": (
                f"GraphQL error responses on {len(suggestion_occurrences)} endpoint(s) suggest similar "
                "field names when a query uses an incorrect field name. Attackers can use this to enumerate "
                "the full schema without introspection being enabled."
            ),
            "severity": "low",
            "affected_url": suggestion_occurrences[0]["url"],
            "evidence": suggestion_occurrences[0]["evidence"],
            "occurrences": suggestion_occurrences,
            "fix_suggestion": (
                "Disable field suggestions in production:\n"
                "- Apollo Server: Use `ApolloServerPluginLandingPageDisabled` and disable suggestions\n"
                "- graphql-js: Override the `noSchemaIntrospectionCustomScalars` or mask errors"
            ),
            "owasp": "A01",
            "cwe": "CWE-200",
        })

    if progress_callback:
        progress_callback(f"GraphQL: {len(findings)} finding(s)")
    return findings
