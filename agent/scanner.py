"""
Scan Orchestrator — coordinates all scanners, collects findings,
runs Gemini analysis, and generates the final report.
"""
import uuid
import datetime
import logging
from collections import defaultdict
from typing import Callable, Optional

from agent.crawler import WebCrawler
from agent.scanners.headers import check_security_headers
from agent.scanners.ssl_check import check_ssl
from agent.scanners.cookies import check_cookies
from agent.scanners.content import check_content
from agent.scanners.active import check_active
from agent.scanners.cors import check_cors
from agent.scanners.sri import check_sri
from agent.scanners.dns_security import check_dns
from agent.scanners.http_methods import check_http_methods
from agent.scanners.hsts_preload import check_hsts_preload
from agent.scanners.virustotal import check_virustotal
from agent.scanners.subdomains import check_subdomains
from agent.scanners.jwt_security import check_jwt_security
from agent.scanners.cache_control import check_cache_control
from agent.scanners.rate_limiting import check_rate_limiting
from agent.scanners.error_disclosure import check_error_disclosure
from agent.scanners.directory_listing import check_directory_listing
from agent.scanners.graphql_security import check_graphql_security
from agent.scanners.tech_fingerprint import check_tech_fingerprint
from agent.scanners.security_txt import check_security_txt
from agent.scanners.ssrf import check_ssrf
from agent.gemini_analyzer import GeminiAnalyzer
from agent.reporter import generate_report

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _merge_occurrences(items: list) -> list:
    """
    Build a deduplicated occurrences list from a group of same-type findings.
    Handles both old-style findings (single affected_url) and new-style findings
    (pre-built occurrences list).
    """
    seen_urls: set = set()
    occurrences = []
    for item in items:
        if item.get("occurrences"):
            # New scanner style: already has occurrences list
            for occ in item["occurrences"]:
                url = occ.get("url", "")
                if url not in seen_urls:
                    seen_urls.add(url)
                    occurrences.append(occ)
        else:
            # Old scanner style: single affected_url
            url = item.get("affected_url", "")
            if url not in seen_urls:
                seen_urls.add(url)
                occurrences.append({
                    "url": url,
                    "evidence": item.get("evidence", ""),
                })
    return occurrences


class SecurityScanner:
    def __init__(self, gemini_api_key: str, gemini_model: str):
        self.analyzer = GeminiAnalyzer(gemini_api_key, gemini_model)

    def run(
        self,
        target_url: str,
        max_pages: int = 30,
        crawl_delay: float = 1.0,
        progress_callback: Callable = None,
    ) -> dict:
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.datetime.utcnow().isoformat() + "Z"
        raw_findings = []

        def emit(msg: str):
            logger.info(msg)
            if progress_callback:
                progress_callback(msg)

        emit(f"[{scan_id}] Starting scan of {target_url}")

        # ── Phase 1: Domain-level checks (no crawl needed) ───────────────────
        emit("Phase 1/8 — Domain-level checks (SSL, DNS, HTTP methods, reputation)...")

        ssl_findings = check_ssl(target_url, progress_callback=emit)
        raw_findings.extend(ssl_findings)
        emit(f"  → {len(ssl_findings)} SSL/TLS finding(s)")

        dns_findings = check_dns(target_url, progress_callback=emit)
        raw_findings.extend(dns_findings)
        emit(f"  → {len(dns_findings)} DNS finding(s)")

        http_method_findings = check_http_methods(target_url, progress_callback=emit)
        raw_findings.extend(http_method_findings)
        emit(f"  → {len(http_method_findings)} HTTP method finding(s)")

        hsts_findings = check_hsts_preload(target_url, progress_callback=emit)
        raw_findings.extend(hsts_findings)
        emit(f"  → {len(hsts_findings)} HSTS preload finding(s)")

        vt_findings = check_virustotal(target_url, progress_callback=emit)
        raw_findings.extend(vt_findings)
        emit(f"  → {len(vt_findings)} VirusTotal finding(s)")

        subdomain_findings = check_subdomains(target_url, progress_callback=emit)
        raw_findings.extend(subdomain_findings)
        emit(f"  → {len(subdomain_findings)} subdomain finding(s)")

        # ── Phase 2: Crawl ────────────────────────────────────────────────────
        emit(f"Phase 2/8 — Crawling site (max {max_pages} pages)...")
        crawler = WebCrawler(target_url, max_pages=max_pages, delay=crawl_delay)
        pages = crawler.crawl(progress_callback=emit)
        emit(f"  → Crawled {len(pages)} page(s)")

        if not pages:
            emit("No pages crawled. Scan aborted.")
            return {"error": "No pages could be crawled", "scan_id": scan_id}

        # ── Phase 3: Per-page static checks ──────────────────────────────────
        emit("Phase 3/8 — Analyzing headers, cookies, content, and SRI...")
        header_dedup = set()
        for page in pages:
            # Headers (deduplicate repeated findings across pages — one per type)
            for f in check_security_headers(page):
                key = f["type"]
                if key not in header_dedup:
                    header_dedup.add(key)
                    raw_findings.append(f)

            # Cookies
            raw_findings.extend(check_cookies(page))

            # Content
            raw_findings.extend(check_content(page))

            # SRI
            raw_findings.extend(check_sri(page))

        emit(f"  → {len(raw_findings)} finding(s) so far")

        # ── Phase 4: CORS ─────────────────────────────────────────────────────
        emit("Phase 4/8 — CORS misconfiguration check...")
        cors_findings = check_cors(target_url, pages, progress_callback=emit)
        raw_findings.extend(cors_findings)
        emit(f"  → {len(cors_findings)} CORS finding(s)")

        # ── Phase 5: Active probes ────────────────────────────────────────────
        emit("Phase 5/8 — Active probes (XSS, SQLi, paths, redirects, errors)...")
        active_findings = check_active(target_url, pages, progress_callback=emit)
        raw_findings.extend(active_findings)

        error_findings = check_error_disclosure(target_url, progress_callback=emit)
        raw_findings.extend(error_findings)

        dir_findings = check_directory_listing(target_url, progress_callback=emit)
        raw_findings.extend(dir_findings)

        graphql_findings = check_graphql_security(target_url, progress_callback=emit)
        raw_findings.extend(graphql_findings)

        emit(f"  → {len(active_findings) + len(error_findings) + len(dir_findings) + len(graphql_findings)} active finding(s)")

        # ── Phase 6: Page-set checks ──────────────────────────────────────────
        emit("Phase 6/8 — JWT, cache control, rate limiting, SSRF, tech fingerprint...")

        jwt_findings = check_jwt_security(pages, progress_callback=emit)
        raw_findings.extend(jwt_findings)

        cache_findings = check_cache_control(pages, progress_callback=emit)
        raw_findings.extend(cache_findings)

        rate_findings = check_rate_limiting(target_url, pages, progress_callback=emit)
        raw_findings.extend(rate_findings)

        ssrf_findings = check_ssrf(pages, progress_callback=emit)
        raw_findings.extend(ssrf_findings)

        tech_findings = check_tech_fingerprint(pages, progress_callback=emit)
        raw_findings.extend(tech_findings)

        emit(f"  → {len(jwt_findings) + len(cache_findings) + len(rate_findings) + len(ssrf_findings) + len(tech_findings)} page-set finding(s)")

        # ── Phase 7: Disclosure policy checks ────────────────────────────────
        emit("Phase 7/8 — security.txt policy check...")
        sectxt_findings = check_security_txt(target_url, progress_callback=emit)
        raw_findings.extend(sectxt_findings)
        emit(f"  → {len(sectxt_findings)} policy finding(s)")

        # ── Group same-type findings → one merged finding per type ────────────
        type_groups: dict = defaultdict(list)
        for f in raw_findings:
            type_groups[f["type"]].append(f)

        unique_findings = []
        for ftype, items in type_groups.items():
            # Pick best base: prefer entry that already has occurrences (new scanner style)
            base = sorted(
                items,
                key=lambda x: (bool(x.get("occurrences")), bool(x.get("impact"))),
                reverse=True
            )[0].copy()
            base["id"] = str(uuid.uuid4())[:8]

            occurrences = _merge_occurrences(items)

            base["occurrences"]      = occurrences
            base["occurrence_count"] = len(occurrences)
            base["affected_urls"]    = [o["url"] for o in occurrences]
            base["affected_url"]     = occurrences[0]["url"] if occurrences else ""
            unique_findings.append(base)

        # Sort by severity
        # Sort by: 1) effective severity, 2) Gemini priority within same severity tier
        unique_findings.sort(key=lambda x: (
            SEVERITY_ORDER.get(
                (x.get("gemini_severity") or x.get("severity", "info")).lower(), 4
            ),
            x.get("priority", 999),
        ))

        # ── Phase 8: Gemini AI Analysis ───────────────────────────────────────
        emit(f"Phase 8/8 — Gemini AI deep analysis of {len(unique_findings)} findings...")
        try:
            enhanced = self.analyzer.analyze(unique_findings, target_url, progress_callback=emit)
        except Exception as e:
            emit(f"  Gemini analysis error: {e} — using raw findings")
            enhanced = {"summary": {}, "findings": unique_findings}

        # ── Build final report ────────────────────────────────────────────────
        finished_at = datetime.datetime.utcnow().isoformat() + "Z"
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in unique_findings:
            sev = (f.get("gemini_severity") or f.get("severity", "info")).lower()
            if sev not in severity_counts:
                sev = "info"
            severity_counts[sev] += 1

        report_data = {
            "scan_id": scan_id,
            "target_url": target_url,
            "started_at": started_at,
            "finished_at": finished_at,
            "pages_crawled": len(pages),
            "total_findings": len(unique_findings),
            "severity_counts": severity_counts,
            "summary": enhanced.get("summary", {}),
            "findings": unique_findings,
            "gemini_insights": enhanced.get("findings", []),
        }

        report_paths = generate_report(report_data, scan_id)
        report_data["report_json"] = report_paths["json"]
        report_data["report_html"] = report_paths["html"]

        emit(f"Scan complete — {len(unique_findings)} finding(s) | Report: {report_paths['json']}")
        return report_data
