"""
Hourly Scheduler
Runs a full security scan every hour in a background thread.
"""
import threading
import schedule
import time
import logging
import json
from pathlib import Path

logger = logging.getLogger(__name__)
CONFIG_PATH = Path("config.json")

_scheduler_thread: threading.Thread = None
_stop_event = threading.Event()


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}


def _handle_autoscan_merge(new_report_data: dict, target_url: str) -> dict:
    from agent.reporter import REPORTS_DIR, generate_report_from_existing
    
    reports = []
    for f in REPORTS_DIR.glob("scan_*.json"):
        if f.name == Path(new_report_data.get("report_json", "")).name:
            continue
        try:
            with open(f, "r") as fp:
                data = json.load(fp)
            if data.get("target_url") == target_url:
                reports.append((f, data))
        except:
            pass
            
    if not reports:
        return new_report_data
        
    reports.sort(key=lambda x: x[1].get("started_at", ""), reverse=True)
    prev_file, prev_data = reports[0]
    
    prev_keys = set()
    for f in prev_data.get("findings", []):
        ftype = f.get("type", "")
        for occ in f.get("occurrences", [{"url": f.get("affected_url", "")}]):
            prev_keys.add(f"{ftype}:::{occ.get('url', '')}")
            
    new_findings_to_add = []
    has_new = False
    
    for f in new_report_data.get("findings", []):
        ftype = f.get("type", "")
        new_occs = []
        for occ in f.get("occurrences", [{"url": f.get("affected_url", "")}]):
            k = f"{ftype}:::{occ.get('url', '')}"
            if k not in prev_keys:
                new_occs.append(occ)
                
        if new_occs:
            has_new = True
            nf = f.copy()
            nf["occurrences"] = new_occs
            nf["occurrence_count"] = len(new_occs)
            nf["affected_url"] = new_occs[0]["url"] if new_occs else ""
            new_findings_to_add.append(nf)
            
    try:
        Path(new_report_data["report_json"]).unlink()
        Path(new_report_data["report_html"]).unlink()
    except: pass
    
    if not has_new:
        logger.info("Scheduler: No new errors found. Discarded new report.")
        prev_data["finished_at"] = new_report_data.get("finished_at", "")
        generate_report_from_existing(prev_data, prev_file)
        return prev_data
        
    prev_data["findings"].extend(new_findings_to_add)
    sc = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in prev_data["findings"]:
        sev = (f.get("gemini_severity") or f.get("severity", "info")).lower()
        if sev not in sc: sev = "info"
        sc[sev] += 1
        
    prev_data["severity_counts"] = sc
    prev_data["total_findings"] = len(prev_data["findings"])
    prev_data["finished_at"] = new_report_data.get("finished_at", "")
    
    generate_report_from_existing(prev_data, prev_file)
    logger.info("Scheduler: Merged new findings into existing history report.")
    
    # Expose the correct JSON/HTML paths back
    prev_data["report_json"] = str(prev_file)
    prev_data["report_html"] = str(prev_file.with_suffix(".html"))
    return prev_data


def _run_scheduled_scan(scanner_factory, broadcast_fn):
    """Called by schedule every hour. Creates a fresh scanner and runs it."""
    config = _load_config()
    target_url = config.get("target_url", "")
    if not target_url:
        logger.warning("Scheduler: No target URL configured, skipping scan.")
        return

    logger.info(f"Scheduler: Starting hourly scan of {target_url}")
    broadcast_fn({"type": "scheduler", "message": f"Hourly scan started for {target_url}"})

    try:
        scanner = scanner_factory()
        report = scanner.run(
            target_url=target_url,
            max_pages=config.get("max_pages", 30),
            crawl_delay=config.get("crawl_delay", 1.0),
            progress_callback=lambda msg: broadcast_fn({"type": "progress", "message": msg}),
        )
        
        # Intercept and optionally merge the autoscan report
        report = _handle_autoscan_merge(report, target_url)
        
        broadcast_fn({
            "type": "scan_complete",
            "scan_id": report.get("scan_id"),
            "total_findings": report.get("total_findings", 0),
            "severity_counts": report.get("severity_counts", {}),
            "report_json": report.get("report_json", ""),
            "report_html": report.get("report_html", ""),
        })
        logger.info(f"Scheduler: Hourly scan complete — {report.get('total_findings',0)} findings")
    except Exception as e:
        logger.error(f"Scheduler: Scan failed — {e}")
        broadcast_fn({"type": "error", "message": f"Hourly scan failed: {e}"})


def start_scheduler(scanner_factory, broadcast_fn):
    global _scheduler_thread, _stop_event
    _stop_event.clear()

    schedule.clear("hourly-scan")
    schedule.every(10).minutes.do(_run_scheduled_scan, scanner_factory, broadcast_fn).tag("hourly-scan")

    def loop():
        while not _stop_event.is_set():
            schedule.run_pending()
            time.sleep(30)

    _scheduler_thread = threading.Thread(target=loop, daemon=True, name="SecurityScheduler")
    _scheduler_thread.start()
    logger.info("Hourly scheduler started")


def stop_scheduler():
    global _stop_event
    _stop_event.set()
    schedule.clear("hourly-scan")
    logger.info("Hourly scheduler stopped")


def is_running() -> bool:
    return _scheduler_thread is not None and _scheduler_thread.is_alive()
