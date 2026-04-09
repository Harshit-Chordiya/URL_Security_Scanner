import os
import json
import logging
import threading
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from fastapi.requests import Request
from fastapi.templating import Jinja2Templates

from sockets.manager import manager
from agent import scheduler as sched

logger = logging.getLogger("api.routes")
router = APIRouter()

CONFIG_PATH = Path("config.json")
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)
templates = Jinja2Templates(directory="ui/templates")

scan_state = {
    "running": False,
    "scan_id": None,
    "last_report": None,
}
_scan_lock = threading.Lock()

def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {"target_url": "", "max_pages": 30, "crawl_delay": 1.0, "hourly_scan_enabled": False}

def save_config(cfg: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)

def _make_scanner():
    from agent.scanner import SecurityScanner
    api_key = os.getenv("GEMINI_API_KEY", "")
    model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite-preview")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not set in .env")
    return SecurityScanner(api_key, model)

def _run_scan_thread(target_url: str, max_pages: int, crawl_delay: float):
    with _scan_lock:
        scan_state["running"] = True
        scan_state["last_report"] = None

    manager.sync_broadcast({"type": "scan_started", "target_url": target_url})

    try:
        scanner = _make_scanner()
        report = scanner.run(
            target_url=target_url,
            max_pages=max_pages,
            crawl_delay=crawl_delay,
            progress_callback=lambda msg: manager.sync_broadcast({"type": "progress", "message": msg}),
        )
        with _scan_lock:
            scan_state["running"] = False
            scan_state["scan_id"] = report.get("scan_id")
            scan_state["last_report"] = report

        cfg = load_config()
        cfg["last_scan"] = report.get("finished_at")
        save_config(cfg)

        manager.sync_broadcast({
            "type": "scan_complete",
            "scan_id": report.get("scan_id"),
            "total_findings": report.get("total_findings", 0),
            "severity_counts": report.get("severity_counts", {}),
            "summary": report.get("summary", {}),
            "report_json": report.get("report_json", ""),
            "report_html": report.get("report_html", ""),
            "findings": report.get("findings", []),
        })

    except Exception as e:
        logger.error(f"Scan error: {e}")
        with _scan_lock:
            scan_state["running"] = False
        manager.sync_broadcast({"type": "error", "message": str(e)})

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/api/config")
async def get_config():
    return load_config()

class ConfigUpdate(BaseModel):
    target_url: str = None
    max_pages: int = None
    crawl_delay: float = None
    hourly_scan_enabled: bool = None

@router.post("/api/config")
async def update_config(body: ConfigUpdate):
    cfg = load_config()
    if body.target_url is not None:
        cfg["target_url"] = body.target_url.strip().rstrip("/")
    if body.max_pages is not None:
        cfg["max_pages"] = max(5, min(body.max_pages, 100))
    if body.crawl_delay is not None:
        cfg["crawl_delay"] = max(0.3, min(body.crawl_delay, 5.0))
    if body.hourly_scan_enabled is not None:
        cfg["hourly_scan_enabled"] = body.hourly_scan_enabled
        if body.hourly_scan_enabled:
            sched.start_scheduler(_make_scanner, manager.sync_broadcast)
        else:
            sched.stop_scheduler()
    save_config(cfg)
    return {"status": "ok", "config": cfg}

@router.post("/api/scan/start")
async def start_scan():
    if scan_state["running"]:
        raise HTTPException(status_code=409, detail="A scan is already running")
    cfg = load_config()
    target = cfg.get("target_url", "")
    if not target:
        raise HTTPException(status_code=400, detail="No target URL configured")

    t = threading.Thread(
        target=_run_scan_thread,
        args=(target, cfg.get("max_pages", 30), cfg.get("crawl_delay", 1.0)),
        daemon=True,
        name="ScanThread",
    )
    t.start()
    return {"status": "started", "target_url": target}

@router.get("/api/scan/status")
async def scan_status():
    return {
        "running": scan_state["running"],
        "scan_id": scan_state["scan_id"],
        "scheduler_running": sched.is_running(),
    }

@router.get("/api/reports")
async def list_reports():
    reports = []
    for f in REPORTS_DIR.glob("scan_*.json"):
        try:
            with open(f, "r") as fp:
                data = json.load(fp)
            reports.append({
                "file": f.name,
                "scan_id": data.get("scan_id"),
                "target_url": data.get("target_url"),
                "started_at": data.get("started_at", ""),
                "finished_at": data.get("finished_at", ""),
                "total_findings": data.get("total_findings", 0),
                "severity_counts": data.get("severity_counts", {}),
                "overall_risk": data.get("summary", {}).get("overall_risk", "—"),
            })
        except Exception:
            continue
    reports.sort(key=lambda r: r["started_at"], reverse=True)
    return reports[:20]

@router.get("/api/reports/{filename}")
async def get_report(filename: str):
    path = REPORTS_DIR / filename
    if not path.exists() or not filename.endswith(".json"):
        raise HTTPException(status_code=404, detail="Report not found")
    with open(path, "r") as f:
        return json.load(f)

@router.get("/api/reports/{filename}/html")
async def get_report_html(filename: str):
    html_name = filename.replace(".json", ".html")
    path = REPORTS_DIR / html_name
    if not path.exists():
        raise HTTPException(status_code=404, detail="HTML report not found")
    return FileResponse(path, media_type="text/html")

@router.delete("/api/reports/{filename}")
async def delete_report(filename: str):
    path = REPORTS_DIR / Path(filename).name
    if not path.exists() or not filename.endswith(".json"):
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        path.unlink()
        html_path = REPORTS_DIR / filename.replace(".json", ".html")
        if html_path.exists():
            html_path.unlink()
        return {"status": "deleted"}
    except Exception as e:
        logger.error(f"Error deleting report {filename}: {e}")
        raise HTTPException(status_code=500, detail="Could not delete files")
