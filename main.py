"""
Buyhatke Security Scanner — FastAPI Server
Serves the UI dashboard, manages scan lifecycle, WebSocket real-time updates,
and controls the hourly auto-scan scheduler.
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles

from sockets.manager import manager
from api.routes import router as api_router
from api.routes import load_config, _make_scanner
from agent import scheduler as sched

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("main")

# ── Lifespan (replaces deprecated on_event) ─────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    manager.set_loop(asyncio.get_running_loop())
    cfg = load_config()
    if cfg.get("hourly_scan_enabled"):
        sched.start_scheduler(_make_scanner, manager.sync_broadcast)
        logger.info("Hourly scheduler auto-started from config")
    yield
    sched.stop_scheduler()


# ── FastAPI app ─────────────────────────────────────────────────────────────

app = FastAPI(title="Buyhatke Security Scanner", version="1.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="ui/static"), name="static")

# ── Includes ────────────────────────────────────────────────────────────────

app.include_router(api_router)


# ── WebSockets ──────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        from api.routes import scan_state
        await websocket.send_json({
            "type": "connected",
            "running": scan_state["running"],
            "scan_id": scan_state["scan_id"],
            "scheduler_running": sched.is_running(),
        })
        while True:
            await websocket.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
