import asyncio
import json
import logging
from typing import List, Optional
from fastapi import WebSocket

logger = logging.getLogger("sockets.manager")

class ConnectionManager:
    def __init__(self):
        self.active_ws: List[WebSocket] = []
        self._main_loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._main_loop = loop

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_ws.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_ws:
            self.active_ws.remove(websocket)

    async def broadcast(self, payload: dict):
        msg = json.dumps(payload)
        dead = []
        for ws in list(self.active_ws):
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def sync_broadcast(self, payload: dict):
        """Thread-safe broadcast from background threads using the captured main loop."""
        if self._main_loop and self._main_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(payload), self._main_loop)
        else:
            logger.debug("sync_broadcast: no running loop yet, dropping message")

manager = ConnectionManager()
