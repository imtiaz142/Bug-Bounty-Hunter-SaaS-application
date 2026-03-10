from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import json
import logging
import os

from app.core.config import get_settings
from app.core.database import init_db
from app.api.v1 import auth, scans, findings, agents, reports, recon, settings as settings_router

logger = logging.getLogger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(auth.router, prefix=f"{settings.API_V1_PREFIX}/auth", tags=["auth"])
app.include_router(scans.router, prefix=f"{settings.API_V1_PREFIX}/scans", tags=["scans"])
app.include_router(findings.router, prefix=f"{settings.API_V1_PREFIX}/scans/{{scan_id}}/findings", tags=["findings"])
app.include_router(agents.router, prefix=f"{settings.API_V1_PREFIX}/scans/{{scan_id}}/agents", tags=["agents"])
app.include_router(reports.router, prefix=f"{settings.API_V1_PREFIX}/scans/{{scan_id}}/report", tags=["reports"])
app.include_router(recon.router, prefix=f"{settings.API_V1_PREFIX}/scans/{{scan_id}}/recon", tags=["recon"])
app.include_router(settings_router.router, prefix=f"{settings.API_V1_PREFIX}/settings", tags=["settings"])


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "version": settings.VERSION}


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = []
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id] = [
                ws for ws in self.active_connections[scan_id] if ws != websocket
            ]
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            dead = []
            for ws in self.active_connections[scan_id]:
                try:
                    await ws.send_json(message)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(ws, scan_id)


manager = ConnectionManager()


@app.websocket(f"{settings.API_V1_PREFIX}/scans/{{scan_id}}/live")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await manager.connect(websocket, scan_id)

    # Redis is optional for local dev
    redis_client = None
    pubsub = None
    if settings.REDIS_URL:
        try:
            import redis.asyncio as aioredis
            redis_client = aioredis.from_url(settings.REDIS_URL)
            pubsub = redis_client.pubsub()
            await pubsub.subscribe(f"scan:{scan_id}")
        except Exception:
            logger.warning("Redis unavailable; WebSocket will only support ping/pong")
            redis_client = None
            pubsub = None

    try:
        import asyncio

        async def listen_redis():
            if pubsub is None:
                # No Redis — just sleep forever so gather doesn't exit
                while True:
                    await asyncio.sleep(60)
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    await manager.broadcast(scan_id, data)

        async def listen_ws():
            while True:
                try:
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break

        await asyncio.gather(listen_redis(), listen_ws(), return_exceptions=True)
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, scan_id)
        if pubsub:
            await pubsub.unsubscribe(f"scan:{scan_id}")
        if redis_client:
            await redis_client.close()
