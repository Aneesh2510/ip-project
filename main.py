import asyncio
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from config import settings
from utils.logger import system_logger
from capture.packet_capture import packet_queue, capture_service
from detection.decision_engine import decision_engine
from services.firebase_service import firebase_db
from api.routes import router, broadcast_log

# Traffic processing background task
async def process_traffic_queue():
    system_logger.info("Traffic processing background task started.")
    while True:
        try:
            # Non-blocking get from queue with short sleep
            if not packet_queue.empty():
                packet_data = packet_queue.get_nowait()
                ip = packet_data["ip"]
                features = packet_data["features"]
                stats = packet_data["stats"]
                
                # Check for threats and block if necessary
                decision_engine.evaluate_traffic(ip, features, stats)
                
                # Broadcast live state to UI
                await broadcast_log({
                    "ip": ip,
                    "req_count": stats.get("req_count", 0),
                    "blocked": ip in decision_engine.blocked_ips,
                    "timestamp": packet_data["timestamp"]
                })
                
                packet_queue.task_done()
            else:
                await asyncio.sleep(0.1) # Prevents CPU burning when queue empty
                
        except asyncio.CancelledError:
            break
        except Exception as e:
            system_logger.error(f"Error in traffic processor: {e}")
            await asyncio.sleep(1)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    system_logger.info("Initializing IP Tracking System...")
    
    # Pre-warm: Sync existing blocked IPs from DB
    blocked_ips = firebase_db.get_all_blocked_ips()
    decision_engine.sync_blocked_list(blocked_ips)
    system_logger.info(f"Loaded {len(blocked_ips)} previously blocked IPs from DB.")
    
    # Start packet sniffer in background thread (Scapy blocks otherwise)
    threading.Thread(target=capture_service.start, daemon=True).start()
    
    # Start asyncio background task to drain the queue and evaluate traffic
    task = asyncio.create_task(process_traffic_queue())
    
    yield
    
    # SHUTDOWN
    system_logger.info("Shutting down system...")
    capture_service.stop()
    task.cancel()
    
app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (allow local dashboard access)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
app.include_router(router)

# Basic Rate Limiting Middleware (Hardcoded 100 req/sec for demonstration logic protection)
from fastapi import HTTPException
import time
from collections import defaultdict

# Simple token bucket per IP for API endpoints
RATE_LIMIT = 100
api_rate_buckets = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        client_ip = request.client.host
        now = time.time()
        
        # Clean old tokens (> 1 minute old)
        api_rate_buckets[client_ip] = [t for t in api_rate_buckets[client_ip] if now - t < 60]
        
        if len(api_rate_buckets[client_ip]) >= RATE_LIMIT:
            system_logger.warning(f"API Rate limit hit by {client_ip}")
            # Also block them automatically if they hit API rate limit aggressively
            # decision_engine._block_ip(client_ip, "API Brute Force Rate Limit", 1.0)
            return HTMLResponse(status_code=429, content="Too many requests")
            
        api_rate_buckets[client_ip].append(now)
        
    return await call_next(request)

# Note: Static files should be mounted LAST
import os
frontend_dir = os.path.join(settings.BASE_DIR, "frontend")

if os.path.exists(frontend_dir):
    # Explicitly serve the main SPA file on the root path to prevent any directory listing or 404
    @app.get("/", include_in_schema=False)
    async def serve_spa():
        return FileResponse(os.path.join(frontend_dir, "index.html"))
        
    # Mount the rest of the frontend directory (like css/ and js/)
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

if __name__ == "__main__":
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
