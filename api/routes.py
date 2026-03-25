import asyncio
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status
from pydantic import BaseModel
from services.firebase_service import firebase_db
from services.firewall_manager import firewall
from detection.decision_engine import decision_engine
from utils.validators import is_valid_ipv4, sanitize_input

router = APIRouter()

# Global Connected WebSocket Clients
active_clients: List[WebSocket] = []

class BlockRequest(BaseModel):
    ip: str
    reason: str = "Manual Block via Dashboard"

@router.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_clients.append(websocket)
    try:
        while True:
            # We don't expect messages from client, but keep conn alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_clients.remove(websocket)

async def broadcast_log(log_data: dict):
    """Pushes new logs to all connected WebSocket clients"""
    disconnected = []
    for client in active_clients:
        try:
            await client.send_json(log_data)
        except Exception:
            disconnected.append(client)
    
    for client in disconnected:
        if client in active_clients:
            active_clients.remove(client)

@router.get("/api/blocked", summary="Get all blocked IPs")
async def get_blocked_ips():
    try:
        ips = firebase_db.get_all_blocked_ips()
        return {"status": "success", "blocked_ips": ips}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/block", summary="Manually block an IP")
async def manual_block(req: BlockRequest):
    if not is_valid_ipv4(req.ip):
        raise HTTPException(status_code=400, detail="Invalid IPv4 format")
        
    reason = sanitize_input(req.reason)
    
    success = firewall.block_ip(req.ip)
    if success:
        firebase_db.add_blocked_ip(req.ip, reason, 1.0)
        # Add to memory cache
        decision_engine.sync_blocked_list([req.ip])
        return {"status": "success", "message": f"IP {req.ip} blocked"}
        
    raise HTTPException(status_code=500, detail="Failed to apply firewall rule")

@router.delete("/api/unblock/{ip}", summary="Unblock an IP")
async def unblock_ip(ip: str):
    if not is_valid_ipv4(ip):
        raise HTTPException(status_code=400, detail="Invalid IPv4 format")
        
    success = firewall.unblock_ip(ip)
    if success:
        firebase_db.remove_blocked_ip(ip)
        # Remove from memory cache
        if ip in decision_engine.blocked_ips:
            decision_engine.blocked_ips.remove(ip)
        return {"status": "success", "message": f"IP {ip} unblocked"}
        
    raise HTTPException(status_code=500, detail="Failed to remove firewall rule")

@router.get("/api/stats", summary="Get dashboard summary stats")
async def get_stats():
    # In a full prod setup, these would come from Firebase aggregate queries.
    # For speed, we return the counts based on in-memory and basic queries.
    blocked_count = len(decision_engine.blocked_ips)
    
    return {
        "status": "success",
        "data": {
            "total_blocked": blocked_count,
            "engine_status": "Active"
        }
    }
