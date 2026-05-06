from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uuid
import os
from collections import deque
import logging
import time
from typing import Dict, List, Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetCopServer")

app = FastAPI(title="NetCop Server")

API_KEY = os.environ.get("NETCOP_API_KEY", "secret")

@app.middleware("http")
async def verify_api_key_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        key = request.headers.get("X-NetCop-Key")
        if key != API_KEY:
            return JSONResponse(status_code=403, content={"detail": "Invalid API Key"})
    response = await call_next(request)
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# State
agents_state: Dict[str, Any] = {}
command_queue: Dict[str, List[Dict[str, Any]]] = {}
limits_state: Dict[str, Any] = {} # keep track of current limits visually
traffic_history: Dict[str, deque] = {}
process_limits_state: Dict[str, Dict[str, int]] = {}

PROCESS_CATEGORIES = {
    "qbittorrent.exe": "torrent", "utorrent.exe": "torrent", "tixati.exe": "torrent",
    "transmission-qt.exe": "torrent", "deluge.exe": "torrent", "bittorrent.exe": "torrent",
    "steam.exe": "gaming", "steamwebhelper.exe": "gaming", "epicgameslauncher.exe": "gaming", "battle.net.exe": "gaming",
    "obs64.exe": "streaming", "obs32.exe": "streaming", "streamlabs.exe": "streaming",
    "chrome.exe": "web", "firefox.exe": "web", "msedge.exe": "web", "browser.exe": "web",
    "svchost.exe": "system", "searchhost.exe": "system", "msmpeng.exe": "system"
}
DEFAULT_CATEGORY = "other"

class ReportPayload(BaseModel):
    hostname: str
    ip: str
    mac: str
    traffic_in_bps: float
    traffic_out_bps: float
    top_processes: List[Dict[str, Any]]
    
class LimitPayload(BaseModel):
    speed_mbps: int

class ProcessLimitPayload(BaseModel):
    exe_name: str
    speed_mbps: int

class ProcessUnlimitPayload(BaseModel):
    exe_name: str

@app.post("/api/report")
async def receive_report(payload: ReportPayload):
    hostname = payload.hostname
    if hostname not in agents_state:
        logger.info(f"New agent connected: {hostname} ({payload.ip})")
        
    agents_state[hostname] = {
        "last_seen": time.time(),
        "ip": payload.ip,
        "mac": payload.mac,
        "traffic_in_bps": payload.traffic_in_bps,
        "traffic_out_bps": payload.traffic_out_bps,
        "top_processes": payload.top_processes,
        "limit_mbps": limits_state.get(hostname, None),
        "status": "online"
    }
    if hostname not in command_queue:
        command_queue[hostname] = []
        
    if hostname not in traffic_history:
        traffic_history[hostname] = deque(maxlen=600)
    traffic_history[hostname].append({
        "t": time.time(),
        "in": payload.traffic_in_bps,
        "out": payload.traffic_out_bps
    })
    
    return {"status": "ok"}

@app.get("/api/status")
async def get_status():
    current_time = time.time()
    for hostname, state in agents_state.items():
        if current_time - state["last_seen"] > 15:
            state["status"] = "offline"
        else:
            state["status"] = "online"
        state["limit_mbps"] = limits_state.get(hostname, None)
        state["process_limits"] = process_limits_state.get(hostname, {})
        
        for p in state.get("top_processes", []):
            exe_name = p.get("name", "").lower()
            if "exe" in p and p["exe"]:
                exe_name = os.path.basename(p["exe"]).lower()
            p["category"] = PROCESS_CATEGORIES.get(exe_name, DEFAULT_CATEGORY)
            
    return {"agents": agents_state}

@app.get("/api/commands/{hostname}")
async def get_commands(hostname: str):
    if hostname in command_queue and len(command_queue[hostname]) > 0:
        cmds = command_queue[hostname]
        command_queue[hostname] = [] # Clear after sending
        return {"commands": cmds}
    return {"commands": []}

@app.post("/api/limit/{hostname}")
async def set_limit(hostname: str, payload: LimitPayload):
    logger.info(f"Command: global limit {hostname} to {payload.speed_mbps} Mbps")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "limit",
        "payload": {"speed_mbps": payload.speed_mbps}
    })
    limits_state[hostname] = payload.speed_mbps
    return {"status": "enqueued"}

@app.post("/api/unlimit/{hostname}")
async def unset_limit(hostname: str):
    logger.info(f"Command: global unlimit {hostname}")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unlimit",
        "payload": {}
    })
    limits_state[hostname] = None
    return {"status": "enqueued"}

@app.post("/api/kill/{hostname}")
async def kill_network(hostname: str):
    logger.warning(f"Command: KILL NETWORK on {hostname}")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "kill",
        "payload": {}
    })
    return {"status": "enqueued"}

# Mount static files at the end
@app.get("/api/history/{hostname}")
async def get_history(hostname: str):
    history = list(traffic_history.get(hostname, []))
    return {"history": history}

@app.post("/api/limit_process/{hostname}")
async def set_process_limit(hostname: str, payload: ProcessLimitPayload):
    if not payload.exe_name or payload.speed_mbps <= 0:
        return JSONResponse(status_code=400, content={"detail": "Invalid limit payload"})
        
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "limit_process",
        "payload": {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps}
    })
    
    if hostname not in process_limits_state:
        process_limits_state[hostname] = {}
    process_limits_state[hostname][payload.exe_name] = payload.speed_mbps
    return {"status": "enqueued"}

@app.post("/api/unlimit_process/{hostname}")
async def unset_process_limit(hostname: str, payload: ProcessUnlimitPayload):
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unlimit_process",
        "payload": {"exe_name": payload.exe_name}
    })
    
    if hostname in process_limits_state and payload.exe_name in process_limits_state[hostname]:
        del process_limits_state[hostname][payload.exe_name]
        
    return {"status": "enqueued"}

@app.post("/api/shape_process/{hostname}")
async def shape_process_limit(hostname: str, payload: ProcessLimitPayload):
    if not payload.exe_name or payload.speed_mbps <= 0:
        return JSONResponse(status_code=400, content={"detail": "Invalid limit payload"})
        
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "shape_process",
        "payload": {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps}
    })
    return {"status": "enqueued"}

@app.post("/api/unshape_process/{hostname}")
async def unshape_process_limit(hostname: str, payload: ProcessUnlimitPayload):
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unshape_process",
        "payload": {"exe_name": payload.exe_name}
    })
    return {"status": "enqueued"}

@app.post("/api/full_throttle/{hostname}")
async def full_throttle(hostname: str, payload: ProcessLimitPayload):
    logger.info(f"Command: full_throttle {payload.exe_name} to {payload.speed_mbps} Mbps on {hostname}")
    if not payload.exe_name or payload.speed_mbps <= 0:
        return JSONResponse(status_code=400, content={"detail": "Invalid limit payload"})
        
    if hostname not in command_queue:
        command_queue[hostname] = []
    
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "limit_process",
        "payload": {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps}
    })
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "shape_process",
        "payload": {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps}
    })
    
    if hostname not in process_limits_state:
        process_limits_state[hostname] = {}
    process_limits_state[hostname][payload.exe_name] = payload.speed_mbps
    return {"status": "enqueued"}

@app.post("/api/full_unthrottle/{hostname}")
async def full_unthrottle(hostname: str, payload: ProcessUnlimitPayload):
    logger.info(f"Command: full_unthrottle {payload.exe_name} on {hostname}")
    if hostname not in command_queue:
        command_queue[hostname] = []
        
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unlimit_process",
        "payload": {"exe_name": payload.exe_name}
    })
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unshape_process",
        "payload": {"exe_name": payload.exe_name}
    })
    
    if hostname in process_limits_state and payload.exe_name in process_limits_state[hostname]:
        del process_limits_state[hostname][payload.exe_name]
        
    return {"status": "enqueued"}

static_dir = os.environ.get('STATIC_DIR', os.path.join(os.path.dirname(__file__), "static"))
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
