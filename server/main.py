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
import sqlite3
import json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("NetCopServer")

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

def load_or_generate_config():
    import secrets
    config_data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config_data = json.load(f)
        except:
            pass
            
    api_key = os.environ.get("NETCOP_API_KEY", config_data.get("api_key"))
    
    if not api_key or api_key == "secret" or len(api_key) < 16:
        api_key = secrets.token_urlsafe(32)
        print("============================================")
        print("NEW API KEY GENERATED:")
        print(api_key)
        print("Save this key — you will need it for agents.")
        print("============================================")
    
    config_data["api_key"] = api_key
    config_data["host"] = config_data.get("host", "127.0.0.1")
    config_data["port"] = config_data.get("port", 8000)
    if "priority_profile" not in config_data:
        config_data["priority_profile"] = {
            "torrent": {"in_kbps": 128, "out_kbps": 64},
            "gaming": {"in_kbps": 256, "out_kbps": 128},
            "streaming": {"in_kbps": 256, "out_kbps": 128}
        }
        
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config_data, f, indent=4)
    except Exception as e:
        print(f"Warning: Could not save config.json: {e}")
        
    return config_data

config = load_or_generate_config()
API_KEY = os.environ.get("NETCOP_API_KEY", config.get("api_key"))

if API_KEY == "secret" or len(API_KEY) < 16:
    print("ERROR: Insecure API key detected. Please use a key of at least 16 characters.")
    import sys
    sys.exit(1)

DB_FILE = os.path.join(os.path.dirname(__file__), "netcop.db")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS state
                 (key TEXT PRIMARY KEY, value TEXT)''')
    # TODO: log rotation/retention policy for audit_log to prevent DB bloat
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp REAL NOT NULL,
                 hostname TEXT NOT NULL,
                 action TEXT NOT NULL,
                 target TEXT,
                 params TEXT,
                 source_ip TEXT)''')
    conn.commit()
    conn.close()

def log_audit(hostname, action, target, params, source_ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (timestamp, hostname, action, target, params, source_ip) VALUES (?, ?, ?, ?, ?, ?)",
              (time.time(), hostname, action, target, params, source_ip))
    conn.commit()
    conn.close()

def load_state(key, default):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT value FROM state WHERE key=?", (key,))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return default

def save_state(key, value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("REPLACE INTO state (key, value) VALUES (?, ?)", (key, json.dumps(value)))
    conn.commit()
    conn.close()

init_db()

app = FastAPI(title="NetCop Server")

@app.middleware("http")
async def verify_api_key_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        key = request.headers.get("X-NetCop-Key")
        if key != API_KEY:
            logger.warning(f"Auth failed from {request.client.host} - invalid API key")
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
limits_state: Dict[str, Any] = load_state('limits_state', {}) # keep track of current limits visually
traffic_history: Dict[str, deque] = {}
process_limits_state: Dict[str, Dict[str, int]] = load_state('process_limits_state', {})
priority_mode_active = load_state('priority_mode_active', False)
priority_mode_limits = load_state('priority_mode_limits', {})
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
    speed_mbps: float

class ProcessLimitPayload(BaseModel):
    exe_name: str
    speed_mbps: float

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
        
    if priority_mode_active:
        priority_profile = config.get("priority_profile", {})
        if hostname not in priority_mode_limits:
            priority_mode_limits[hostname] = []
            
        for p in payload.top_processes:
            exe_name = p.get("name", "").lower()
            if "exe" in p and p["exe"]:
                exe_name = os.path.basename(p["exe"]).lower()
            
            if exe_name not in priority_mode_limits[hostname]:
                cat = PROCESS_CATEGORIES.get(exe_name, DEFAULT_CATEGORY)
                if cat in priority_profile:
                    speed_mbps = float(priority_profile[cat].get("out_kbps", 128)) / 1000.0
                    current_limit = process_limits_state.get(hostname, {}).get(exe_name)
                    
                    if current_limit is None or current_limit > speed_mbps:
                        command_queue[hostname].append({
                            "id": str(uuid.uuid4()),
                            "type": "limit_process",
                            "payload": {"exe_name": exe_name, "speed_mbps": speed_mbps}
                        })
                        command_queue[hostname].append({
                            "id": str(uuid.uuid4()),
                            "type": "shape_process",
                            "payload": {"exe_name": exe_name, "speed_mbps": speed_mbps}
                        })
                        priority_mode_limits[hostname].append(exe_name)
                        save_state('priority_mode_limits', priority_mode_limits)
                        log_audit(hostname, "priority_mode_auto_apply", exe_name, f"{speed_mbps} Mbps", payload.ip)
        
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
    return {
        "agents": agents_state,
        "priority_mode": priority_mode_active
    }

@app.get("/api/commands/{hostname}")
async def get_commands(hostname: str):
    if hostname in command_queue and len(command_queue[hostname]) > 0:
        cmds = command_queue[hostname]
        command_queue[hostname] = [] # Clear after sending
        return {"commands": cmds}
    return {"commands": []}

@app.post("/api/limit/{hostname}")
async def set_limit(hostname: str, payload: LimitPayload, request: Request):
    logger.info(f"Command: global limit {hostname} to {payload.speed_mbps} Mbps")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "limit",
        "payload": {"speed_mbps": payload.speed_mbps}
    })
    limits_state[hostname] = payload.speed_mbps
    save_state('limits_state', limits_state)
    log_audit(hostname, "limit", "global", f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}

@app.post("/api/unlimit/{hostname}")
async def unset_limit(hostname: str, request: Request):
    logger.info(f"Command: global unlimit {hostname}")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unlimit",
        "payload": {}
    })
    limits_state[hostname] = None
    save_state('limits_state', limits_state)
    log_audit(hostname, "unlimit", "global", "", request.client.host)
    return {"status": "enqueued"}

@app.post("/api/kill/{hostname}")
async def kill_network(hostname: str, request: Request):
    logger.warning(f"Command: KILL NETWORK on {hostname}")
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "kill",
        "payload": {}
    })
    log_audit(hostname, "kill", "network", "", request.client.host)
    return {"status": "enqueued"}

# Mount static files at the end
@app.get("/api/history/{hostname}")
async def get_history(hostname: str):
    history = list(traffic_history.get(hostname, []))
    return {"history": history}

@app.post("/api/limit_process/{hostname}")
async def set_process_limit(hostname: str, payload: ProcessLimitPayload, request: Request):
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
    save_state('process_limits_state', process_limits_state)
    log_audit(hostname, "limit_process", payload.exe_name, f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}

@app.post("/api/unlimit_process/{hostname}")
async def unset_process_limit(hostname: str, payload: ProcessUnlimitPayload, request: Request):
    if hostname not in command_queue:
        command_queue[hostname] = []
    command_queue[hostname].append({
        "id": str(uuid.uuid4()),
        "type": "unlimit_process",
        "payload": {"exe_name": payload.exe_name}
    })
    
    if hostname in process_limits_state and payload.exe_name in process_limits_state[hostname]:
        del process_limits_state[hostname][payload.exe_name]
        save_state('process_limits_state', process_limits_state)
        
    log_audit(hostname, "unlimit_process", payload.exe_name, "", request.client.host)
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
async def full_throttle(hostname: str, payload: ProcessLimitPayload, request: Request):
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
    save_state('process_limits_state', process_limits_state)
    log_audit(hostname, "full_throttle", payload.exe_name, f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}

@app.post("/api/full_unthrottle/{hostname}")
async def full_unthrottle(hostname: str, payload: ProcessUnlimitPayload, request: Request):
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
        save_state('process_limits_state', process_limits_state)
        
    log_audit(hostname, "full_unthrottle", payload.exe_name, "", request.client.host)
    return {"status": "enqueued"}

@app.get("/api/audit")
async def get_audit(hostname: Optional[str] = None, limit: int = 50, offset: int = 0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    if hostname:
        c.execute("SELECT * FROM audit_log WHERE hostname=? ORDER BY timestamp DESC LIMIT ? OFFSET ?", (hostname, limit, offset))
    else:
        c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?", (limit, offset))
    
    rows = c.fetchall()
    conn.close()
    
    logs = []
    for row in rows:
        logs.append({
            "id": row[0],
            "timestamp": row[1],
            "hostname": row[2],
            "action": row[3],
            "target": row[4],
            "params": row[5],
            "source_ip": row[6]
        })
    return {"logs": logs}

@app.post("/api/priority_mode/on")
async def priority_mode_on(request: Request):
    global priority_mode_active
    if priority_mode_active:
        return {"status": "already active"}
        
    priority_profile = config.get("priority_profile", {})
    
    for hostname, state in agents_state.items():
        if hostname not in priority_mode_limits:
            priority_mode_limits[hostname] = []
            
        top_processes = state.get("top_processes", [])
        for p in top_processes:
            exe_name = p.get("name", "").lower()
            if "exe" in p and p["exe"]:
                exe_name = os.path.basename(p["exe"]).lower()
                
            cat = PROCESS_CATEGORIES.get(exe_name, DEFAULT_CATEGORY)
            if cat in priority_profile:
                speed_mbps = float(priority_profile[cat].get("out_kbps", 128)) / 1000.0
                
                current_limit = process_limits_state.get(hostname, {}).get(exe_name)
                if current_limit is not None and current_limit < speed_mbps:
                    continue 
                
                if hostname not in command_queue:
                    command_queue[hostname] = []
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "limit_process",
                    "payload": {"exe_name": exe_name, "speed_mbps": speed_mbps}
                })
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "shape_process",
                    "payload": {"exe_name": exe_name, "speed_mbps": speed_mbps}
                })
                
                priority_mode_limits[hostname].append(exe_name)
                log_audit(hostname, "priority_mode_apply", exe_name, f"{speed_mbps} Mbps", request.client.host)
                
    priority_mode_active = True
    save_state('priority_mode_active', True)
    save_state('priority_mode_limits', priority_mode_limits)
    log_audit("GLOBAL", "priority_mode", "ON", "", request.client.host)
    return {"status": "enqueued"}

@app.post("/api/priority_mode/off")
async def priority_mode_off(request: Request):
    global priority_mode_active
    if not priority_mode_active:
        return {"status": "already inactive"}
        
    for hostname, exes in priority_mode_limits.items():
        for exe_name in exes:
            original_limit = process_limits_state.get(hostname, {}).get(exe_name)
            if hostname not in command_queue:
                command_queue[hostname] = []
                
            if original_limit is not None:
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "limit_process",
                    "payload": {"exe_name": exe_name, "speed_mbps": original_limit}
                })
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "shape_process",
                    "payload": {"exe_name": exe_name, "speed_mbps": original_limit}
                })
                log_audit(hostname, "priority_mode_restore", exe_name, f"{original_limit} Mbps", request.client.host)
            else:
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "unlimit_process",
                    "payload": {"exe_name": exe_name}
                })
                command_queue[hostname].append({
                    "id": str(uuid.uuid4()),
                    "type": "unshape_process",
                    "payload": {"exe_name": exe_name}
                })
                log_audit(hostname, "priority_mode_restore", exe_name, "Unlimited", request.client.host)
            
    priority_mode_limits.clear()
    priority_mode_active = False
    save_state('priority_mode_active', False)
    save_state('priority_mode_limits', priority_mode_limits)
    log_audit("GLOBAL", "priority_mode", "OFF", "", request.client.host)
    return {"status": "enqueued"}

static_dir = os.environ.get('STATIC_DIR', os.path.join(os.path.dirname(__file__), "static"))
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
