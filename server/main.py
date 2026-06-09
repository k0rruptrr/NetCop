"""
NetCop server. Central brain + dashboard host.

Key properties:
  * Commands are delivered with at-least-once semantics: they stay in the
    queue until the agent ACKs the specific command IDs it ran. A dropped
    HTTP response no longer silently loses a command. Commands are written
    to be idempotent, so a rare double-delivery is harmless.
  * Network kill is paired with unkill, and the agent also self-restores on
    a watchdog, so a kill can't strand a machine.
  * API auth uses a constant-time comparison. CORS is locked to explicit
    origins (a credentialed "*" is rejected by browsers anyway).
  * SQLite writes go through a single background thread, so request handlers
    never block the event loop on disk I/O.
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uuid
import os
import secrets
import queue
import threading
import sqlite3
import json
import time
import logging
from collections import deque
from typing import Dict, List, Any, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("NetCopServer")

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
DB_FILE = os.path.join(os.path.dirname(__file__), "netcop.db")

OFFLINE_AFTER = 15          # seconds without a report -> "offline"
COMMAND_TTL = 60            # unacked commands expire after this many seconds
HISTORY_POINTS = 600        # ~30 min at 3s cadence


# ----------------------------------------------------------------------------
# Config / key handling
# ----------------------------------------------------------------------------

def load_or_generate_config():
    data = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                data = json.load(f)
        except Exception:
            pass

    api_key = os.environ.get("NETCOP_API_KEY", data.get("api_key"))
    if not api_key or api_key == "secret" or len(api_key) < 16:
        api_key = secrets.token_urlsafe(32)
        print("=" * 44)
        print("NEW API KEY GENERATED:")
        print(api_key)
        print("Save this key — you will need it for agents.")
        print("=" * 44)

    data["api_key"] = api_key
    data.setdefault("host", "127.0.0.1")
    data.setdefault("port", 8000)
    data.setdefault("allowed_origins", [])  # e.g. ["http://192.168.1.100:8000"]
    if "priority_profile" not in data:
        data["priority_profile"] = {
            "torrent": {"in_kbps": 128, "out_kbps": 64},
            "gaming": {"in_kbps": 256, "out_kbps": 128},
            "streaming": {"in_kbps": 256, "out_kbps": 128},
        }

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Warning: could not save config.json: {e}")
    return data


config = load_or_generate_config()
API_KEY = os.environ.get("NETCOP_API_KEY", config.get("api_key"))

if API_KEY == "secret" or len(API_KEY) < 16:
    print("ERROR: insecure API key. Use at least 16 characters.")
    import sys
    sys.exit(1)


# ----------------------------------------------------------------------------
# SQLite via a single writer thread (keeps disk I/O off the event loop)
# ----------------------------------------------------------------------------

_db_write_q: "queue.Queue" = queue.Queue()


def _init_schema():
    """Create tables synchronously, before any read/write happens. Doing
    this inside the writer thread caused a race: load_state() could read
    the 'state' table before the thread created it."""
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)")
        c.execute(
            """CREATE TABLE IF NOT EXISTS audit_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   timestamp REAL NOT NULL,
                   hostname TEXT NOT NULL,
                   action TEXT NOT NULL,
                   target TEXT, params TEXT, source_ip TEXT)"""
        )
        conn.commit()
    finally:
        conn.close()


_init_schema()


def _db_writer():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    while True:
        job = _db_write_q.get()
        if job is None:
            break
        sql, params = job
        try:
            c.execute(sql, params)
            conn.commit()
        except Exception as e:
            logger.error("DB write failed: %s", e)
    conn.close()


_writer_thread = threading.Thread(target=_db_writer, daemon=True)
_writer_thread.start()


def _db_read(sql, params=()):
    """Reads use a short-lived connection; reads are rare (audit view) and
    don't need to share the writer's connection."""
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute(sql, params)
        return c.fetchall()
    finally:
        conn.close()


def log_audit(hostname, action, target, params, source_ip):
    _db_write_q.put((
        "INSERT INTO audit_log (timestamp, hostname, action, target, params, source_ip)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (time.time(), hostname, action, target, params, source_ip),
    ))


def load_state(key, default):
    rows = _db_read("SELECT value FROM state WHERE key=?", (key,))
    if rows:
        try:
            return json.loads(rows[0][0])
        except Exception:
            return default
    return default


def save_state(key, value):
    _db_write_q.put(("REPLACE INTO state (key, value) VALUES (?, ?)", (key, json.dumps(value))))


# ----------------------------------------------------------------------------
# App + middleware
# ----------------------------------------------------------------------------

app = FastAPI(title="NetCop Server")


@app.middleware("http")
async def verify_api_key(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        key = request.headers.get("X-NetCop-Key", "")
        # Constant-time compare to avoid leaking the key via timing.
        if not secrets.compare_digest(key, API_KEY):
            logger.warning("Auth failed from %s", request.client.host)
            return JSONResponse(status_code=403, content={"detail": "Invalid API Key"})
    return await call_next(request)


# A credentialed wildcard is invalid and browsers drop it. Use explicit
# origins from config; if none given, fall back to no-credential wildcard
# (fine here because auth is via header, not cookies).
_origins = config.get("allowed_origins") or []
if _origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# ----------------------------------------------------------------------------
# In-memory state
# ----------------------------------------------------------------------------

agents_state: Dict[str, Any] = {}
# command_queue[host] = list of {id, type, payload, _ts}
command_queue: Dict[str, List[Dict[str, Any]]] = {}
limits_state: Dict[str, Any] = load_state("limits_state", {})
traffic_history: Dict[str, deque] = {}
process_limits_state: Dict[str, Dict[str, float]] = load_state("process_limits_state", {})
priority_mode_active = load_state("priority_mode_active", False)
priority_mode_limits = load_state("priority_mode_limits", {})

PROCESS_CATEGORIES = {
    "qbittorrent.exe": "torrent", "utorrent.exe": "torrent", "tixati.exe": "torrent",
    "transmission-qt.exe": "torrent", "deluge.exe": "torrent", "bittorrent.exe": "torrent",
    "steam.exe": "gaming", "steamwebhelper.exe": "gaming", "epicgameslauncher.exe": "gaming",
    "battle.net.exe": "gaming",
    "obs64.exe": "streaming", "obs32.exe": "streaming", "streamlabs.exe": "streaming",
    "chrome.exe": "web", "firefox.exe": "web", "msedge.exe": "web", "browser.exe": "web",
    "svchost.exe": "system", "searchhost.exe": "system", "msmpeng.exe": "system",
}
DEFAULT_CATEGORY = "other"


def enqueue(hostname: str, ctype: str, payload: dict):
    command_queue.setdefault(hostname, []).append({
        "id": str(uuid.uuid4()),
        "type": ctype,
        "payload": payload,
        "_ts": time.time(),
    })


def _expire_old_commands(hostname: str):
    q = command_queue.get(hostname)
    if not q:
        return
    cutoff = time.time() - COMMAND_TTL
    command_queue[hostname] = [c for c in q if c.get("_ts", 0) >= cutoff]


def exe_of(p: dict) -> str:
    name = (p.get("name") or "").lower()
    if p.get("exe"):
        # Split on both separators; the agent runs on Windows (backslashes)
        # but the server may run on Linux, where os.path.basename ignores '\'.
        path = p["exe"].replace("\\", "/")
        name = path.rsplit("/", 1)[-1].lower()
    return name


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------

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


class AckPayload(BaseModel):
    ids: List[str]


# ----------------------------------------------------------------------------
# Reporting + command delivery
# ----------------------------------------------------------------------------

@app.post("/api/report")
async def receive_report(payload: ReportPayload):
    hostname = payload.hostname
    if hostname not in agents_state:
        logger.info("New agent: %s (%s)", hostname, payload.ip)

    agents_state[hostname] = {
        "last_seen": time.time(),
        "ip": payload.ip,
        "mac": payload.mac,
        "traffic_in_bps": payload.traffic_in_bps,
        "traffic_out_bps": payload.traffic_out_bps,
        "top_processes": payload.top_processes,
        "limit_mbps": limits_state.get(hostname),
        "status": "online",
    }
    command_queue.setdefault(hostname, [])

    if priority_mode_active:
        _apply_priority_to_host(hostname, payload.top_processes, payload.ip)

    hist = traffic_history.setdefault(hostname, deque(maxlen=HISTORY_POINTS))
    hist.append({"t": time.time(), "in": payload.traffic_in_bps, "out": payload.traffic_out_bps})
    return {"status": "ok"}


@app.get("/api/commands/{hostname}")
async def get_commands(hostname: str):
    """Return queued commands WITHOUT clearing them. They're removed only
    when the agent ACKs (or when they expire). This is what makes delivery
    survive a dropped response."""
    _expire_old_commands(hostname)
    cmds = command_queue.get(hostname, [])
    # Don't leak the internal timestamp to the agent.
    return {"commands": [{"id": c["id"], "type": c["type"], "payload": c["payload"]} for c in cmds]}


@app.post("/api/ack/{hostname}")
async def ack_commands(hostname: str, payload: AckPayload):
    q = command_queue.get(hostname)
    if not q:
        return {"status": "ok", "remaining": 0}
    acked = set(payload.ids)
    command_queue[hostname] = [c for c in q if c["id"] not in acked]
    return {"status": "ok", "remaining": len(command_queue[hostname])}


@app.get("/api/status")
async def get_status():
    now = time.time()
    for hostname, state in agents_state.items():
        state["status"] = "online" if (now - state["last_seen"]) <= OFFLINE_AFTER else "offline"
        state["limit_mbps"] = limits_state.get(hostname)
        state["process_limits"] = process_limits_state.get(hostname, {})
        for p in state.get("top_processes", []):
            p["category"] = PROCESS_CATEGORIES.get(exe_of(p), DEFAULT_CATEGORY)
    return {"agents": agents_state, "priority_mode": priority_mode_active}


@app.get("/api/history/{hostname}")
async def get_history(hostname: str):
    return {"history": list(traffic_history.get(hostname, []))}


# ----------------------------------------------------------------------------
# Global limit (egress via QoS)
# ----------------------------------------------------------------------------

@app.post("/api/limit/{hostname}")
async def set_limit(hostname: str, payload: LimitPayload, request: Request):
    enqueue(hostname, "limit", {"speed_mbps": payload.speed_mbps})
    limits_state[hostname] = payload.speed_mbps
    save_state("limits_state", limits_state)
    log_audit(hostname, "limit", "global", f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/unlimit/{hostname}")
async def unset_limit(hostname: str, request: Request):
    enqueue(hostname, "unlimit", {})
    limits_state[hostname] = None
    save_state("limits_state", limits_state)
    log_audit(hostname, "unlimit", "global", "", request.client.host)
    return {"status": "enqueued"}


# ----------------------------------------------------------------------------
# Network kill / restore
# ----------------------------------------------------------------------------

@app.post("/api/kill/{hostname}")
async def kill_network(hostname: str, request: Request):
    logger.warning("KILL on %s", hostname)
    enqueue(hostname, "kill", {})
    log_audit(hostname, "kill", "network", "", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/unkill/{hostname}")
async def unkill_network(hostname: str, request: Request):
    logger.info("UNKILL on %s", hostname)
    enqueue(hostname, "unkill", {})
    log_audit(hostname, "unkill", "network", "", request.client.host)
    return {"status": "enqueued"}


# ----------------------------------------------------------------------------
# Per-process limits: QoS egress + shaper download, paired
# ----------------------------------------------------------------------------

@app.post("/api/limit_process/{hostname}")
async def set_process_limit(hostname: str, payload: ProcessLimitPayload, request: Request):
    if not payload.exe_name or payload.speed_mbps <= 0:
        return JSONResponse(status_code=400, content={"detail": "Invalid limit payload"})
    enqueue(hostname, "limit_process", {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps})
    process_limits_state.setdefault(hostname, {})[payload.exe_name] = payload.speed_mbps
    save_state("process_limits_state", process_limits_state)
    log_audit(hostname, "limit_process", payload.exe_name, f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/unlimit_process/{hostname}")
async def unset_process_limit(hostname: str, payload: ProcessUnlimitPayload, request: Request):
    enqueue(hostname, "unlimit_process", {"exe_name": payload.exe_name})
    if hostname in process_limits_state:
        process_limits_state[hostname].pop(payload.exe_name, None)
        save_state("process_limits_state", process_limits_state)
    log_audit(hostname, "unlimit_process", payload.exe_name, "", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/full_throttle/{hostname}")
async def full_throttle(hostname: str, payload: ProcessLimitPayload, request: Request):
    """Apply BOTH egress QoS and download shaping for one process."""
    if not payload.exe_name or payload.speed_mbps <= 0:
        return JSONResponse(status_code=400, content={"detail": "Invalid limit payload"})
    enqueue(hostname, "limit_process", {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps})
    enqueue(hostname, "shape_process", {"exe_name": payload.exe_name, "speed_mbps": payload.speed_mbps})
    process_limits_state.setdefault(hostname, {})[payload.exe_name] = payload.speed_mbps
    save_state("process_limits_state", process_limits_state)
    log_audit(hostname, "full_throttle", payload.exe_name, f"{payload.speed_mbps} Mbps", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/full_unthrottle/{hostname}")
async def full_unthrottle(hostname: str, payload: ProcessUnlimitPayload, request: Request):
    enqueue(hostname, "unlimit_process", {"exe_name": payload.exe_name})
    enqueue(hostname, "unshape_process", {"exe_name": payload.exe_name})
    if hostname in process_limits_state:
        process_limits_state[hostname].pop(payload.exe_name, None)
        save_state("process_limits_state", process_limits_state)
    log_audit(hostname, "full_unthrottle", payload.exe_name, "", request.client.host)
    return {"status": "enqueued"}


# ----------------------------------------------------------------------------
# Audit
# ----------------------------------------------------------------------------

@app.get("/api/audit")
async def get_audit(hostname: Optional[str] = None, limit: int = 50, offset: int = 0):
    limit = max(1, min(limit, 500))
    if hostname:
        rows = _db_read(
            "SELECT * FROM audit_log WHERE hostname=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (hostname, limit, offset),
        )
    else:
        rows = _db_read(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
    keys = ["id", "timestamp", "hostname", "action", "target", "params", "source_ip"]
    return {"logs": [dict(zip(keys, r)) for r in rows]}


# ----------------------------------------------------------------------------
# Priority mode
# ----------------------------------------------------------------------------

def _apply_priority_to_host(hostname: str, top_processes: list, source_ip: str):
    profile = config.get("priority_profile", {})
    seen = priority_mode_limits.setdefault(hostname, [])
    changed = False
    for p in top_processes:
        exe = exe_of(p)
        if exe in seen:
            continue
        cat = PROCESS_CATEGORIES.get(exe, DEFAULT_CATEGORY)
        if cat not in profile:
            continue
        speed_mbps = float(profile[cat].get("out_kbps", 128)) / 1000.0
        current = process_limits_state.get(hostname, {}).get(exe)
        if current is None or current > speed_mbps:
            enqueue(hostname, "limit_process", {"exe_name": exe, "speed_mbps": speed_mbps})
            enqueue(hostname, "shape_process", {"exe_name": exe, "speed_mbps": speed_mbps})
            seen.append(exe)
            changed = True
            log_audit(hostname, "priority_mode_auto_apply", exe, f"{speed_mbps} Mbps", source_ip)
    if changed:
        save_state("priority_mode_limits", priority_mode_limits)


@app.post("/api/priority_mode/on")
async def priority_mode_on(request: Request):
    global priority_mode_active
    if priority_mode_active:
        return {"status": "already active"}
    for hostname, state in agents_state.items():
        _apply_priority_to_host(hostname, state.get("top_processes", []), request.client.host)
    priority_mode_active = True
    save_state("priority_mode_active", True)
    save_state("priority_mode_limits", priority_mode_limits)
    log_audit("GLOBAL", "priority_mode", "ON", "", request.client.host)
    return {"status": "enqueued"}


@app.post("/api/priority_mode/off")
async def priority_mode_off(request: Request):
    global priority_mode_active
    if not priority_mode_active:
        return {"status": "already inactive"}
    for hostname, exes in priority_mode_limits.items():
        for exe in exes:
            original = process_limits_state.get(hostname, {}).get(exe)
            if original is not None:
                enqueue(hostname, "limit_process", {"exe_name": exe, "speed_mbps": original})
                enqueue(hostname, "shape_process", {"exe_name": exe, "speed_mbps": original})
                log_audit(hostname, "priority_mode_restore", exe, f"{original} Mbps", request.client.host)
            else:
                enqueue(hostname, "unlimit_process", {"exe_name": exe})
                enqueue(hostname, "unshape_process", {"exe_name": exe})
                log_audit(hostname, "priority_mode_restore", exe, "Unlimited", request.client.host)
    priority_mode_limits.clear()
    priority_mode_active = False
    save_state("priority_mode_active", False)
    save_state("priority_mode_limits", priority_mode_limits)
    log_audit("GLOBAL", "priority_mode", "OFF", "", request.client.host)
    return {"status": "enqueued"}


# ----------------------------------------------------------------------------
# Static dashboard (mounted last so /api/* wins)
# ----------------------------------------------------------------------------

static_dir = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(__file__), "static"))
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
