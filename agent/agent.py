"""
NetCop agent. Runs on each managed Windows machine.

Responsibilities:
  * Report traffic + top processes to the server every few seconds.
  * Pull queued commands and execute them, then ACK the ones it ran so the
    server can stop resending (fixes silent command loss on a flaky link).
  * Apply egress limits via NetQosPolicy and download limits via the
    window-clamping shaper in shaper.py.
  * Guard the network-kill switch with a watchdog that auto-restores after
    a timeout, so a kill can never strand the machine offline.

Windows-only by design (WinDivert + netsh + NetQosPolicy).
"""

import time
import psutil
import requests
import socket
import subprocess
import argparse
import uuid
import platform
import logging
import threading
import ctypes
import sys
from collections import defaultdict

logging.basicConfig(
    filename="agent.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

try:
    from shaper import TrafficShaper
except ImportError:
    TrafficShaper = None

agent_online = False

# How long a network kill stays in effect before the watchdog restores it.
# A kill is a deterrent, not a brick. Server can re-kill if it still wants to.
KILL_RESTORE_SECONDS = 120


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def get_mac_address():
    return ":".join(
        ["{:02x}".format((uuid.getnode() >> ele) & 0xFF) for ele in range(0, 8 * 6, 8)][::-1]
    )


def get_active_interface_name():
    """Pick the interface that actually carries the default route, not just
    the first one that's 'up' (which on a box with VPN/Hyper-V is often a
    virtual adapter -- killing that one does nothing useful)."""
    try:
        # The adapter owning the route to the internet is the one whose
        # address matches the socket the OS picks for an external dest.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            primary_ip = s.getsockname()[0]
        finally:
            s.close()

        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == primary_ip:
                    return iface
    except Exception:
        pass

    # Fallback: first non-loopback that's up.
    try:
        for iface, stat in psutil.net_if_stats().items():
            if stat.isup and "loopback" not in iface.lower():
                return iface
    except Exception:
        pass
    return "Ethernet"


def _ps(script: str):
    """Run a PowerShell snippet, swallow output. Hidden window on frozen builds."""
    flags = 0
    if platform.system() == "Windows":
        flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        capture_output=True,
        creationflags=flags,
    )


class KillWatchdog:
    """Tracks an active network kill and restores connectivity after a
    timeout unless explicitly cancelled (by an un-kill command)."""

    def __init__(self):
        self._timer = None
        self._iface = None
        self._lock = threading.Lock()

    def engage(self, iface_name: str):
        with self._lock:
            self._cancel_timer_locked()
            self._iface = iface_name
            logging.warning("KILL engaged on %s; auto-restore in %ds", iface_name, KILL_RESTORE_SECONDS)
            self._set_iface(iface_name, enable=False)
            self._timer = threading.Timer(KILL_RESTORE_SECONDS, self._auto_restore)
            self._timer.daemon = True
            self._timer.start()

    def restore(self):
        with self._lock:
            self._cancel_timer_locked()
            if self._iface:
                logging.info("KILL manually restored on %s", self._iface)
                self._set_iface(self._iface, enable=True)
                self._iface = None

    def _auto_restore(self):
        with self._lock:
            if self._iface:
                logging.info("KILL watchdog auto-restoring %s", self._iface)
                self._set_iface(self._iface, enable=True)
                self._iface = None
            self._timer = None

    def _cancel_timer_locked(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    @staticmethod
    def _set_iface(iface_name: str, enable: bool):
        action = "enable" if enable else "disable"
        flags = 0
        if platform.system() == "Windows":
            flags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
        subprocess.run(
            ["netsh", "interface", "set", "interface", iface_name, action],
            check=False,
            capture_output=True,
            creationflags=flags,
        )


def execute_command(cmd, interface_name, shaper, watchdog):
    ctype = cmd.get("type")
    logging.info("Executing command: %s", ctype)
    try:
        if ctype == "limit":
            speed_bps = int(cmd["payload"]["speed_mbps"] * 1_000_000)
            _ps(
                f"$p = Get-NetQosPolicy -Name 'NetCopLimit' -ErrorAction SilentlyContinue;"
                f"if ($p) {{ Set-NetQosPolicy -Name 'NetCopLimit' -ThrottleRateActionBitsPerSecond {speed_bps} }}"
                f"else {{ New-NetQosPolicy -Name 'NetCopLimit' -ThrottleRateActionBitsPerSecond {speed_bps} }}"
            )

        elif ctype == "unlimit":
            _ps("Remove-NetQosPolicy -Name 'NetCopLimit' -Confirm:$false -ErrorAction SilentlyContinue")

        elif ctype == "limit_process":
            exe = cmd["payload"]["exe_name"]
            speed_bps = int(cmd["payload"]["speed_mbps"] * 1_000_000)
            pname = f"NetCop_{exe}"
            _ps(
                f"$p = Get-NetQosPolicy -Name '{pname}' -ErrorAction SilentlyContinue;"
                f"if ($p) {{ Set-NetQosPolicy -Name '{pname}' -ThrottleRateActionBitsPerSecond {speed_bps} }}"
                f"else {{ New-NetQosPolicy -Name '{pname}' -AppPathNameMatchCondition '{exe}' -ThrottleRateActionBitsPerSecond {speed_bps} }}"
            )

        elif ctype == "unlimit_process":
            exe = cmd["payload"]["exe_name"]
            _ps(f"Remove-NetQosPolicy -Name 'NetCop_{exe}' -Confirm:$false -ErrorAction SilentlyContinue")

        elif ctype == "shape_process":
            if shaper:
                shaper.set_limit(cmd["payload"]["exe_name"], cmd["payload"]["speed_mbps"])
            else:
                logging.warning("shape_process ignored: shaper disabled")

        elif ctype == "unshape_process":
            if shaper:
                shaper.remove_limit(cmd["payload"]["exe_name"])
            else:
                logging.warning("unshape_process ignored: shaper disabled")

        elif ctype == "shape_global":
            if shaper:
                shaper.set_global_limit(cmd["payload"]["speed_mbps"])
            else:
                logging.warning("shape_global ignored: shaper disabled")

        elif ctype == "unshape_global":
            if shaper:
                shaper.clear_global_limit()

        elif ctype == "kill":
            watchdog.engage(interface_name)

        elif ctype == "unkill":
            watchdog.restore()

        else:
            logging.warning("Unknown command type: %s", ctype)

        return True
    except Exception as e:
        logging.error("Command error (%s): %s", ctype, e)
        return False


def get_top_processes():
    conn_count = defaultdict(int)
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid:
                conn_count[conn.pid] += 1
    except Exception:
        pass  # likely not admin

    processes = []
    for pid, conns in sorted(conn_count.items(), key=lambda kv: kv[1], reverse=True)[:10]:
        try:
            p = psutil.Process(pid)
            try:
                p.cpu_percent(interval=None)  # prime the counter
            except Exception:
                pass

            exe = ""
            try:
                exe = p.exe()
            except Exception:
                pass

            cpu = 0.0
            try:
                cpu = p.cpu_percent(interval=None)
            except Exception:
                pass

            mem = 0.0
            try:
                mem = p.memory_info().rss / (1024 * 1024)
            except Exception:
                pass

            processes.append({
                "name": p.name(),
                "pid": pid,
                "exe": exe,
                "connections": conns,
                "cpu_percent": cpu,
                "memory_mb": mem,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes


def main_loop(args, hostname, ip, mac, interface_name, shaper, watchdog):
    global agent_online
    last_io = psutil.net_io_counters()
    last_time = time.time()

    while True:
        time.sleep(3)
        now = time.time()
        cur_io = psutil.net_io_counters()
        dt = now - last_time

        in_bps = (cur_io.bytes_recv - last_io.bytes_recv) / dt if dt > 0 else 0
        out_bps = (cur_io.bytes_sent - last_io.bytes_sent) / dt if dt > 0 else 0
        last_io, last_time = cur_io, now

        payload = {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "traffic_in_bps": in_bps,
            "traffic_out_bps": out_bps,
            "top_processes": get_top_processes(),
        }

        try:
            r = requests.post(
                f"{args.server}/api/report",
                json=payload,
                headers={"X-NetCop-Key": args.key},
                timeout=4,
            )
            agent_online = r.status_code == 200
        except requests.exceptions.RequestException:
            agent_online = False
            logging.error("Failed to contact server (report)")

        # Pull and run commands, collecting IDs we actually executed.
        try:
            r = requests.get(
                f"{args.server}/api/commands/{hostname}",
                headers={"X-NetCop-Key": args.key},
                timeout=4,
            )
            if r.status_code == 200:
                commands = r.json().get("commands", [])
                done_ids = []
                for cmd in commands:
                    if execute_command(cmd, interface_name, shaper, watchdog):
                        cid = cmd.get("id")
                        if cid:
                            done_ids.append(cid)
                # ACK so the server stops resending these.
                if done_ids:
                    try:
                        requests.post(
                            f"{args.server}/api/ack/{hostname}",
                            json={"ids": done_ids},
                            headers={"X-NetCop-Key": args.key},
                            timeout=4,
                        )
                    except requests.exceptions.RequestException:
                        logging.error("Failed to ACK commands (will rerun, idempotent)")
        except requests.exceptions.RequestException:
            logging.error("Failed to contact server (commands)")


def resolve_ip(hostname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()


def main():
    if platform.system() != "Windows":
        logging.warning("NetCop agent is designed for Windows; limited functionality elsewhere.")

    if not is_admin():
        logging.error("Agent must run as Administrator for shaping/QoS to work.")
        print("ERROR: run this agent as Administrator.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--key", required=True, help="Shared secret API key (required)")
    parser.add_argument("--enable-shaper", action="store_true", help="Enable WinDivert download shaper")
    parser.add_argument("--shaper-priority", type=int, default=1000)
    parser.add_argument("--rtt-ms", type=float, default=50.0, help="Assumed RTT for window clamp (ms)")
    parser.add_argument("--tray", action="store_true", help="Run in system tray")
    args = parser.parse_args()

    hostname = socket.gethostname()
    ip = resolve_ip(hostname)
    mac = get_mac_address()
    interface_name = get_active_interface_name()
    watchdog = KillWatchdog()

    if args.enable_shaper and TrafficShaper is None:
        logging.error("pydivert not installed; shaper disabled. Run: pip install pydivert")
        args.enable_shaper = False

    shaper = None
    if args.enable_shaper:
        try:
            shaper = TrafficShaper(priority=args.shaper_priority, default_rtt_ms=args.rtt_ms)
            shaper.start()
            logging.info("WinDivert shaper started (rtt=%sms).", args.rtt_ms)
        except Exception as e:
            logging.error("Failed to start shaper: %s", e)
            shaper = None

    logging.info("Agent starting on %s (%s) iface=%s server=%s", hostname, ip, interface_name, args.server)

    if args.tray:
        try:
            from tray import TrayApp
        except ImportError:
            logging.error("pystray/Pillow not installed; cannot start tray.")
            return
        t = threading.Thread(
            target=main_loop,
            args=(args, hostname, ip, mac, interface_name, shaper, watchdog),
            daemon=True,
        )
        t.start()
        TrayApp(server_url=args.server, status_callback=lambda: agent_online).run()
    else:
        main_loop(args, hostname, ip, mac, interface_name, shaper, watchdog)


if __name__ == "__main__":
    main()
