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
    filename='agent.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

try:
    from shaper import TrafficShaper
except ImportError:
    TrafficShaper = None

agent_online = False

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_mac_address():
    mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                    for ele in range(0,8*6,8)][::-1])
    return mac

def get_active_interface_name():
    # Attempt to find the primary interface name for netsh commands
    try:
        stats = psutil.net_if_stats()
        for interface, stat in stats.items():
            if stat.isup and interface != "Loopback Pseudo-Interface 1":
                return interface
    except Exception:
        pass
    return "Ethernet"

def execute_command(cmd, interface_name, shaper=None):
    logging.info(f"Executing command: {cmd['type']}")
    try:
        if cmd['type'] == 'limit':
            speed_mbps = cmd['payload']['speed_mbps']
            speed_bps = speed_mbps * 1000000
            script = f"""
            $policy = Get-NetQosPolicy -Name 'NetCopLimit' -ErrorAction SilentlyContinue
            if ($policy) {{
                Set-NetQosPolicy -Name 'NetCopLimit' -ThrottleRateActionBitsPerSecond {speed_bps}
            }} else {{
                New-NetQosPolicy -Name 'NetCopLimit' -ThrottleRateActionBitsPerSecond {speed_bps}
            }}
            """
            subprocess.run(["powershell", "-Command", script], check=False, capture_output=True)
            
        elif cmd['type'] == 'unlimit':
            subprocess.run([
                "powershell", "-Command",
                "Remove-NetQosPolicy -Name 'NetCopLimit' -Confirm:$false"
            ], check=False, capture_output=True)
        elif cmd['type'] == 'limit_process':
            exe_name = cmd['payload']['exe_name']
            speed_mbps = cmd['payload']['speed_mbps']
            speed_bps = speed_mbps * 1000000
            policy_name = f"NetCop_{exe_name}"
            script = f"""
            $policy = Get-NetQosPolicy -Name '{policy_name}' -ErrorAction SilentlyContinue
            if ($policy) {{
                Set-NetQosPolicy -Name '{policy_name}' -ThrottleRateActionBitsPerSecond {speed_bps}
            }} else {{
                New-NetQosPolicy -Name '{policy_name}' -AppPathNameMatchCondition '{exe_name}' -ThrottleRateActionBitsPerSecond {speed_bps}
            }}
            """
            subprocess.run(["powershell", "-Command", script], check=False, capture_output=True)
        elif cmd['type'] == 'unlimit_process':
            exe_name = cmd['payload']['exe_name']
            policy_name = f"NetCop_{exe_name}"
            subprocess.run([
                "powershell", "-Command",
                f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false"
            ], check=False, capture_output=True)
        elif cmd['type'] == 'shape_process':
            if shaper:
                shaper.set_limit(cmd['payload']['exe_name'], cmd['payload']['speed_mbps'])
            else:
                logging.warning("shape_process ignored because shaper is disabled")
        elif cmd['type'] == 'unshape_process':
            if shaper:
                shaper.remove_limit(cmd['payload']['exe_name'])
            else:
                logging.warning("unshape_process ignored because shaper is disabled")
        elif cmd['type'] == 'shape_global':
            if shaper:
                shaper.set_global_limit(cmd['payload']['speed_mbps'])
            else:
                logging.warning("shape_global ignored because shaper is disabled")
        elif cmd['type'] == 'kill':
            subprocess.run([
                "netsh", "interface", "set", "interface", interface_name, "disable"
            ], check=False, capture_output=True)
    except Exception as e:
        logging.error(f"Command error: {e}")

def get_top_processes():
    # Heuristic: count active connections per PID
    conn_count = defaultdict(int)
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid:
                conn_count[conn.pid] += 1
    except Exception:
        pass # Not running as admin?

    processes = []
    for pid, conns in sorted(conn_count.items(), key=lambda item: item[1], reverse=True)[:10]:
        try:
            p = psutil.Process(pid)
            try: p.cpu_percent(interval=None) # Initialize
            except Exception: pass
            
            exe = ""
            try: exe = p.exe()
            except Exception: pass
            
            cpu = 0.0
            try: cpu = p.cpu_percent(interval=None)
            except Exception: pass
            
            mem = 0.0
            try: mem = p.memory_info().rss / (1024 * 1024)
            except Exception: pass

            processes.append({
                "name": p.name(),
                "pid": pid,
                "exe": exe,
                "connections": conns,
                "cpu_percent": cpu,
                "memory_mb": mem
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def main_loop(args, hostname, ip, mac, interface_name, shaper):
    global agent_online
    last_io = psutil.net_io_counters()
    last_time = time.time()

    while True:
        time.sleep(3)
        current_time = time.time()
        current_io = psutil.net_io_counters()
        
        dt = current_time - last_time
        bytes_recv = current_io.bytes_recv - last_io.bytes_recv
        bytes_sent = current_io.bytes_sent - last_io.bytes_sent
        
        in_bps = bytes_recv / dt if dt > 0 else 0
        out_bps = bytes_sent / dt if dt > 0 else 0

        last_io = current_io
        last_time = current_time

        top_procs = get_top_processes()

        payload = {
            "hostname": hostname,
            "ip": ip,
            "mac": mac,
            "traffic_in_bps": in_bps,
            "traffic_out_bps": out_bps,
            "top_processes": top_procs
        }

        # Send report
        try:
            r = requests.post(
                f"{args.server}/api/report", 
                json=payload, 
                headers={"X-NetCop-Key": args.key},
                timeout=2
            )
            agent_online = (r.status_code == 200)
        except requests.exceptions.RequestException:
            agent_online = False
            logging.error("Failed to contact server (report)")

        # Fetch commands
        try:
            r = requests.get(
                f"{args.server}/api/commands/{hostname}", 
                headers={"X-NetCop-Key": args.key},
                timeout=2
            )
            if r.status_code == 200:
                commands = r.json().get("commands", [])
                for cmd in commands:
                    execute_command(cmd, interface_name, shaper)
        except requests.exceptions.RequestException:
            logging.error("Failed to contact server (commands)")

def main():
    if not is_admin():
        logging.error("Agent must be run as Administrator for traffic shaping to work.")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--key", default="secret", help="Shared secret API key")
    parser.add_argument("--enable-shaper", action="store_true", help="Enable WinDivert inbound shaper")
    parser.add_argument("--shaper-priority", type=int, default=1000, help="WinDivert priority")
    parser.add_argument("--tray", action="store_true", help="Run in system tray")
    args = parser.parse_args()

    hostname = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = socket.gethostbyname(hostname)
    finally:
        s.close()
    mac = get_mac_address()
    interface_name = get_active_interface_name()
    
    if args.enable_shaper and TrafficShaper is None:
        logging.error("pydivert not installed. Run: pip install pydivert")
        args.enable_shaper = False
        
    shaper = None
    if args.enable_shaper:
        try:
            shaper = TrafficShaper(priority=args.shaper_priority)
            shaper.start()
            logging.info("WinDivert Shaper started successfully.")
        except Exception as e:
            logging.error(f"Failed to start WinDivert Shaper: {e}")
            shaper = None

    logging.info(f"Agent starting on {hostname} ({ip})")
    logging.info(f"Server: {args.server}")
    logging.info(f"Primary Interface: {interface_name}")

    if args.tray:
        try:
            from tray import TrayApp
        except ImportError:
            logging.error("pystray or Pillow not installed. Cannot start in tray mode.")
            return

        agent_thread = threading.Thread(
            target=main_loop, 
            args=(args, hostname, ip, mac, interface_name, shaper), 
            daemon=True
        )
        agent_thread.start()

        tray = TrayApp(server_url=args.server, status_callback=lambda: agent_online)
        tray.run()
    else:
        main_loop(args, hostname, ip, mac, interface_name, shaper)

if __name__ == "__main__":
    if platform.system() != "Windows":
        logging.warning("NetCop MVP is designed for Windows.")
    main()
