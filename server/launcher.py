import uvicorn
import os
import sys
import argparse

if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    base_path = sys._MEIPASS
    os.environ['STATIC_DIR'] = os.path.join(base_path, 'static')
else:
    os.environ['STATIC_DIR'] = os.path.join(os.path.dirname(__file__), 'static')

from main import app, config, DB_FILE

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=config.get("host", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=config.get("port", 8000))
    args = parser.parse_args()

    print("NetCop Server starting...")
    print(f"Bind: http://{args.host}:{args.port}")
    print(f"Database: {DB_FILE}")
    print("Auth: enabled (key loaded from config.json or env)")

    uvicorn.run(app, host=args.host, port=args.port)
