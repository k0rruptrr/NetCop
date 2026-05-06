import uvicorn
import os
import sys

if getattr(sys, 'frozen', False):
    # Running as PyInstaller bundle
    base_path = sys._MEIPASS
    os.environ['STATIC_DIR'] = os.path.join(base_path, 'static')
else:
    os.environ['STATIC_DIR'] = os.path.join(os.path.dirname(__file__), 'static')

from main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
