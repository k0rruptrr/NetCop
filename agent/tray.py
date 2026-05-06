import pystray
from PIL import Image, ImageDraw
import threading
import webbrowser
import os

def create_icon(online: bool):
    image = Image.new('RGB', (64, 64), color='#1e2130')
    draw = ImageDraw.Draw(image)
    color = '#10b981' if online else '#ef4444'
    draw.ellipse((16, 16, 48, 48), fill=color)
    return image

class TrayApp:
    def __init__(self, server_url, status_callback):
        self.server_url = server_url
        self.status_callback = status_callback
        self.icon = None

    def create_menu(self):
        status_text = "Status: Online" if self.status_callback() else "Status: Offline"
        return pystray.Menu(
            pystray.MenuItem("NetCop Agent", None, enabled=False),
            pystray.MenuItem(status_text, None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", self.open_dashboard),
            pystray.MenuItem("Exit", self.exit_app)
        )

    def open_dashboard(self, icon, item):
        webbrowser.open(self.server_url)

    def exit_app(self, icon, item):
        self.icon.stop()
        os._exit(0)

    def update_icon(self):
        if self.icon:
            online = self.status_callback()
            self.icon.icon = create_icon(online)
            self.icon.menu = self.create_menu()
            
            threading.Timer(10.0, self.update_icon).start()

    def run(self):
        online = self.status_callback()
        self.icon = pystray.Icon("NetCop", create_icon(online), "NetCop Agent", self.create_menu())
        threading.Timer(10.0, self.update_icon).start()
        self.icon.run()
