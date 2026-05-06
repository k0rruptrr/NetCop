@echo off
echo Building NetCop Agent...
pip install pyinstaller
pyinstaller --onefile --noconsole --name NetCopAgent ^
    --hidden-import shaper ^
    --hidden-import pystray ^
    --hidden-import PIL ^
    agent.py
echo Done! Executable is in dist\NetCopAgent.exe
pause
