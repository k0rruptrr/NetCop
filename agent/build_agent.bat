@echo off
echo Building NetCop Agent...
pip install pyinstaller
pyinstaller --onefile --noconsole --name NetCopAgent ^
    --hidden-import shaper ^
    --hidden-import pystray ^
    --hidden-import PIL ^
    agent.py
echo.
echo Done! Executable is in dist\NetCopAgent.exe
echo NOTE: if using the shaper, place WinDivert.dll and WinDivert64.sys next to the exe.
pause
