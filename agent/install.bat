@echo off
echo Installing requirements...
pip install -r requirements.txt
echo.

set SERVER=http://127.0.0.1:8000
set APIKEY=secret

set /p INPUT_SERVER="Enter server URL (default: http://127.0.0.1:8000): "
if not "%INPUT_SERVER%"=="" set SERVER=%INPUT_SERVER%

set /p INPUT_APIKEY="Enter API Key (default: secret): "
if not "%INPUT_APIKEY%"=="" set APIKEY=%INPUT_APIKEY%

set /p SHAPER="Enable WinDivert shaper? (y/n): "
set /p TRAY="Run in system tray (no console)? (y/n): "

set CMD=python agent.py --server %SERVER% --key %APIKEY%
if /i "%SHAPER%"=="y" (
    set CMD=%CMD% --enable-shaper
)
if /i "%TRAY%"=="y" (
    set CMD=%CMD% --tray
)

echo Running Agent...
%CMD%
pause
