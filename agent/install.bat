@echo off
echo Installing requirements...
pip install -r requirements.txt
echo.

set SERVER=http://127.0.0.1:8000

set /p INPUT_SERVER="Enter server URL (default: http://127.0.0.1:8000): "
if not "%INPUT_SERVER%"=="" set SERVER=%INPUT_SERVER%

:ask_key
set /p APIKEY="Enter API Key (required): "
if "%APIKEY%"=="" (
    echo ERROR: API Key is required. Get it from server console on first run.
    goto ask_key
)

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
