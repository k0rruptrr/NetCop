@echo off
echo Building NetCop Server...
pip install pyinstaller
pyinstaller --onefile --name NetCopServer ^
    --add-data "static;static" ^
    --hidden-import uvicorn.logging ^
    --hidden-import uvicorn.protocols.http ^
    --hidden-import uvicorn.protocols.http.auto ^
    --hidden-import uvicorn.protocols.websockets ^
    --hidden-import uvicorn.protocols.websockets.auto ^
    --hidden-import uvicorn.lifespan ^
    --hidden-import uvicorn.lifespan.on ^
    launcher.py
echo Done! Executable is in dist\NetCopServer.exe
pause
