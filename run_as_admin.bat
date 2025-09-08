@echo off
echo 正在以管理員權限啟動 Real Memory Detection Engine...
echo.

REM 檢查是否已經以管理員權限運行
net session >nul 2>&1
if %errorLevel% == 0 (
    echo 已檢測到管理員權限，直接啟動程式...
    cd /d "%~dp0"
    build\src\real_detection_engine.exe
) else (
    echo 需要管理員權限，正在請求提升權限...
    powershell -Command "Start-Process '%~dp0build\src\real_detection_engine.exe' -Verb RunAs -WorkingDirectory '%~dp0'"
)

pause
