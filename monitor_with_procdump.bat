@echo off
echo 使用 Procdump 監控 Real Memory Detection Engine...
echo.

REM 檢查 procdump 是否存在
if not exist "procdump.exe" (
    echo 錯誤：找不到 procdump.exe
    echo 請從 Sysinternals 下載 Procdump: https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
    echo.
    pause
    exit /b 1
)

REM 創建 dumps 目錄
if not exist "dumps" mkdir dumps

echo 正在啟動 Procdump 監控...
echo 監控目標: build\src\real_detection_engine.exe
echo Dump 目錄: dumps
echo.

REM 使用 procdump 監控程式
REM -ma: 完整記憶體 dump
REM -e: 在異常時生成 dump
REM -x: 指定 dump 目錄
procdump -ma -e -x dumps build\src\real_detection_engine.exe

echo.
echo Procdump 監控已結束
pause
