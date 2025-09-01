@echo off
echo 設置 Windows 符號路徑...

REM 設置符號路徑環境變數
setx _NT_SYMBOL_PATH "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"

REM 設置本地符號緩存目錄
if not exist "C:\Symbols" (
    mkdir "C:\Symbols"
    echo 創建符號緩存目錄: C:\Symbols
)

echo.
echo 符號路徑已設置:
echo _NT_SYMBOL_PATH = srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
echo.
echo 請重新啟動命令提示字元或 IDE 以使環境變數生效。
echo.

pause
