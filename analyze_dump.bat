@echo off
chcp 65001 >nul
echo WinDbg Dump Analysis Tool
echo.

if "%~1"=="" (
    echo Usage: analyze_dump.bat <dump_file.dmp>
    echo.
    echo Example: analyze_dump.bat dumps\crash_20231201_143022.dmp
    echo.
    echo Available dump files:
    if exist "dumps\*.dmp" (
        dir /b dumps\*.dmp
    ) else (
        echo No dump files found
    )
    pause
    exit /b 1
)

set DUMP_FILE=%~1

if not exist "%DUMP_FILE%" (
    echo Error: Dump file not found: %DUMP_FILE%
    pause
    exit /b 1
)

echo Analyzing dump file with WinDbg: %DUMP_FILE%
echo.

REM Check if windbg exists
where windbg >nul 2>&1
if %errorLevel% neq 0 (
    echo Warning: windbg.exe not found
    echo Please ensure Windows SDK or Debugging Tools for Windows is installed
    echo.
    echo Manual analysis steps:
    echo 1. Open WinDbg
    echo 2. Load dump file: File -> Open Crash Dump -> %DUMP_FILE%
    echo 3. Run analysis: !analyze -v
    echo 4. View call stack: k
    echo.
    pause
    exit /b 1
)

REM Use WinDbg to analyze dump
echo Starting WinDbg...
windbg -z "%DUMP_FILE%"

echo.
echo WinDbg analysis completed
pause
