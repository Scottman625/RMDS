@echo off
echo 測試進程掃描順序和攻擊模擬器位置...
echo.

REM 檢查攻擊模擬器是否在運行
tasklist /FI "IMAGENAME eq attack_simulator.exe" 2>NUL | find /I "attack_simulator.exe" >NUL
if %ERRORLEVEL% EQU 0 (
    echo [INFO] 攻擊模擬器正在運行
    for /f "tokens=2" %%i in ('tasklist /FI "IMAGENAME eq attack_simulator.exe" /FO CSV ^| find /I "attack_simulator.exe"') do (
        set ATTACK_PID=%%i
        set ATTACK_PID=!ATTACK_PID:"=!
        echo [INFO] 攻擊模擬器 PID: !ATTACK_PID!
    )
) else (
    echo [WARNING] 攻擊模擬器未運行
)

echo.
echo 前50個進程列表：
echo ========================================

REM 獲取前50個進程
set /a count=0
for /f "skip=1 tokens=1,2" %%a in ('tasklist /FO CSV') do (
    set /a count+=1
    if !count! leq 50 (
        set process_name=%%a
        set process_pid=%%b
        set process_name=!process_name:"=!
        set process_pid=!process_pid:"=!
        echo !count!. !process_name! (PID: !process_pid!)
        
        REM 檢查是否為攻擊模擬器
        echo !process_name! | find /I "attack_simulator" >NUL
        if !ERRORLEVEL! EQU 0 (
            echo     *** 發現攻擊模擬器在第!count!個位置 ***
        )
        
        REM 檢查是否為白名單進程
        echo !process_name! | find /I "svchost" >NUL
        if !ERRORLEVEL! EQU 0 (
            echo     [白名單] 系統進程
        )
        echo !process_name! | find /I "lsass" >NUL
        if !ERRORLEVEL! EQU 0 (
            echo     [白名單] 系統進程
        )
        echo !process_name! | find /I "explorer" >NUL
        if !ERRORLEVEL! EQU 0 (
            echo     [白名單] 系統進程
        )
    )
)

echo.
echo ========================================
echo 測試完成
pause 