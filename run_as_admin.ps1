# 檢查是否以管理員權限運行
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $isAdmin) {
    Write-Host "此程式需要管理員權限才能運行！" -ForegroundColor Red
    Write-Host "正在請求管理員權限..." -ForegroundColor Yellow
    
    # 重新以管理員權限啟動
    Start-Process PowerShell -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "=== Real Memory Attack Detection Engine ===" -ForegroundColor Green
Write-Host "管理員權限已確認，正在啟動程式..." -ForegroundColor Green
Write-Host ""

# 切換到腳本目錄
Set-Location $PSScriptRoot

# 檢查程式是否存在
$exePath = "build\src\real_detection_engine.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "錯誤：找不到 $exePath" -ForegroundColor Red
    Write-Host "請先編譯專案" -ForegroundColor Yellow
    Read-Host "按 Enter 退出"
    exit 1
}

# 啟動程式
Write-Host "正在啟動 Real Memory Detection Engine..." -ForegroundColor Green
& $exePath

Write-Host ""
Write-Host "程式已結束" -ForegroundColor Yellow
Read-Host "按 Enter 退出"
