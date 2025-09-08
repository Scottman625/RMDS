#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修復編譯問題
提供多種解決方案來修復 Windows 上的編譯問題
"""

import sys
import os
import subprocess
import platform
from pathlib import Path

def check_visual_studio_installation():
    """檢查 Visual Studio 安裝"""
    print("🔍 檢查 Visual Studio 安裝...")
    
    vs_paths = [
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional", 
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise"
    ]
    
    for path in vs_paths:
        if Path(path).exists():
            print(f"✅ 找到 Visual Studio: {path}")
            return path
    
    print("❌ 未找到 Visual Studio 安裝")
    return None

def create_build_batch_file():
    """創建批處理文件來設置環境並編譯"""
    print("📝 創建編譯批處理文件...")
    
    # 獲取專案根目錄
    agent_system_dir = Path(__file__).parent
    repo_root = agent_system_dir.parent
    
    batch_content = f"""@echo off
echo 設置 Visual Studio 環境...

REM 嘗試設置 Visual Studio 2022 環境
if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

if exist "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

REM 嘗試設置 Visual Studio 2019 環境
if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

if exist "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat" (
    call "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
    goto :build
)

echo 錯誤：未找到 Visual Studio 環境
pause
exit /b 1

:build
echo 開始編譯項目...
cd /d "{repo_root}"

REM 清理構建目錄
if exist build (
    echo 清理構建目錄...
    rmdir /s /q build
)

REM 創建構建目錄
mkdir build
cd build

REM 配置 CMake
echo 配置 CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Debug

if %ERRORLEVEL% neq 0 (
    echo CMake 配置失敗
    pause
    exit /b 1
)

REM 編譯項目
echo 編譯項目...
cmake --build . --config Debug --parallel

if %ERRORLEVEL% neq 0 (
    echo 編譯失敗
    pause
    exit /b 1
)

echo 編譯成功！
echo.
echo 生成的文件：
dir /s *.exe
pause
"""
    
    batch_file = repo_root / "build_project.bat"
    with open(batch_file, 'w', encoding='utf-8') as f:
        f.write(batch_content)
    
    print(f"✅ 批處理文件已創建: {batch_file}")
    return batch_file

def create_powershell_script():
    """創建 PowerShell 腳本來編譯"""
    print("📝 創建 PowerShell 編譯腳本...")
    
    agent_system_dir = Path(__file__).parent
    repo_root = agent_system_dir.parent
    
    ps_content = f"""# PowerShell 編譯腳本
Write-Host "🔨 開始編譯項目..." -ForegroundColor Green

# 設置專案路徑
$repoRoot = "{repo_root}"
Set-Location $repoRoot

# 清理構建目錄
if (Test-Path "build") {{
    Write-Host "清理構建目錄..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "build"
}}

# 創建構建目錄
New-Item -ItemType Directory -Path "build" -Force | Out-Null
Set-Location "build"

# 嘗試設置 Visual Studio 環境
$vsPaths = @(
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
    "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
)

$vsEnvSet = $false
foreach ($path in $vsPaths) {{
    if (Test-Path $path) {{
        Write-Host "設置 Visual Studio 環境: $path" -ForegroundColor Cyan
        cmd /c "`"$path`" && set" | ForEach-Object {{
            if ($_ -match "^([^=]+)=(.*)$") {{
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }}
        }}
        $vsEnvSet = $true
        break
    }}
}}

if (-not $vsEnvSet) {{
    Write-Host "警告：未找到 Visual Studio 環境" -ForegroundColor Yellow
}}

# 配置 CMake
Write-Host "配置 CMake..." -ForegroundColor Cyan
$cmakeResult = cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Debug

if ($LASTEXITCODE -ne 0) {{
    Write-Host "CMake 配置失敗" -ForegroundColor Red
    exit 1
}}

# 編譯項目
Write-Host "編譯項目..." -ForegroundColor Cyan
$buildResult = cmake --build . --config Debug --parallel

if ($LASTEXITCODE -ne 0) {{
    Write-Host "編譯失敗" -ForegroundColor Red
    exit 1
}}

Write-Host "編譯成功！" -ForegroundColor Green
Write-Host ""
Write-Host "生成的文件：" -ForegroundColor Cyan
Get-ChildItem -Recurse -Filter "*.exe" | ForEach-Object {{
    Write-Host "  $($_.FullName)" -ForegroundColor White
}}

Read-Host "按 Enter 鍵繼續"
"""
    
    ps_file = repo_root / "build_project.ps1"
    with open(ps_file, 'w', encoding='utf-8') as f:
        f.write(ps_content)
    
    print(f"✅ PowerShell 腳本已創建: {ps_file}")
    return ps_file

def print_solutions():
    """打印解決方案"""
    print("\n🔧 編譯問題解決方案:")
    print("=" * 50)
    
    vs_path = check_visual_studio_installation()
    
    if vs_path:
        print("✅ 找到 Visual Studio 安裝")
        print("\n解決方案 1: 使用批處理文件")
        batch_file = create_build_batch_file()
        print(f"   運行: {batch_file}")
        
        print("\n解決方案 2: 使用 PowerShell 腳本")
        ps_file = create_powershell_script()
        print(f"   運行: powershell -ExecutionPolicy Bypass -File {ps_file}")
        
        print("\n解決方案 3: 手動設置環境")
        print("   1. 打開 'Developer Command Prompt for VS 2022'")
        print("   2. 導航到專案目錄")
        print("   3. 運行以下命令:")
        print("      mkdir build")
        print("      cd build")
        print("      cmake .. -G \"Visual Studio 17 2022\" -A x64")
        print("      cmake --build . --config Debug")
        
    else:
        print("❌ 未找到 Visual Studio 安裝")
        print("\n請先安裝 Visual Studio 2022 Community (免費版本):")
        print("   下載地址: https://visualstudio.microsoft.com/downloads/")
        print("   安裝時選擇 'C++ 桌面開發' 工作負載")
        print("\n或者安裝 CMake 和 Clang:")
        print("   - CMake: https://cmake.org/download/")
        print("   - Clang: https://releases.llvm.org/download.html")

def main():
    """主函數"""
    print("🔧 修復編譯問題")
    print("=" * 30)
    
    if platform.system() != "Windows":
        print("此腳本僅適用於 Windows 系統")
        return
    
    print_solutions()

if __name__ == "__main__":
    main()
