#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
編譯環境診斷
詳細檢查編譯環境並提供解決方案
"""

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path

def check_environment_variables():
    """檢查環境變數"""
    print("🔍 檢查環境變數...")
    
    important_vars = [
        'PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VCINSTALLDIR', 'VSINSTALLDIR'
    ]
    
    for var in important_vars:
        value = os.environ.get(var, '')
        if value:
            print(f"✅ {var}: {value[:100]}...")
        else:
            print(f"❌ {var}: 未設置")

def check_visual_studio_installation():
    """詳細檢查 Visual Studio 安裝"""
    print("\n🔍 詳細檢查 Visual Studio 安裝...")
    
    vs_paths = [
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional", 
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise"
    ]
    
    found_vs = False
    for path in vs_paths:
        if Path(path).exists():
            print(f"✅ 找到 Visual Studio: {path}")
            found_vs = True
            
            # 檢查關鍵文件
            key_files = [
                f"{path}\\VC\\Auxiliary\\Build\\vcvars64.bat",
                f"{path}\\VC\\Tools\\MSVC",
                f"{path}\\VC\\Tools\\MSVC\\14.37.32822\\bin\\Hostx64\\x64\\cl.exe"
            ]
            
            for file_path in key_files:
                if Path(file_path).exists():
                    print(f"   ✅ {file_path}")
                else:
                    print(f"   ❌ {file_path}")
    
    if not found_vs:
        print("❌ 未找到 Visual Studio 安裝")
    
    return found_vs

def check_compiler_tools():
    """檢查編譯器工具"""
    print("\n🔍 檢查編譯器工具...")
    
    tools = ['cl', 'clang++', 'g++', 'cmake', 'ninja']
    
    for tool in tools:
        path = shutil.which(tool)
        if path:
            print(f"✅ {tool}: {path}")
            # 嘗試獲取版本
            try:
                if tool == 'cl':
                    result = subprocess.run([tool], capture_output=True, text=True, timeout=10)
                    if "Microsoft" in result.stderr:
                        print(f"   MSVC 編譯器可用")
                else:
                    result = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        version_line = result.stdout.split('\n')[0]
                        print(f"   版本: {version_line}")
            except Exception as e:
                print(f"   版本檢查失敗: {e}")
        else:
            print(f"❌ {tool}: 未找到")

def test_visual_studio_environment():
    """測試 Visual Studio 環境設置"""
    print("\n🔍 測試 Visual Studio 環境設置...")
    
    vs_paths = [
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
    ]
    
    for vs_path in vs_paths:
        if Path(vs_path).exists():
            print(f"測試: {vs_path}")
            try:
                # 執行 vcvars64.bat 並檢查環境
                result = subprocess.run(
                    f'"{vs_path}" && cl',
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if "Microsoft" in result.stderr:
                    print(f"   ✅ 環境設置成功，cl 編譯器可用")
                    return True
                else:
                    print(f"   ❌ 環境設置失敗: {result.stderr}")
                    
            except Exception as e:
                print(f"   ❌ 測試失敗: {e}")
    
    return False

def create_workaround_solution():
    """創建臨時解決方案"""
    print("\n🔧 創建臨時解決方案...")
    
    # 創建一個簡化的 CMakeLists.txt 來測試
    simple_cmake = """cmake_minimum_required(VERSION 3.10)
project(SimpleTest VERSION 1.0.0 LANGUAGES CXX)

# 強制使用 MSVC
if(WIN32)
    set(CMAKE_CXX_COMPILER "cl")
    set(CMAKE_C_COMPILER "cl")
endif()

# 簡單的測試程序
add_executable(simple_test main.cpp)

# 創建測試源文件
file(WRITE main.cpp "#include <iostream>
int main() {
    std::cout << \\"Hello, World!\\" << std::endl;
    return 0;
}")
"""
    
    test_dir = Path("build_test")
    test_dir.mkdir(exist_ok=True)
    
    cmake_file = test_dir / "CMakeLists.txt"
    with open(cmake_file, 'w', encoding='utf-8') as f:
        f.write(simple_cmake)
    
    print(f"✅ 創建測試目錄: {test_dir}")
    print(f"✅ 創建簡化 CMakeLists.txt: {cmake_file}")
    
    return test_dir

def print_recommendations():
    """打印建議"""
    print("\n📋 建議和解決方案:")
    print("=" * 50)
    
    print("1. 重新安裝 Visual Studio 2022:")
    print("   - 下載: https://visualstudio.microsoft.com/downloads/")
    print("   - 選擇 'Community' 版本 (免費)")
    print("   - 安裝時確保選擇 'C++ 桌面開發' 工作負載")
    print("   - 包含以下組件:")
    print("     * MSVC v143 - VS 2022 C++ x64/x86 編譯器")
    print("     * Windows 10/11 SDK")
    print("     * CMake 工具")
    
    print("\n2. 使用 Visual Studio Installer 修復:")
    print("   - 打開 Visual Studio Installer")
    print("   - 選擇 '修改'")
    print("   - 確保 'C++ 桌面開發' 已選中")
    print("   - 點擊 '修改' 重新安裝")
    
    print("\n3. 手動設置環境變數:")
    print("   - 將 Visual Studio 的 bin 目錄添加到 PATH")
    print("   - 典型路徑: C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.37.32822\\bin\\Hostx64\\x64")
    
    print("\n4. 使用開發者命令提示字元:")
    print("   - 從開始菜單打開 'Developer Command Prompt for VS 2022'")
    print("   - 在該環境中運行編譯命令")
    
    print("\n5. 替代方案 - 使用 Clang:")
    print("   - 下載 Clang for Windows: https://releases.llvm.org/download.html")
    print("   - 或使用 Chocolatey: choco install llvm")
    print("   - 修改 CMakeLists.txt 使用 Clang")

def main():
    """主函數"""
    print("🔧 編譯環境詳細診斷")
    print("=" * 40)
    
    if platform.system() != "Windows":
        print("此腳本僅適用於 Windows 系統")
        return
    
    check_environment_variables()
    vs_installed = check_visual_studio_installation()
    check_compiler_tools()
    vs_env_ok = test_visual_studio_environment()
    
    if vs_installed and not vs_env_ok:
        print("\n⚠️  Visual Studio 已安裝但環境設置有問題")
        test_dir = create_workaround_solution()
        print(f"\n可以嘗試在 {test_dir} 目錄中測試編譯")
    
    print_recommendations()

if __name__ == "__main__":
    main()
