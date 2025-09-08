#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
編譯環境要求檢查
檢查系統是否具備編譯 C++ 項目的必要工具
"""

import sys
import platform
import shutil
import subprocess
from pathlib import Path

def check_cmake():
    """檢查 CMake 是否可用"""
    print("🔍 檢查 CMake...")
    if shutil.which("cmake"):
        try:
            result = subprocess.run(["cmake", "--version"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                print(f"✅ CMake 已安裝: {version_line}")
                return True
        except Exception as e:
            print(f"❌ CMake 檢查失敗: {e}")
    else:
        print("❌ CMake 未安裝")
    return False

def check_compiler():
    """檢查 C++ 編譯器"""
    print("🔍 檢查 C++ 編譯器...")
    
    is_windows = platform.system() == "Windows"
    
    if is_windows:
        # 檢查 MSVC 編譯器
        if shutil.which("cl"):
            try:
                result = subprocess.run(["cl"], 
                                      capture_output=True, text=True, timeout=10)
                if "Microsoft" in result.stderr:
                    print("✅ MSVC 編譯器已安裝")
                    return True
            except Exception:
                pass
        
        # 檢查 Clang 編譯器
        if shutil.which("clang++"):
            try:
                result = subprocess.run(["clang++", "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    print(f"✅ Clang 編譯器已安裝: {version_line}")
                    return True
            except Exception as e:
                print(f"❌ Clang 檢查失敗: {e}")
        
        print("❌ 未找到可用的 C++ 編譯器")
        return False
    else:
        # Linux/macOS 檢查
        if shutil.which("clang++"):
            try:
                result = subprocess.run(["clang++", "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    print(f"✅ Clang 編譯器已安裝: {version_line}")
                    return True
            except Exception as e:
                print(f"❌ Clang 檢查失敗: {e}")
        
        if shutil.which("g++"):
            try:
                result = subprocess.run(["g++", "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    version_line = result.stdout.split('\n')[0]
                    print(f"✅ GCC 編譯器已安裝: {version_line}")
                    return True
            except Exception as e:
                print(f"❌ GCC 檢查失敗: {e}")
        
        print("❌ 未找到可用的 C++ 編譯器")
        return False

def check_visual_studio():
    """檢查 Visual Studio 安裝"""
    print("🔍 檢查 Visual Studio...")
    
    # 檢查常見的 Visual Studio 安裝路徑
    vs_paths = [
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
        "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
    ]
    
    for path in vs_paths:
        if Path(path).exists():
            print(f"✅ Visual Studio 已安裝: {path}")
            return True
    
    print("❌ Visual Studio 未安裝或未找到")
    return False

def print_installation_guide():
    """打印安裝指南"""
    print("\n📋 安裝指南:")
    print("=" * 50)
    
    is_windows = platform.system() == "Windows"
    
    if is_windows:
        print("Windows 環境安裝步驟:")
        print("1. 安裝 CMake:")
        print("   - 下載: https://cmake.org/download/")
        print("   - 或使用 Chocolatey: choco install cmake")
        print("   - 或使用 winget: winget install Kitware.CMake")
        print()
        print("2. 安裝 C++ 編譯器 (選擇其中一種):")
        print("   A. Visual Studio 2022 Community (推薦):")
        print("      - 下載: https://visualstudio.microsoft.com/downloads/")
        print("      - 安裝時選擇 'C++ 桌面開發' 工作負載")
        print("   B. Clang for Windows:")
        print("      - 下載: https://releases.llvm.org/download.html")
        print("      - 或使用 Chocolatey: choco install llvm")
        print()
        print("3. 設置環境變數:")
        print("   - 將 CMake 和編譯器的 bin 目錄添加到 PATH")
        print("   - 或使用 Visual Studio 開發者命令提示字元")
    else:
        print("Linux/macOS 環境安裝步驟:")
        print("1. 安裝 CMake:")
        print("   - Ubuntu/Debian: sudo apt install cmake")
        print("   - CentOS/RHEL: sudo yum install cmake")
        print("   - macOS: brew install cmake")
        print()
        print("2. 安裝 C++ 編譯器:")
        print("   - Ubuntu/Debian: sudo apt install clang++")
        print("   - CentOS/RHEL: sudo yum install clang")
        print("   - macOS: xcode-select --install")
        print()
        print("3. 驗證安裝:")
        print("   - cmake --version")
        print("   - clang++ --version")

def main():
    """主函數"""
    print("🔧 編譯環境要求檢查")
    print("=" * 50)
    
    cmake_ok = check_cmake()
    compiler_ok = check_compiler()
    
    if platform.system() == "Windows":
        vs_ok = check_visual_studio()
        all_ok = cmake_ok and (compiler_ok or vs_ok)
    else:
        all_ok = cmake_ok and compiler_ok
    
    print("\n📊 檢查結果:")
    print(f"   CMake: {'✅' if cmake_ok else '❌'}")
    print(f"   C++ 編譯器: {'✅' if compiler_ok else '❌'}")
    if platform.system() == "Windows":
        print(f"   Visual Studio: {'✅' if vs_ok else '❌'}")
    
    if all_ok:
        print("\n🎉 所有要求都已滿足！可以進行編譯。")
        return True
    else:
        print("\n❌ 缺少必要的編譯工具。")
        print_installation_guide()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
