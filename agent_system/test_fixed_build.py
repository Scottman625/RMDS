#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修正後的編譯測試
測試新的工具鏈選擇邏輯
"""

import sys
import logging
import platform
import shutil
from pathlib import Path

# 添加當前目錄到 Python 路徑
sys.path.insert(0, str(Path(__file__).parent))

from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def detect_toolchain():
    """檢測可用的工具鏈"""
    print("🔍 檢測可用工具鏈...")
    print("=" * 40)
    
    is_windows = platform.system() == "Windows"
    
    if is_windows:
        print("Windows 平台檢測:")
        
        # 檢測 Visual Studio 環境
        vs_paths = [
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\VC\\Auxiliary\\Build\\vcvars64.bat",
            "C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\VC\\Auxiliary\\Build\\vcvars64.bat"
        ]
        
        vs_found = False
        for path in vs_paths:
            if Path(path).exists():
                print(f"✅ Visual Studio 環境: {path}")
                vs_found = True
                break
        
        if not vs_found:
            print("❌ Visual Studio 環境未找到")
        
        # 檢測編譯器
        clang_cl = shutil.which("clang-cl")
        if clang_cl:
            print(f"✅ ClangCL: {clang_cl}")
        else:
            print("❌ ClangCL: 未找到")
        
        raw_clangpp = shutil.which("clang++")
        if raw_clangpp:
            print(f"✅ Clang++: {raw_clangpp}")
            # 檢測是否為 MinGW 版本
            p = str(Path(raw_clangpp)).lower()
            if "mingw" in p or "llvm-mingw" in p:
                print("   → 檢測為 MinGW/llvm-mingw 版本")
            else:
                print("   → 檢測為標準 LLVM 版本")
        else:
            print("❌ Clang++: 未找到")
        
        # 檢測 MSVC
        cl = shutil.which("cl")
        if cl:
            print(f"✅ MSVC (cl): {cl}")
        else:
            print("❌ MSVC (cl): 未找到")
        
        # 檢測 Ninja
        ninja = shutil.which("ninja")
        if ninja:
            print(f"✅ Ninja: {ninja}")
        else:
            print("❌ Ninja: 未找到")
        
        # 檢測 CMake
        cmake = shutil.which("cmake")
        if cmake:
            print(f"✅ CMake: {cmake}")
        else:
            print("❌ CMake: 未找到")
        
        # 預測工具鏈選擇
        print("\n🔮 預測工具鏈選擇:")
        if clang_cl:
            print("   → 將使用 Visual Studio + ClangCL")
        elif raw_clangpp and ("mingw" in str(Path(raw_clangpp)).lower() or "llvm-mingw" in str(Path(raw_clangpp)).lower()):
            if ninja:
                print("   → 將使用 Ninja + MinGW Clang")
            else:
                print("   → 將使用 MinGW Makefiles + MinGW Clang")
        elif vs_found:
            print("   → 將使用 Visual Studio + MSVC")
        else:
            print("   → 無法確定工具鏈選擇")
    
    else:
        print("Linux/macOS 平台檢測:")
        clangpp = shutil.which("clang++")
        if clangpp:
            print(f"✅ Clang++: {clangpp}")
        else:
            print("❌ Clang++: 未找到")
        
        cmake = shutil.which("cmake")
        if cmake:
            print(f"✅ CMake: {cmake}")
        else:
            print("❌ CMake: 未找到")
    
    print()

def test_build():
    """測試編譯"""
    print("🔨 測試項目編譯...")
    print("=" * 30)
    
    # 獲取專案根目錄
    agent_system_dir = Path(__file__).parent
    repo_root = agent_system_dir.parent
    policy_file = agent_system_dir / "policy.json"
    
    print(f"📁 專案根目錄: {repo_root}")
    print(f"📄 策略文件: {policy_file}")
    print()
    
    try:
        # 初始化 MCP Server
        print("🚀 初始化 MCP Server...")
        mcp_server = MCPServer(repo_root=str(repo_root), policy_file=str(policy_file))
        print("✅ MCP Server 初始化成功")
        print()
        
        # 測試編譯項目
        print("🔨 開始編譯測試...")
        build_result = mcp_server.build_project({
            "build_type": "Debug",
            "target": "all"
        })
        
        if build_result.success:
            print(f"✅ 編譯成功！")
            print(f"   構建類型: {build_result.data['build_type']}")
            print(f"   目標: {build_result.data['target']}")
            print(f"   工具鏈模式: {build_result.data['toolchain_mode']}")
            print(f"   構建目錄: {build_result.data['build_dir']}")
            print(f"   可執行文件數量: {len(build_result.data['executables'])}")
            
            for exe in build_result.data['executables']:
                print(f"   - {exe['path']} ({exe['size']} bytes)")
            
            print("\n📋 CMake 配置輸出:")
            print("-" * 20)
            print(build_result.data['cmake_output'])
            
            print("\n📋 編譯輸出:")
            print("-" * 20)
            print(build_result.data['build_output'])
            
            return True
        else:
            print(f"❌ 編譯失敗: {build_result.error}")
            print("詳細錯誤信息:")
            print(build_result.error)
            return False
    
    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函數"""
    print("🔧 修正後的編譯測試")
    print("=" * 50)
    
    # 檢測工具鏈
    detect_toolchain()
    
    # 測試編譯
    success = test_build()
    
    if success:
        print("\n🎉 編譯測試成功完成！")
        print("✅ 工具鏈選擇邏輯工作正常")
    else:
        print("\n❌ 編譯測試失敗")
        print("請檢查錯誤信息並確保環境配置正確")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
