#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - 編譯和執行功能測試
測試 MCP Server 的編譯和執行能力
"""

import sys
import logging
from pathlib import Path

# 添加當前目錄到 Python 路徑
sys.path.insert(0, str(Path(__file__).parent))

from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_build_and_execute():
    """測試編譯和執行功能"""
    print("🔨 測試 MCP Server 編譯和執行功能")
    print("=" * 50)

    # 獲取專案根目錄（agent_system 的父目錄）
    agent_system_dir = Path(__file__).parent
    repo_root = agent_system_dir.parent
    policy_file = agent_system_dir / "policy.json"

    print(f"📁 Agent System 目錄: {agent_system_dir}")
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
        print("🔨 測試項目編譯...")
        build_result = mcp_server.build_project({
            "build_type": "Debug",
            "target": "all"
        })

        if build_result.success:
            print(f"✅ 編譯成功")
            print(f"   構建類型: {build_result.data['build_type']}")
            print(f"   目標: {build_result.data['target']}")
            print(f"   構建目錄: {build_result.data['build_dir']}")
            print(f"   可執行文件數量: {len(build_result.data['executables'])}")
            
            for exe in build_result.data['executables'][:5]:  # 只顯示前5個
                print(f"   - {exe['path']} ({exe['size']} bytes)")
            if len(build_result.data['executables']) > 5:
                print(f"   ... 還有 {len(build_result.data['executables']) - 5} 個文件")
        else:
            print(f"❌ 編譯失敗: {build_result.error}")
            return
        print()

        # 查找並執行測試文件
        print("🧪 測試執行編譯後的文件...")
        test_executables = []
        for exe_info in build_result.data.get("executables", []):
            exe_path = exe_info["path"]
            if "test" in exe_path.lower() or "tests" in exe_path.lower():
                test_executables.append(exe_path)

        if test_executables:
            print(f"找到 {len(test_executables)} 個測試可執行文件")
            for test_exe in test_executables[:3]:  # 只測試前3個
                print(f"   執行測試: {test_exe}")
                exec_result = mcp_server.execute_binary({
                    "path": test_exe,
                    "args": [],
                    "working_dir": str(repo_root)
                })

                if exec_result.success:
                    status = "✅ 通過" if exec_result.data["return_code"] == 0 else "❌ 失敗"
                    print(f"   {status} - 返回碼: {exec_result.data['return_code']}")
                    if exec_result.data["stdout"]:
                        print(f"   輸出: {exec_result.data['stdout'][:200]}...")
                    if exec_result.data["stderr"]:
                        print(f"   錯誤: {exec_result.data['stderr'][:200]}...")
                else:
                    print(f"   ❌ 執行失敗: {exec_result.error}")
                print()
        else:
            print("⚠️ 未找到測試可執行文件")

        # 測試執行主程序
        print("🚀 測試執行主程序...")
        main_executables = []
        for exe_info in build_result.data.get("executables", []):
            exe_path = exe_info["path"]
            if "memory_monitor" in exe_path.lower() or "detection_engine" in exe_path.lower():
                main_executables.append(exe_path)

        if main_executables:
            print(f"找到 {len(main_executables)} 個主程序")
            for main_exe in main_executables[:2]:  # 只測試前2個
                print(f"   執行主程序: {main_exe}")
                exec_result = mcp_server.execute_binary({
                    "path": main_exe,
                    "args": ["--help"],  # 使用幫助參數避免長時間運行
                    "working_dir": str(repo_root)
                })

                if exec_result.success:
                    print(f"   ✅ 執行成功 - 返回碼: {exec_result.data['return_code']}")
                    if exec_result.data["stdout"]:
                        print(f"   輸出: {exec_result.data['stdout'][:300]}...")
                else:
                    print(f"   ❌ 執行失敗: {exec_result.error}")
                print()
        else:
            print("⚠️ 未找到主程序可執行文件")

        # 測試權限檢查
        print("🔒 測試權限檢查...")
        test_paths = [
            ("build/src/memory_monitor.exe", "execute"),
            ("build/src/detection_engine.exe", "execute"),
            ("build/tests/test_detection.exe", "execute"),
            ("src/detection_engine.cpp", "read"),
            ("include/detection_engine.hpp", "read"),
            ("build/CMakeCache.txt", "read"),
            ("secrets/api_key.txt", "read"),
            (".env", "read")
        ]

        for path, operation in test_paths:
            has_permission = mcp_server._check_permission(path, operation)
            status = "✅ 允許" if has_permission else "❌ 拒絕"
            print(f"   {operation.upper()} {path}: {status}")

        print()
        print("🎉 編譯和執行功能測試完成！")

    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_build_and_execute()
