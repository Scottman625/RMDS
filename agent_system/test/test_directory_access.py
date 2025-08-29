#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - 目錄訪問測試
測試 Agent 是否能正確讀取 include/ 和 src/ 目錄
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

def test_directory_access():
    """測試目錄訪問"""
    print("🔍 測試 Agent 目錄訪問權限")
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
        
        # 測試讀取 include 目錄
        print("📂 測試讀取 include 目錄...")
        include_result = mcp_server.list_files({
            "path": "include",
            "glob": "*.hpp"
        })
        
        if include_result.success:
            print(f"✅ include 目錄訪問成功")
            print(f"   找到 {include_result.data['count']} 個 .hpp 文件")
            for file_info in include_result.data['files'][:5]:  # 只顯示前5個
                print(f"   - {file_info['path']} ({file_info['size']} bytes)")
            if len(include_result.data['files']) > 5:
                print(f"   ... 還有 {len(include_result.data['files']) - 5} 個文件")
        else:
            print(f"❌ include 目錄訪問失敗: {include_result.error}")
        print()
        
        # 測試讀取 src 目錄
        print("📂 測試讀取 src 目錄...")
        src_result = mcp_server.list_files({
            "path": "src",
            "glob": "*.cpp"
        })
        
        if src_result.success:
            print(f"✅ src 目錄訪問成功")
            print(f"   找到 {src_result.data['count']} 個 .cpp 文件")
            for file_info in src_result.data['files'][:5]:  # 只顯示前5個
                print(f"   - {file_info['path']} ({file_info['size']} bytes)")
            if len(src_result.data['files']) > 5:
                print(f"   ... 還有 {len(src_result.data['files']) - 5} 個文件")
        else:
            print(f"❌ src 目錄訪問失敗: {src_result.error}")
        print()
        
        # 測試讀取特定文件
        print("📄 測試讀取特定文件...")
        test_files = [
            "include/detection_engine.hpp",
            "src/detection_engine.cpp"
        ]
        
        for test_file in test_files:
            print(f"   測試讀取: {test_file}")
            file_result = mcp_server.read_file({"path": test_file})
            
            if file_result.success:
                print(f"   ✅ 成功讀取 {test_file}")
                print(f"      大小: {file_result.data['size']} 字符")
                print(f"      行數: {file_result.data['lines']} 行")
                print(f"      哈希: {file_result.data['hash'][:16]}...")
            else:
                print(f"   ❌ 讀取失敗: {file_result.error}")
            print()
        
        # 測試權限檢查
        print("🔒 測試權限檢查...")
        test_paths = [
            ("include/memory_detection_types.hpp", "read"),
            ("src/detection_engine.cpp", "read"),
            ("include/new_feature.hpp", "write"),
            ("src/new_feature.cpp", "write"),
            ("secrets/api_key.txt", "read"),
            (".env", "read")
        ]
        
        for path, operation in test_paths:
            has_permission = mcp_server._check_permission(path, operation)
            status = "✅ 允許" if has_permission else "❌ 拒絕"
            print(f"   {operation.upper()} {path}: {status}")
        
        print()
        print("🎉 目錄訪問測試完成！")
        
    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_directory_access()
