#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡化的 MCP Server 測試
"""

import sys
from pathlib import Path

# 添加當前目錄到 Python 路徑
sys.path.insert(0, str(Path(__file__).parent))

try:
    from mcp_server import MCPServer
    print("✅ MCP Server 模組導入成功")
    
    # 初始化 MCP Server
    agent_system_dir = Path(__file__).parent
    repo_root = agent_system_dir.parent
    policy_file = agent_system_dir / "policy.json"
    
    print(f"📁 專案根目錄: {repo_root}")
    print(f"📄 策略文件: {policy_file}")
    
    mcp_server = MCPServer(repo_root=str(repo_root), policy_file=str(policy_file))
    print("✅ MCP Server 初始化成功")
    
    # 測試列出文件
    result = mcp_server.list_files({"path": "src", "glob": "*.cpp"})
    if result.success:
        print(f"✅ 列出文件成功，找到 {result.data['count']} 個文件")
    else:
        print(f"❌ 列出文件失敗: {result.error}")
    
    # 測試讀取文件
    result = mcp_server.read_file({"path": "src/detection_engine.cpp"})
    if result.success:
        print(f"✅ 讀取文件成功，文件大小: {result.data['size']} 字符")
    else:
        print(f"❌ 讀取文件失敗: {result.error}")
    
    print("🎉 基本功能測試完成！")
    
except Exception as e:
    print(f"❌ 測試失敗: {e}")
    import traceback
    traceback.print_exc()
