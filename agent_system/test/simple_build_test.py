#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡化的編譯測試
專門測試 MCP Server 的編譯功能
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

def test_simple_build():
    """簡化的編譯測試"""
    print("🔨 簡化編譯測試")
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
            
            for exe in build_result.data['executables']:
                print(f"   - {exe['path']} ({exe['size']} bytes)")
        else:
            print(f"❌ 編譯失敗: {build_result.error}")
            print("詳細錯誤信息:")
            print(build_result.error)
            return False

        print()
        print("🎉 編譯測試完成！")
        return True

    except Exception as e:
        print(f"❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_simple_build()
    sys.exit(0 if success else 1)
