#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡單測試修復後的邏輯
"""

import logging
from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_simple_fix():
    """測試簡單的修復"""
    
    server = MCPServer(repo_root="../", policy_file="policy.json")
    
    # 測試讀取原始文件
    result = server.read_file({"path": "src/detection_engine.cpp"})
    
    if result.success:
        print("✅ 成功讀取原始文件")
        print(f"文件長度: {len(result.data.get('content', ''))}")
        print(f"前200字符: {result.data.get('content', '')[:200]}")
    else:
        print(f"❌ 讀取文件失敗: {result.error}")

if __name__ == "__main__":
    test_simple_fix()
