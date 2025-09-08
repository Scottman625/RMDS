#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 list_functions 功能
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mcp_server import MCPServer

def test_list_functions():
    """測試 list_functions 功能"""
    print("測試 list_functions 功能...")
    
    # 初始化 MCP 服務器
    server = MCPServer(repo_root="..")
    
    # 測試列出 event_handler.cpp 中的函數
    print("\n1. 測試 event_handler.cpp:")
    result = server.list_functions({"path": "src/event_handler.cpp"})
    if result.success:
        print(f"✅ 成功找到 {result.data['total_functions']} 個函數/類")
        for func in result.data['functions']:
            print(f"  {func['type']:12} | {func['name']:30} | 行 {func['line']:3} | 作用域: {func.get('scope', 'global')}")
    else:
        print(f"❌ 失敗: {result.error}")
    
    # 測試列出 detection_engine.cpp 中的函數
    print("\n2. 測試 detection_engine.cpp:")
    result = server.list_functions({"path": "src/detection_engine.cpp"})
    if result.success:
        print(f"✅ 成功找到 {result.data['total_functions']} 個函數/類")
        for func in result.data['functions']:
            print(f"  {func['type']:12} | {func['name']:30} | 行 {func['line']:3} | 作用域: {func.get('scope', 'global')}")
    else:
        print(f"❌ 失敗: {result.error}")
    
    # 測試列出 memory_detection_monitor.cpp 中的函數
    print("\n3. 測試 memory_detection_monitor.cpp:")
    result = server.list_functions({"path": "src/memory_detection_monitor.cpp"})
    if result.success:
        print(f"✅ 成功找到 {result.data['total_functions']} 個函數/類")
        for func in result.data['functions']:
            print(f"  {func['type']:12} | {func['name']:30} | 行 {func['line']:3} | 作用域: {func.get('scope', 'global')}")
    else:
        print(f"❌ 失敗: {result.error}")
    
    # 測試列出 attack_simulator.cpp 中的函數
    print("\n4. 測試 attack_simulator.cpp:")
    result = server.list_functions({"path": "src/attack_simulator.cpp"})
    if result.success:
        print(f"✅ 成功找到 {result.data['total_functions']} 個函數/類")
        for func in result.data['functions']:
            print(f"  {func['type']:12} | {func['name']:30} | 行 {func['line']:3} | 作用域: {func.get('scope', 'global')}")
    else:
        print(f"❌ 失敗: {result.error}")

def test_token_optimization():
    """測試 token 優化效果"""
    print("\n" + "="*60)
    print("測試 Token 優化效果...")
    
    server = MCPServer(repo_root="..")
    
    # 讀取完整文件
    print("\n1. 讀取完整文件:")
    result = server.read_file({"path": "src/event_handler.cpp"})
    if result.success:
        full_content = result.data['content']
        print(f"  完整文件大小: {len(full_content)} 字符")
        print(f"  完整文件行數: {len(full_content.splitlines())} 行")
    
    # 列出函數
    print("\n2. 列出函數:")
    result = server.list_functions({"path": "src/event_handler.cpp"})
    if result.success:
        functions = result.data['functions']
        print(f"  找到函數數量: {len(functions)} 個")
        
        # 計算函數相關代碼的總大小
        total_func_size = 0
        for func in functions:
            # 估算每個函數的平均大小（這裡簡化處理）
            total_func_size += 200  # 假設每個函數平均200字符
        
        print(f"  函數相關代碼估算大小: {total_func_size} 字符")
        if full_content:
            reduction = (1 - total_func_size / len(full_content)) * 100
            print(f"  Token 使用減少: {reduction:.1f}%")

if __name__ == "__main__":
    test_list_functions()
    test_token_optimization()
