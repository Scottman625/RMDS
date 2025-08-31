#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試路徑修復功能
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from workflow_orchestrator import WorkflowOrchestrator

def test_path_cleaning():
    """測試路徑清理功能"""
    orchestrator = WorkflowOrchestrator(repo_root="..")
    
    # 測試用例
    test_cases = [
        "src//detection_engine.cpp",
        "src\\\\detection_engine.cpp", 
        "src///detection_engine.cpp",
        "src\\detection_engine.cpp",
        "src/detection_engine.cpp",
        "src//include//header.hpp",
        "src\\include\\header.hpp"
    ]
    
    print("🧪 測試路徑清理功能")
    print("=" * 50)
    
    for test_path in test_cases:
        # 模擬路徑清理邏輯
        cleaned_path = '/'.join(part for part in test_path.replace('\\', '/').split('/') if part)
        print(f"原始路徑: {test_path}")
        print(f"清理後:   {cleaned_path}")
        print(f"是否正確: {cleaned_path in ['src/detection_engine.cpp', 'src/include/header.hpp']}")
        print("-" * 30)
    
    print("✅ 路徑清理測試完成")

def test_permission_check():
    """測試權限檢查功能"""
    orchestrator = WorkflowOrchestrator(repo_root="..")
    
    test_paths = [
        "src/detection_engine.cpp",
        "src/include/detection_engine.hpp",
        "tests/test_detection.cpp",
        "build/test.exe",
        "logs/test.log"
    ]
    
    print("\n🔐 測試權限檢查功能")
    print("=" * 50)
    
    for test_path in test_paths:
        read_permission = orchestrator.mcp_server._check_permission(test_path, "read")
        write_permission = orchestrator.mcp_server._check_permission(test_path, "write")
        print(f"路徑: {test_path}")
        print(f"  讀取權限: {read_permission}")
        print(f"  寫入權限: {write_permission}")
        print("-" * 30)
    
    print("✅ 權限檢查測試完成")

if __name__ == "__main__":
    test_path_cleaning()
    test_permission_check()
