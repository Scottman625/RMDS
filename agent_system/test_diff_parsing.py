#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 diff 解析功能
"""

import logging
from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_diff_parsing():
    """測試 diff 解析功能"""
    server = MCPServer(repo_root="../", policy_file="policy.json")
    
    # 測試 LLM 返回的實際格式
    test_content = """*** Begin Patch
*** Update File: include/memory_detection_monitor.hpp
@@
 #pragma once
 #include <Windows.h>
 #include <vector>
 #include <string>
 #include <functional>
+#include <atomic>
+#include <chrono>
+#include <random>
+#include <sstream>
+#include <iomanip>
 
 class MemoryDetectionMonitor {
 private:
     std::vector<std::string> detection_patterns;
     std::function<void(const std::string&)> alert_callback;
+    std::atomic<uint64_t> detection_counter{0};
+    std::mt19937_64 rng;
+    std::uniform_int_distribution<uint64_t> dist;
 
 public:
     MemoryDetectionMonitor();
     void add_pattern(const std::string& pattern);
     void set_alert_callback(std::function<void(const std::string&)> callback);
     void scan_memory();
+    std::string generate_detection_id();
 };
"""
    
    print("=== 測試 diff 解析 ===")
    print(f"原始內容長度: {len(test_content)}")
    print(f"原始內容前200字符: {test_content[:200]}")
    
    # 模擬 workflow_orchestrator 的修復邏輯
    lines = test_content.split('\n')
    
    # 尋找文件路徑
    file_path = None
    for line in lines:
        if "*** Update File:" in line:
            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
            break
        elif "*** Add File:" in line:
            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
            break
    
    # 尋找 diff 內容的開始
    diff_start = -1
    for i, line in enumerate(lines):
        if line.startswith("@@"):
            diff_start = i
            break
    
    if diff_start >= 0 and file_path:
        # 構建完整的 diff 格式
        if "*** Add File:" in test_content:
            # 新文件
            diff_content = f"--- /dev/null\n+++ b/{file_path}\n"
        else:
            # 修改文件
            diff_content = f"--- a/{file_path}\n+++ b/{file_path}\n"
        
        # 添加從 @@ 開始的內容，但需要修復 @@ 標記
        diff_lines = lines[diff_start:]
        if diff_lines and diff_lines[0].startswith("@@"):
            # 修復 @@ 標記，添加行號信息
            diff_lines[0] = "@@ -1,1 +1,1 @@"
        
        diff_content += '\n'.join(diff_lines)
        
        print(f"提取的 diff 內容長度: {len(diff_content)}")
        print(f"提取的 diff 內容: {diff_content}")
        
        # 測試 diff 驗證
        diff_meta = server._extract_and_validate_unified_diff(diff_content, server.repo_root)
        print(f"Diff 驗證結果: valid={diff_meta.valid}")
        print(f"Diff 問題: {diff_meta.issues}")
    else:
        print("未找到 diff 標記或文件路徑")

if __name__ == "__main__":
    test_diff_parsing()
