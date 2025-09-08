#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試上下文匹配功能
"""

import logging
from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_context_matching():
    """測試上下文匹配功能"""
    
    server = MCPServer(repo_root="../", policy_file="policy.json")
    
    # 測試文件路徑
    test_file = "src/test_context.cpp"
    
    # 創建一個測試文件，模擬 detection_engine.cpp 的開頭
    original_content = """#include <iostream>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <conio.h>
#include <algorithm>
#include <cctype>
#include <array>
#include <cmath>
#include <algorithm>
#include "../include/detection_engine.hpp"
#include "../include/memory_detection_types.hpp"
#include "../include/memory_detection_utils.hpp"
#include "../include/memory_detection_veh.hpp"
#include "../include/memory_detection_monitor.hpp"
#include "../include/utils/performance_monitor.hpp"
#include "../include/utils/logger.hpp"
#include "../include/utils/process_lists.hpp"

#ifdef _MSC_VER
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#endif

// 添加缺少的常數定義
#ifndef EXCEPTION_GUARD_PAGE_VIOLATION
#define EXCEPTION_GUARD_PAGE_VIOLATION 0x80000001
#endif

#ifndef PROCESS_HEAP_ENTRY_CORRUPTED
#define PROCESS_HEAP_ENTRY_CORRUPTED 0x00000010
#endif

// 模擬器標記常量
constexpr DWORD SIMULATOR_MAGIC = 0x53494D55; // 'SIMU'

using namespace RealMemoryDetection;
using namespace MemoryDetectionEngine;
using namespace std::chrono_literals;

class DetectionEngineImpl : public RealMemoryDetectionEngine, public MemoryMonitor {
private:
    // 添加 monitor 成員
    std::unique_ptr<MemoryDetectionMonitor> monitor;
    std::atomic<uint64_t> detection_counter{0};
    std::mt19937_64 rng;
    std::uniform_int_distribution<uint64_t> dist;

public:
    DetectionEngineImpl();
    ~DetectionEngineImpl();
    void process_event(const MemoryEvent& event) override;
    std::string generate_detection_id();
};"""
    
    # 先創建文件
    create_result = server.write_file({
        "path": test_file,
        "content": original_content,
        "create_dirs": True
    })
    
    if not create_result.success:
        print(f"❌ 創建測試文件失敗: {create_result.error}")
        return
    
    print("✅ 成功創建測試文件")
    
    # 測試 diff 內容（沒有明確行號的格式）
    diff_content = """@@
 class DetectionEngineImpl : public RealMemoryDetectionEngine, public MemoryMonitor {
 private:
     // 添加 monitor 成員
     std::unique_ptr<MemoryDetectionMonitor> monitor;
+    std::atomic<uint64_t> detection_counter{0};
+    std::mt19937_64 rng;
+    std::uniform_int_distribution<uint64_t> dist;

 public:
     DetectionEngineImpl();
     ~DetectionEngineImpl();
     void process_event(const MemoryEvent& event) override;
+    std::string generate_detection_id();
 };"""
    
    # 應用 diff
    diff_result = server.apply_diff({
        "path": test_file,
        "diff_content": diff_content
    })
    
    if diff_result.success:
        print("✅ 成功應用 diff")
        print(f"原始大小: {diff_result.data.get('original_size')}")
        print(f"新大小: {diff_result.data.get('new_size')}")
        print(f"原始行數: {diff_result.data.get('original_lines')}")
        print(f"新行數: {diff_result.data.get('new_lines')}")
        
        # 讀取修改後的文件
        read_result = server.read_file({"path": test_file})
        if read_result.success:
            print("修改後的內容:")
            print(read_result.data.get('content', ''))
        else:
            print(f"❌ 讀取文件失敗: {read_result.error}")
    else:
        print(f"❌ 應用 diff 失敗: {diff_result.error}")

if __name__ == "__main__":
    test_context_matching()
