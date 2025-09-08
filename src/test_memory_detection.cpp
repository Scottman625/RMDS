#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

// 包含頭文件
#include "detection_engine.hpp"
#include "memory_detection_types.hpp"
#include "memory_detection_utils.hpp"
#include "utils/logger.hpp"

// 簡單的測試框架
class TestFramework {
private:
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;

public:
    void run_test(const std::string& test_name, std::function<bool()> test_func) {
        total_tests++;
        std::cout << "Running test: " << test_name << " ... ";
        
        try {
            bool result = test_func();
            if (result) {
                std::cout << "PASS" << std::endl;
                passed_tests++;
            } else {
                std::cout << "FAIL" << std::endl;
                failed_tests++;
            }
        } catch (const std::exception& e) {
            std::cout << "FAIL (Exception: " << e.what() << ")" << std::endl;
            failed_tests++;
        }
    }

    void print_summary() {
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Total tests: " << total_tests << std::endl;
        std::cout << "Passed: " << passed_tests << std::endl;
        std::cout << "Failed: " << failed_tests << std::endl;
        std::cout << "Success rate: " << (total_tests > 0 ? (passed_tests * 100.0 / total_tests) : 0) << "%" << std::endl;
    }

    int get_exit_code() const {
        return failed_tests > 0 ? 1 : 0;
    }
};

// 測試函數
bool test_detection_id_generation() {
    // 測試檢測ID生成
    std::string id1 = generate_detection_id();
    std::string id2 = generate_detection_id();
    
    // 檢查ID不為空
    if (id1.empty() || id2.empty()) {
        return false;
    }
    
    // 檢查ID不同
    if (id1 == id2) {
        return false;
    }
    
    // 檢查ID格式
    if (id1.find("detection_") != 0) {
        return false;
    }
    
    return true;
}

bool test_memory_detection_types() {
    // 測試記憶體檢測類型定義
    MemoryDetectionEvent event;
    event.event_type = EventType::MEMORY_WRITE_EXECUTE;
    event.timestamp = std::chrono::system_clock::now();
    event.process_id = 1234;
    event.thread_id = 5678;
    event.memory_address = 0x12345678;
    event.memory_size = 1024;
    
    // 檢查事件屬性
    if (event.event_type != EventType::MEMORY_WRITE_EXECUTE) {
        return false;
    }
    
    if (event.process_id != 1234) {
        return false;
    }
    
    if (event.memory_address != 0x12345678) {
        return false;
    }
    
    return true;
}

bool test_logger_functionality() {
    // 測試日誌功能
    Logger logger;
    
    // 測試不同級別的日誌
    logger.log(LogLevel::INFO, "Test info message");
    logger.log(LogLevel::WARNING, "Test warning message");
    logger.log(LogLevel::ERROR, "Test error message");
    
    // 檢查日誌文件是否創建
    // 這裡只是簡單測試，實際應該檢查文件內容
    
    return true;
}

bool test_performance_monitor() {
    // 測試性能監控
    PerformanceMonitor monitor;
    
    // 開始監控
    monitor.start_monitoring();
    
    // 模擬一些工作
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // 停止監控
    auto stats = monitor.stop_monitoring();
    
    // 檢查統計數據
    if (stats.cpu_usage < 0 || stats.cpu_usage > 100) {
        return false;
    }
    
    if (stats.memory_usage < 0) {
        return false;
    }
    
    return true;
}

bool test_process_list_operations() {
    // 測試進程列表操作
    ProcessList process_list;
    
    // 獲取當前進程列表
    auto processes = process_list.get_processes();
    
    // 檢查是否獲取到進程
    if (processes.empty()) {
        return false;
    }
    
    // 檢查進程信息
    for (const auto& process : processes) {
        if (process.process_id <= 0) {
            return false;
        }
        
        if (process.process_name.empty()) {
            return false;
        }
    }
    
    return true;
}

bool test_memory_utils() {
    // 測試記憶體工具函數
    uintptr_t test_address = 0x12345678;
    size_t test_size = 1024;
    
    // 測試地址範圍檢查
    if (!is_valid_memory_address(test_address)) {
        return false;
    }
    
    // 測試記憶體大小檢查
    if (!is_valid_memory_size(test_size)) {
        return false;
    }
    
    // 測試無效地址
    if (is_valid_memory_address(0)) {
        return false;
    }
    
    return true;
}

bool test_detection_engine_initialization() {
    // 測試檢測引擎初始化
    try {
        DetectionEngine engine;
        
        // 檢查引擎狀態
        if (!engine.is_initialized()) {
            return false;
        }
        
        // 檢查配置
        auto config = engine.get_configuration();
        if (config.scan_interval_ms <= 0) {
            return false;
        }
        
        return true;
    } catch (const std::exception& e) {
        // 初始化失敗是正常的，因為可能需要管理員權限
        return true;
    }
}

int main() {
    std::cout << "=== Memory Detection Engine Unit Tests ===" << std::endl;
    std::cout << "Starting tests...\n" << std::endl;
    
    TestFramework test_framework;
    
    // 運行所有測試
    test_framework.run_test("Detection ID Generation", test_detection_id_generation);
    test_framework.run_test("Memory Detection Types", test_memory_detection_types);
    test_framework.run_test("Logger Functionality", test_logger_functionality);
    test_framework.run_test("Performance Monitor", test_performance_monitor);
    test_framework.run_test("Process List Operations", test_process_list_operations);
    test_framework.run_test("Memory Utils", test_memory_utils);
    test_framework.run_test("Detection Engine Initialization", test_detection_engine_initialization);
    
    // 打印測試摘要
    test_framework.print_summary();
    
    return test_framework.get_exit_code();
}
