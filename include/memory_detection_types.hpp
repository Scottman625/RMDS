#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <Windows.h>
#include <chrono>
#include "utils/process_lists.hpp"

namespace RealMemoryDetection {

/**
 * @brief 攻擊類型枚舉
 */
enum class AttackType {
    ROP_CHAIN,              // Return-Oriented Programming 鏈
    JOP_CHAIN,              // Jump-Oriented Programming 鏈
    BUFFER_OVERFLOW,        // 緩衝區溢出
    HEAP_CORRUPTION,        // 堆積破壞
    STACK_OVERFLOW,         // 堆疊溢出
    USE_AFTER_FREE,         // 釋放後使用
    DOUBLE_FREE,            // 重複釋放
    SHELLCODE_INJECTION,    // Shellcode 注入
    API_HOOK,               // API Hook
    MEMORY_CORRUPTION,      // 記憶體破壞
    COMPLEX_ATTACK,         // 複雜攻擊鏈
    SUSPICIOUS_BEHAVIOR     // 可疑行為模式
};

/**
 * @brief 檢測結果結構
 */
struct DetectionResult {
    AttackType type;
    uint64_t timestamp;
    uint64_t address;
    std::string description;
    double confidence;
    std::string process_name;
    DWORD process_id;
};

/**
 * @brief 記憶體區域監控結構
 */
struct MemoryRegion {
    LPVOID base_address;
    SIZE_T size;
    DWORD protection;
    DWORD state;
    DWORD type;
    bool is_monitored;
};

/**
 * @brief 進程監控結構
 */
struct ProcessInfo {
    DWORD process_id;
    std::string process_name;
    HANDLE process_handle;
    std::vector<MemoryRegion> memory_regions;
    bool is_suspicious;
    MemoryDetectionEngine::ProcessCategory category;
    int priority;
    std::chrono::steady_clock::time_point last_scan;
    uint32_t scan_count;
};

/**
 * @brief 引擎統計結構
 */
struct EngineStats {
    uint64_t total_detections;
    uint64_t rop_detections;
    uint64_t jop_detections;
    uint64_t buffer_overflow_detections;
    uint64_t heap_corruption_detections;
    uint64_t stack_overflow_detections;
    uint64_t use_after_free_detections;
    uint64_t shellcode_detections;
    uint64_t uptime_seconds;
    std::chrono::system_clock::time_point last_detection;
};

/**
 * @brief 引擎配置結構
 */
struct EngineConfig {
    // 檢測功能開關
    bool enable_rop_detection = true;
    bool enable_jop_detection = true;
    bool enable_buffer_overflow_detection = true;
    bool enable_heap_corruption_detection = true;
    bool enable_stack_overflow_detection = true;
    bool enable_use_after_free_detection = true;
    bool enable_shellcode_detection = true;
    bool enable_api_hook_detection = true;
    bool enable_memory_corruption_detection = true;
    
    // 系統功能開關
    bool enable_veh_handler = true;
    bool enable_dep = true;
    bool enable_memory_monitoring = true;
    bool enable_process_monitoring = true;
    
    // 時間間隔設置
    uint32_t scan_interval_ms = 1000;
    uint32_t detection_interval_ms = 50;
    uint32_t memory_scan_interval_ms = 100;
    uint32_t process_scan_interval_ms = 1000;
    
    // 其他設置
    uint32_t max_detection_results = 1000;
    std::string log_file = "logs/real_memory_detection.log";
};

} // namespace RealMemoryDetection 