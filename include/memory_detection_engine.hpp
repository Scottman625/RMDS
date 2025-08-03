#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

namespace MemoryDetectionEngine {

// 前向聲明
class MTEManager;
class LLVMInstrumentation;
class PatternMatcher;
class PerformanceMonitor;
class Logger;

/**
 * @brief 攻擊類型枚舉
 */
enum class AttackType {
    ROP,                    // Return-Oriented Programming
    JOP,                    // Jump-Oriented Programming
    CALLOP,                 // Call-Oriented Programming
    STACK_PIVOT,            // Stack Pivot Attack
    ROP_CHAIN,              // Return-Oriented Programming 鏈
    JOP_CHAIN,              // Jump-Oriented Programming 鏈
    CALLOP_CHAIN,           // Call-Oriented Programming 鏈
    RET2LIBC,               // Return-to-libc 攻擊
    SHELLCODE_INJECTION,    // Shellcode 注入
    MEMORY_CORRUPTION,      // 記憶體破壞
    BUFFER_OVERFLOW,        // 緩衝區溢出
    USE_AFTER_FREE,         // 釋放後使用
    DOUBLE_FREE,            // 重複釋放
    HEAP_SPRAYING,          // 堆噴灑攻擊
    RACE_CONDITION,         // 競態條件
    UNKNOWN                 // 未知攻擊類型
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
    bool is_false_positive;
};

/**
 * @brief 引擎統計結構
 */
struct EngineStats {
    uint64_t total_detections;
    uint64_t total_false_positives;
    uint64_t average_detection_time_us;
    uint64_t uptime_seconds;
};

/**
 * @brief 性能統計結構
 */
struct PerformanceStats {
    uint64_t total_detections;
    uint64_t false_positives;
    double average_latency_us;
    double max_latency_us;
    double min_latency_us;
    uint64_t memory_usage_bytes;
};

/**
 * @brief 配置結構
 */
struct EngineConfig {
    bool enable_mte = true;
    bool enable_llvm_instrumentation = true;
    bool enable_pattern_matching = true;
    bool enable_performance_monitoring = true;
    uint32_t detection_threshold = 80;
    uint32_t max_latency_us = 3;
    uint32_t detection_interval_ms = 100;
    std::string log_level = "INFO";
};

/**
 * @brief 實時內存攻擊檢測引擎主類
 */
class MemoryDetectionEngine {
public:
    explicit MemoryDetectionEngine(const EngineConfig& config = EngineConfig{});
    ~MemoryDetectionEngine();

    // 禁用複製構造和賦值
    MemoryDetectionEngine(const MemoryDetectionEngine&) = delete;
    MemoryDetectionEngine& operator=(const MemoryDetectionEngine&) = delete;

    /**
     * @brief 啟動檢測
     * @return 是否啟動成功
     */
    bool start();

    /**
     * @brief 停止檢測
     */
    void stop();

    /**
     * @brief 檢查是否正在運行
     * @return 運行狀態
     */
    bool is_running() const;

    /**
     * @brief 獲取引擎統計
     * @return 統計數據
     */
    EngineStats get_stats() const;

    /**
     * @brief 獲取引擎版本
     * @return 版本字符串
     */
    static std::string get_version();

private:
    void detection_loop();
    void perform_detection();

    // 成員變數
    EngineConfig config_;
    std::atomic<bool> running_;
    
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<MTEManager> mte_manager_;
    std::unique_ptr<LLVMInstrumentation> llvm_instrumentation_;
    std::unique_ptr<PatternMatcher> pattern_matcher_;
    std::unique_ptr<PerformanceMonitor> performance_monitor_;
    
    std::thread detection_thread_;
    mutable std::mutex stats_mutex_;
};

/**
 * @brief 工廠函數：創建檢測引擎實例
 * @param config 引擎配置
 * @return 引擎實例
 */
std::unique_ptr<MemoryDetectionEngine> create_engine(const EngineConfig& config = EngineConfig{});

} // namespace MemoryDetectionEngine 