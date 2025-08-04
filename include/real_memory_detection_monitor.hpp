#pragma once

#include <windows.h>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <chrono>
#include <fstream>
#include "real_memory_detection_types.hpp"

namespace RealMemoryDetection {

// 記憶體區域信息
struct MemoryRegionInfo {
    LPVOID base_address;
    SIZE_T size;
    DWORD protection;
    DWORD state;
    DWORD type;
    bool is_monitored;
    std::chrono::system_clock::time_point last_scan;
    uint32_t scan_count;
    bool is_suspicious;
};

// 記憶體監控配置
struct MemoryMonitorConfig {
    uint32_t scan_interval_ms = 200;
    uint32_t max_regions_per_scan = 1000;
    bool enable_heap_monitoring = true;
    bool enable_stack_monitoring = true;
    bool enable_executable_monitoring = true;
    bool enable_shared_memory_monitoring = true;
    uint32_t suspicious_pattern_threshold = 5;
    std::string log_file = "memory_monitor.log";
};

// 記憶體監控回調
using MemoryViolationCallback = std::function<void(AttackType, uint64_t, const std::string&, double)>;

/**
 * 記憶體監控器
 * 負責監控系統記憶體區域，檢測記憶體攻擊
 */
class MemoryMonitor {
public:
    explicit MemoryMonitor(const MemoryMonitorConfig& config = MemoryMonitorConfig{});
    ~MemoryMonitor();

    // 啟動監控
    bool start();
    
    // 停止監控
    void stop();
    
    // 檢查是否正在運行
    bool is_running() const;
    
    // 設置違規回調
    void set_violation_callback(MemoryViolationCallback callback);
    
    // 掃描記憶體區域
    void scan_memory_regions();
    
    // 檢查堆完整性
    void check_heap_integrity();
    
    // 檢查堆疊完整性
    void check_stack_integrity();
    
    // 檢查可執行記憶體
    void check_executable_memory();
    
    // 檢查共享記憶體
    void check_shared_memory();
    
    // 獲取監控統計
    struct MonitorStats {
        uint64_t total_scans;
        uint64_t regions_scanned;
        uint64_t violations_detected;
        uint64_t heap_corruptions;
        uint64_t stack_corruptions;
        uint64_t executable_violations;
        std::chrono::system_clock::time_point last_scan;
    };
    
    MonitorStats get_stats() const;
    
    // 獲取監控的記憶體區域
    std::vector<MemoryRegionInfo> get_monitored_regions() const;
    
    // 添加記憶體區域到監控
    void add_region_to_monitor(LPVOID address, SIZE_T size);
    
    // 移除記憶體區域監控
    void remove_region_from_monitor(LPVOID address);
    
    // 清空監控列表
    void clear_monitored_regions();
    
    // 設置掃描間隔
    void set_scan_interval(uint32_t interval_ms);
    
    // 啟用/禁用特定類型的監控
    void enable_heap_monitoring(bool enable);
    void enable_stack_monitoring(bool enable);
    void enable_executable_monitoring(bool enable);
    void enable_shared_memory_monitoring(bool enable);

private:
    // 監控線程
    void monitor_loop();
    
    // 掃描單個記憶體區域
    void scan_memory_region(const MemoryRegionInfo& region);
    
    // 檢查記憶體區域的完整性
    bool check_region_integrity(LPVOID address, SIZE_T size);
    
    // 檢查ROP/JOP gadgets
    bool check_rop_jop_gadgets(LPVOID address, SIZE_T size);
    
    // 檢查Shellcode特徵
    bool check_shellcode_signatures(LPVOID address, SIZE_T size);
    
    // 檢查堆損壞模式
    bool check_heap_corruption_patterns(LPVOID address, SIZE_T size);
    
    // 檢查Use-After-Free模式
    bool check_use_after_free_patterns(LPVOID address, SIZE_T size);
    
    // 檢查緩衝區溢出模式
    bool check_buffer_overflow_patterns(LPVOID address, SIZE_T size);
    
    // 報告記憶體違規
    void report_violation(AttackType type, uint64_t address, 
                         const std::string& description, double confidence);
    
    // 記錄日誌
    void log_message(const std::string& level, const std::string& message);
    
    // 獲取時間戳
    std::string get_timestamp() const;
    
    // 格式化地址
    std::string format_address(uint64_t address) const;
    
    // 檢查記憶體保護
    bool is_executable_memory(LPVOID address, SIZE_T size) const;
    bool is_readable_memory(LPVOID address, SIZE_T size) const;
    bool is_writable_memory(LPVOID address, SIZE_T size) const;
    
    // 安全讀取記憶體
    bool safe_read_memory(LPVOID address, SIZE_T size, std::vector<uint8_t>& buffer) const;
    
    // 配置
    MemoryMonitorConfig config_;
    
    // 運行標誌
    std::atomic<bool> running_;
    
    // 監控線程
    std::thread monitor_thread_;
    
    // 違規回調
    MemoryViolationCallback violation_callback_;
    
    // 監控的記憶體區域
    std::map<LPVOID, MemoryRegionInfo> monitored_regions_;
    
    // 統計信息
    MonitorStats stats_;
    
    // 互斥鎖
    mutable std::mutex regions_mutex_;
    mutable std::mutex stats_mutex_;
    
    // 日誌檔案
    std::ofstream log_file_;
    mutable std::mutex log_mutex_;
    
    // 監控標誌
    std::atomic<bool> heap_monitoring_enabled_;
    std::atomic<bool> stack_monitoring_enabled_;
    std::atomic<bool> executable_monitoring_enabled_;
    std::atomic<bool> shared_memory_monitoring_enabled_;
};

} // namespace RealMemoryDetection 