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
#include <unordered_map>
#include "memory_detection_types.hpp"
#include "utils/process_lists.hpp"

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
    bool is_executable;
    bool has_gadgets;
    std::vector<uint8_t> cached_data;
};

// 使用已定義的 ProcessInfo 結構體，並擴展其功能
// ProcessInfo 已在 memory_detection_types.hpp 中定義
// 這裡添加額外的監控相關字段
struct ExtendedProcessInfo : public ProcessInfo {
    MemoryDetectionEngine::ProcessCategory category;
    int priority;
    std::chrono::steady_clock::time_point last_scan;
    uint32_t scan_count;
    std::vector<MemoryRegionInfo> memory_regions;
};

// 自適應閾值配置
struct AdaptiveThresholds {
    // 系統進程閾值
    int system_rop_suspicious_patterns = 25;
    int system_rop_ret_count = 40;
    int system_consecutive_ret = 12;
    int system_gadget_chains = 8;
    int system_heap_corruption_patterns = 8;
    int system_shellcode_patterns = 12;
    
    // 用戶進程閾值
    int user_rop_suspicious_patterns = 30;
    int user_rop_ret_count = 45;
    int user_consecutive_ret = 15;
    int user_gadget_chains = 10;
    int user_heap_corruption_patterns = 5;
    int user_shellcode_patterns = 5;
    
    // 攻擊模擬器閾值
    int simulator_rop_suspicious_patterns = 8;
    int simulator_rop_ret_count = 12;
    int simulator_consecutive_ret = 2;
    int simulator_gadget_chains = 1;
    int simulator_heap_corruption_patterns = 10;
    int simulator_shellcode_patterns = 8;
    double simulator_entropy_threshold = 2.5;
    
    // 高風險進程閾值
    int high_risk_rop_suspicious_patterns = 25;
    int high_risk_rop_ret_count = 35;
    int high_risk_consecutive_ret = 12;
    int high_risk_gadget_chains = 8;
    int high_risk_heap_corruption_patterns = 6;
    int high_risk_shellcode_patterns = 5;
};

// ROP Gadget 結構
struct ROPGadget {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string instruction;
    bool is_ret_gadget;
    bool is_pop_gadget;
    bool is_stack_pivot;
    
    ROPGadget(uint64_t addr, const std::vector<uint8_t>& b, const std::string& inst)
        : address(addr), bytes(b), instruction(inst), is_ret_gadget(false), 
          is_pop_gadget(false), is_stack_pivot(false) {
        analyze_gadget();
    }
    
    void analyze_gadget();
};

// 攻擊鏈結構
struct AttackChain {
    DWORD process_id;
    uint64_t base_address;
    std::chrono::steady_clock::time_point first_detection;
    std::vector<AttackType> detected_attacks;
    bool has_shellcode_payload;
    double highest_confidence;
    
    AttackChain() 
        : process_id(0), base_address(0), has_shellcode_payload(false), highest_confidence(0.0) {
        first_detection = std::chrono::steady_clock::now();
    }
    
    AttackChain(DWORD pid, uint64_t addr) 
        : process_id(pid), base_address(addr), has_shellcode_payload(false), highest_confidence(0.0) {
        first_detection = std::chrono::steady_clock::now();
    }
};

// 記憶體監控配置
struct MemoryMonitorConfig {
    uint32_t scan_interval_ms = 200;
    uint32_t max_regions_per_scan = 1000;
    uint32_t max_processes_to_scan = 200;
    bool enable_heap_monitoring = true;
    bool enable_stack_monitoring = true;
    bool enable_executable_monitoring = true;
    bool enable_shared_memory_monitoring = true;
    uint32_t suspicious_pattern_threshold = 5;
    std::string log_file = "logs/memory_monitor.log";
    
    // 性能配置
    size_t max_scan_size = 8192;
    int min_trigger_threshold = 3;
    int scan_step_size = 2;
    size_t max_gadget_size = 16;
    int min_gadget_count = 3;
    
    // 白名單和黑名單
    std::vector<std::string> whitelist_processes;
    std::vector<std::string> high_risk_processes;
    std::vector<std::string> system_processes;
};

// 監控統計
struct MonitorStats {
    uint64_t total_scans;
    uint64_t regions_scanned;
    uint64_t violations_detected;
    uint64_t heap_corruptions;
    uint64_t stack_corruptions;
    uint64_t executable_violations;
    uint64_t rop_detections;
    uint64_t jop_detections;
    uint64_t shellcode_detections;
    std::chrono::system_clock::time_point last_scan;
    std::chrono::system_clock::time_point last_detection;
};

// 記憶體違規回調
using MemoryViolationCallback = std::function<void(AttackType, uint64_t, const std::string&, double, DWORD)>;

/**
 * 統一的記憶體監控器
 * 作為底層工具庫供 detection_engine 使用
 */
class MemoryMonitor : public MagicHeader {

protected:
    static const uint8_t* find_pattern(const uint8_t* haystack, size_t haystack_len, const char* needle, size_t needle_len);

public:
    explicit MemoryMonitor(const MemoryMonitorConfig& config = MemoryMonitorConfig{});
    virtual ~MemoryMonitor() {
        invalidate(); // 標記為無效
    }

    // 基本控制
    bool start();
    void stop();
    bool is_running() const;
    
    // 日誌函數
    void log_message(const std::string& level, const std::string& message);
    
    // 回調設置
    void set_violation_callback(MemoryViolationCallback callback);
    
    // 進程監控工具函數
    void scan_processes();
    void monitor_process(DWORD process_id, const std::string& process_name);

    static MemoryDetectionEngine::ProcessCategory classify_process(const std::string& process_name);
    static int get_process_priority(DWORD pid, const std::string& process_name);
    
    // 記憶體掃描工具函數
    void scan_memory_regions();
    void scan_process_memory(DWORD process_id, bool is_system_process = false);
    
    // 完整性檢查工具函數
    void check_heap_integrity();
    void check_heap_region(LPVOID base, SIZE_T size);
    void check_heap_region_remote(HANDLE hProcess, LPVOID base, SIZE_T size);
    void check_executable_integrity(LPVOID base, SIZE_T size);
    void check_executable_integrity_remote(HANDLE hProcess, LPVOID base, SIZE_T size);
    void check_stack_integrity();
    void check_shared_memory();

    // 工具函數
    static std::string get_process_name(DWORD process_id);
    static bool is_whitelisted_process(const std::string& process_name);
    static bool is_system_process(DWORD process_id);
    static double calculate_shannon_entropy(const uint8_t* buffer, size_t size, const std::string& process_name);
    static bool is_valid_shellcode(const uint8_t* buffer, size_t size, const std::string& process_name);
    static bool detect_modern_shellcode(const uint8_t* buffer, size_t size);
    
    // 統計和狀態
    MonitorStats get_stats() const;
    std::vector<ExtendedProcessInfo> get_monitored_processes() const;
    std::vector<MemoryRegionInfo> get_monitored_regions() const;
    
    // 配置管理
    void set_scan_interval(uint32_t interval_ms);
    void enable_heap_monitoring(bool enable);
    void enable_stack_monitoring(bool enable);
    void enable_executable_monitoring(bool enable);
    void enable_shared_memory_monitoring(bool enable);
    void update_config(const MemoryMonitorConfig& config);
    
    // 攻擊鏈管理
    void add_to_attack_chain(DWORD process_id, uint64_t address, AttackType attack_type, double confidence);
    void cleanup_old_attack_chains();
    std::vector<AttackChain> get_attack_chains() const;



private:
    // 監控線程
    void monitor_loop();
    void process_monitor_loop();
    void memory_monitor_loop();
    virtual void deep_scan_process(DWORD process_id); // 設為純虛函數
    
    // 內部掃描函數
    void scan_memory_region(const MemoryRegionInfo& region);
    bool check_region_integrity(LPVOID address, SIZE_T size);
    bool check_rop_jop_gadgets(LPVOID address, SIZE_T size);
    bool check_shellcode_signatures(LPVOID address, SIZE_T size);
    bool check_heap_corruption_patterns(LPVOID address, SIZE_T size);
    bool check_use_after_free_patterns(LPVOID address, SIZE_T size);
    bool check_buffer_overflow_patterns(LPVOID address, SIZE_T size);
    
    
    
    // 工具函數
    void report_violation(AttackType type, uint64_t address, 
                         const std::string& description, double confidence, DWORD process_id = 0);
    std::string get_timestamp() const;
    std::string format_address(uint64_t address) const;
    
    // 記憶體操作
    bool is_executable_memory(LPVOID address, SIZE_T size) const;
    bool is_readable_memory(LPVOID address, SIZE_T size) const;
    bool is_writable_memory(LPVOID address, SIZE_T size) const;
    bool safe_read_memory(LPVOID address, SIZE_T size, std::vector<uint8_t>& buffer) const;
    bool check_memory_consistency(HANDLE hProcess, LPVOID base, SIZE_T size);
    
    // 閾值管理
    AdaptiveThresholds get_adaptive_thresholds(MemoryDetectionEngine::ProcessCategory category);
    int get_rop_threshold(MemoryDetectionEngine::ProcessCategory category);
    int get_heap_corruption_threshold(MemoryDetectionEngine::ProcessCategory category);
    int get_shellcode_threshold(MemoryDetectionEngine::ProcessCategory category);
    
    // 配置
    MemoryMonitorConfig config_;
    AdaptiveThresholds adaptive_thresholds_;
    
    // 運行狀態
    std::atomic<bool> running_;
    std::thread monitor_thread_;
    std::thread process_monitor_thread_;
    std::thread memory_monitor_thread_;
    
    // 回調
    MemoryViolationCallback violation_callback_;
    
    // 數據結構
    std::map<DWORD, ExtendedProcessInfo> monitored_processes_;
    std::map<LPVOID, MemoryRegionInfo> monitored_regions_;
    std::map<uint64_t, AttackChain> attack_chains_;
    std::unordered_map<std::string, double> process_entropy_baseline_;
    
    // 統計
    MonitorStats stats_;
    
    // 互斥鎖
    mutable std::mutex processes_mutex_;
    mutable std::mutex regions_mutex_;
    mutable std::mutex stats_mutex_;
    mutable std::mutex attack_chain_mutex_;
    mutable std::mutex entropy_baseline_mutex_;
    
    // 日誌
    std::ofstream log_file_;
    mutable std::mutex log_mutex_;
    
    // 監控標誌
    std::atomic<bool> heap_monitoring_enabled_;
    std::atomic<bool> stack_monitoring_enabled_;
    std::atomic<bool> executable_monitoring_enabled_;
    std::atomic<bool> shared_memory_monitoring_enabled_;
};

} // namespace RealMemoryDetection 