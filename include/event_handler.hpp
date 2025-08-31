#pragma once

#include <windows.h>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include "utils/process_lists.hpp"
#include "event_utils.hpp"

// 前向聲明
namespace RealMemoryDetection {
    class MemoryMonitor;
}

namespace RealMemoryDetection {

// 可疑頁面鍵值結構 - 修復跨進程地址衝突
struct SuspiciousKey {
    DWORD pid;
    uint64_t page; // page-aligned
    
    bool operator==(const SuspiciousKey& o) const noexcept {
        return pid == o.pid && page == o.page;
    }
};

// 可疑頁面鍵值哈希函數
struct SuspiciousKeyHash {
    size_t operator()(const SuspiciousKey& k) const noexcept {
        return (size_t)k.page ^ ((size_t)k.pid << 1);
    }
};

// 完整性檢查鍵值哈希函數
struct IntegrityKeyHash {
    size_t operator()(const std::pair<DWORD, uint64_t>& k) const noexcept {
        return (size_t)k.first ^ ((size_t)k.second << 1);
    }
};

// 可疑頁面條目
struct SuspiciousEntry {
    SuspiciousKey key;
    std::chrono::steady_clock::time_point last_seen;
    uint8_t analysis_count;
    uint8_t flags; // bit0=high_risk, bit1=recently_analyzed
};

// 事件優先級枚舉
enum class EventPriority : uint8_t {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

// 事件來源枚舉
enum class EventSource : uint8_t {
    RAW = 0,        // 來自 hook/ETW
    INTERNAL = 1,   // 內部排程任務
    DERIVED = 2     // 衍生分析事件
};

// 擴展 Event 結構定義
struct Event {
    enum class Type : uint8_t {
        // 原始行為事件（來自 hook/ETW）
        MEM_PROTECT_CHANGE,
        WRITE_PROCESS_MEMORY,
        CREATE_REMOTE_THREAD,
        IMAGE_LOAD,
        FILE_WRITE,
        HEAP_CORRUPTION,
        CUSTOM,
        
        // 內部任務事件（排程/分析/報表）
        PROCESS_SCAN,           // 進程掃描事件
        MEMORY_REGION_SCAN,     // 記憶體區域掃描事件
        EXECUTABLE_INTEGRITY_CHECK, // 可執行檔案完整性檢查
        HEAP_REGION_CHECK,      // 堆區域檢查
        COMPREHENSIVE_ATTACK_DETECTION, // 綜合攻擊檢測
        ALL_PROCESSES_SCAN,     // 全進程掃描
        STATUS_OUTPUT,          // 狀態輸出
        CYCLE_COMPLETION,       // 循環完成
        CLEANUP_SIMULATOR,      // 清理模擬器
        TERMINATE               // 終止事件
    };

    Type type;
    DWORD process_id;
    uint64_t address;
    size_t size;
    uint64_t timestamp_ms;
    std::string meta; // optional extra info (e.g., module path)
    
    // 新增欄位用於擴展功能
    HANDLE process_handle;
    MemoryDetectionEngine::ProcessCategory process_category;
    MEMORY_BASIC_INFORMATION memory_info;
    std::vector<uint8_t> memory_data;
    
    // 新增欄位用於事件控制
    EventPriority priority;
    EventSource source;
    uint8_t depth;              // 防止無限遞迴
    uint8_t flags;              // bit0=reanalysis, bit1=high_risk
    uint32_t sequence_id;       // 事件序列號
};

// 事件統計結構
struct EventStats {
    std::atomic<uint64_t> events_in{0};
    std::atomic<uint64_t> events_dropped{0};
    std::atomic<uint64_t> events_dropped_high{0};
    std::atomic<uint64_t> peak_queue_length{0};
    std::atomic<uint64_t> confirmed_findings{0};
    std::atomic<uint64_t> scan_runs{0};
    
    // 延遲統計
    std::atomic<uint64_t> total_queue_wait_time{0};
    std::atomic<uint64_t> queue_wait_count{0};
    
    // 可疑區域統計
    std::atomic<uint64_t> suspicious_regions_analyzed{0};
    std::atomic<uint64_t> reanalysis_skipped{0};
};

// 進程句柄快取項
struct ProcessHandleInfo {
    HANDLE handle;
    std::chrono::steady_clock::time_point last_used;
    uint32_t ref_count;
    bool is_valid;
};

// 擴展的 Event 處理器類別
class EventHandler {
public:
    EventHandler();
    ~EventHandler();

    // 基本操作
    void start();
    void stop();
    void enqueue_event(const Event& ev);
    void schedule_suspicious_region(DWORD pid, uint64_t address);
    
    // 新增：設置依賴項
    void set_memory_monitor(MemoryMonitor* monitor);
    void set_detection_engine(void* engine); // 使用 void* 避免循環依賴
    
    // 新增：定時事件調度
    void schedule_periodic_scan();
    void schedule_comprehensive_detection();
    void schedule_status_output();
    void schedule_cycle_completion();
    
    // 新增：統計和監控
    const EventStats& get_stats() const { return stats_; }

private:
    // 原有成員
    std::mutex event_mutex_;
    std::condition_variable event_cv_;
    std::deque<Event> event_queue_;
    std::deque<Event> high_priority_queue_; // 新增高優先級佇列
    size_t fast_batch_size_ = 128;
    int fast_interval_ms_ = 50;

    // 改良的可疑區域管理
    std::mutex suspicious_mutex_;
    std::deque<SuspiciousKey> suspicious_regions_;
    std::unordered_set<SuspiciousKey, SuspiciousKeyHash> suspicious_set_;
    std::unordered_map<SuspiciousKey, std::chrono::steady_clock::time_point, SuspiciousKeyHash> suspicious_last_seen_;
    size_t deferred_batch_limit_ = 200;
    std::chrono::seconds deferred_interval_ = std::chrono::seconds(1);
    std::chrono::seconds suspicious_cooldown_ = std::chrono::seconds(5);
    size_t max_suspicious_queue_ = 5000;

    // 進程句柄快取
    std::mutex process_handle_mutex_;
    std::unordered_map<DWORD, ProcessHandleInfo> process_handle_cache_;

    // 完整性檢查重複計數
    std::mutex integrity_mutex_;
    std::unordered_map<std::pair<DWORD, uint64_t>, uint8_t, IntegrityKeyHash> integrity_recheck_count_;

    std::thread fast_event_thread_;
    std::thread deferred_analyzer_thread_;
    std::atomic<bool> running_;
    
    // 新增：定時調度線程
    std::thread scheduler_thread_;
    std::atomic<bool> scheduler_running_;
    
    // 新增：依賴項
    MemoryMonitor* memory_monitor_;
    void* detection_engine_; // 使用 void* 避免循環依賴
    
    // 新增：計數器和狀態
    std::atomic<int> status_tick_counter_{0};
    std::atomic<int> comprehensive_tick_counter_{0};
    std::atomic<int> total_detections_{0};
    
    // 新增：統計
    EventStats stats_;
    
    // 新增：定時器
    std::chrono::steady_clock::time_point last_scan_time_;
    std::chrono::steady_clock::time_point last_comprehensive_time_;
    std::chrono::steady_clock::time_point last_status_time_;
    std::chrono::steady_clock::time_point last_cycle_time_;
    
    // 新增：掃描配置
    const std::chrono::seconds scan_interval_ = std::chrono::seconds(10);
    const std::chrono::seconds comprehensive_interval_ = std::chrono::seconds(10);
    const std::chrono::seconds status_interval_ = std::chrono::seconds(60);
    const std::chrono::seconds cycle_interval_ = std::chrono::seconds(300);
    const int max_regions_to_scan_ = 10;

    // 原有方法
    void analyze_event_batch(const std::vector<Event>& batch);
    void fast_event_loop();
    void deferred_analyzer_loop();
    
    // 新增：定時調度方法
    void scheduler_loop();
    void process_scheduled_events();
    
    // 新增：事件處理方法
    void handle_process_scan_event(const Event& ev);
    void handle_memory_region_scan_event(const Event& ev);
    void handle_executable_integrity_check_event(const Event& ev);
    void handle_heap_region_check_event(const Event& ev);
    void handle_comprehensive_attack_detection_event(const Event& ev);
    void handle_all_processes_scan_event(const Event& ev);
    void handle_status_output_event(const Event& ev);
    void handle_cycle_completion_event(const Event& ev);
    void handle_cleanup_simulator_event(const Event& ev);
    
    // 新增：輔助方法
    void scan_memory_for_attacks();
    void scan_all_processes_memory();
    void show_status();
    void cleanup_simulator_output_controls();
    void check_executable_integrity(LPVOID base_address, SIZE_T region_size, DWORD pid, int depth = 0);
    void check_heap_region(LPVOID base_address, SIZE_T region_size);
    void perform_comprehensive_attack_detection(DWORD process_id, HANDLE hProcess, MemoryDetectionEngine::ProcessCategory category);
    
    // 新增：檢測方法
    void detect_attack_simulator_patterns(DWORD process_id, HANDLE hProcess);
    void detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess);
    void detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess);
    void detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess);
    
    // 新增：進程句柄管理
    HANDLE get_process_handle(DWORD pid);
    void cleanup_process_handles();
    
    // 新增：事件優先級處理
    void enqueue_event_with_priority(const Event& ev);
    std::vector<Event> get_event_batch();
    
    // 新增：統計更新
    void update_stats_on_enqueue();
    void update_stats_on_drop(bool is_high_priority);
    void update_stats_on_finding();
    void update_stats_on_scan();
};

} // namespace RealMemoryDetection
