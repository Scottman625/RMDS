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
#include "ring_buffer.hpp"
#include "event_normalizer.hpp"
#include "raw_event_types.hpp"
// debug switches for binary-search disabling
#include "debug_switches.hpp"

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

// 追蹤跨進程可執行頁 (pid+base) key
struct ExecKey {
    DWORD pid;
    uint64_t base;
    bool operator==(const ExecKey& o) const noexcept {
        return pid == o.pid && base == o.base;
    }
};

struct ExecKeyHash {
    size_t operator()(ExecKey const& k) const noexcept {
        return ((size_t)k.pid * 1315423911u) ^ (size_t)k.base;
    }
};

// 完整性檢查鍵值哈希函數
struct IntegrityKeyHash {
    size_t operator()(const std::pair<DWORD, uint64_t>& k) const noexcept {
        return (size_t)k.first ^ ((size_t)k.second << 1);
    }
};

// 新增：可執行頁面資訊結構
struct ExecPageInfo {
    DWORD last_protect;
    uint64_t first_seen_ts;
    uint64_t last_transition_ts;
    bool seen_exec;
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
        MEM_PROTECT_CHANGE,        // 0
        WRITE_PROCESS_MEMORY,      // 1
        CREATE_REMOTE_THREAD,      // 2
        IMAGE_LOAD,                // 3
        FILE_WRITE,                // 4
        HEAP_CORRUPTION,           // 5
        CUSTOM,                    // 6
        
        // 內部任務事件（排程/分析/報表）
        PROCESS_SCAN,              // 7
        MEMORY_REGION_SCAN,        // 8
        EXECUTABLE_INTEGRITY_CHECK, // 9
        HEAP_REGION_CHECK,         // 10
        COMPREHENSIVE_ATTACK_DETECTION, // 11
        ALL_PROCESSES_SCAN,        // 12
        STATUS_OUTPUT,             // 13
        CYCLE_COMPLETION,          // 14
        CLEANUP_SIMULATOR,         // 15
        TERMINATE                  // 16
    };

    // 診斷欄位
    uint32_t struct_version = 1;
    uint32_t sanity = 0xEFBEADDE;  // 魔術數字，用於檢測未初始化

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

    // 預設建構函數 - 確保正確初始化
    Event() : 
        struct_version(1),
        sanity(0xEFBEADDE),
        type(Type::CUSTOM),
        process_id(0),
        address(0),
        size(0),
        timestamp_ms(0),
        process_handle(nullptr),
        process_category(MemoryDetectionEngine::ProcessCategory::USER_PROCESS),
        priority(EventPriority::NORMAL),
        source(EventSource::INTERNAL),
        depth(0),
        flags(0),
        sequence_id(0) {
        memset(&memory_info, 0, sizeof(memory_info));
    }

    // 靜態工廠方法，用於創建特定類型的事件
    static Event make_event(Type t, DWORD pid = 0, uint64_t addr = 0, size_t sz = 0) {
        Event ev{};
        ev.type = t;
        ev.process_id = pid;
        ev.address = addr;
        ev.size = sz;
        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        return ev;
    }

    // 檢查事件是否正確初始化
    bool is_valid() const {
        return sanity == 0xEFBEADDE && struct_version == 1;
    }

    // 獲取事件類型名稱
    std::string get_type_name() const {
        switch (type) {
            case Type::MEM_PROTECT_CHANGE: return "MEM_PROTECT_CHANGE";
            case Type::WRITE_PROCESS_MEMORY: return "WRITE_PROCESS_MEMORY";
            case Type::CREATE_REMOTE_THREAD: return "CREATE_REMOTE_THREAD";
            case Type::IMAGE_LOAD: return "IMAGE_LOAD";
            case Type::FILE_WRITE: return "FILE_WRITE";
            case Type::HEAP_CORRUPTION: return "HEAP_CORRUPTION";
            case Type::CUSTOM: return "CUSTOM";
            case Type::PROCESS_SCAN: return "PROCESS_SCAN";
            case Type::MEMORY_REGION_SCAN: return "MEMORY_REGION_SCAN";
            case Type::EXECUTABLE_INTEGRITY_CHECK: return "EXECUTABLE_INTEGRITY_CHECK";
            case Type::HEAP_REGION_CHECK: return "HEAP_REGION_CHECK";
            case Type::COMPREHENSIVE_ATTACK_DETECTION: return "COMPREHENSIVE_ATTACK_DETECTION";
            case Type::ALL_PROCESSES_SCAN: return "ALL_PROCESSES_SCAN";
            case Type::STATUS_OUTPUT: return "STATUS_OUTPUT";
            case Type::CYCLE_COMPLETION: return "CYCLE_COMPLETION";
            case Type::CLEANUP_SIMULATOR: return "CLEANUP_SIMULATOR";
            case Type::TERMINATE: return "TERMINATE";
            default: return "UNKNOWN";
        }
    }
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
    
    // 禁用複製構造函數和賦值操作符
    EventStats() = default;
    EventStats(const EventStats&) = delete;
    EventStats& operator=(const EventStats&) = delete;
};

// 進程句柄快取項
struct ProcessHandleInfo {
    HANDLE handle;
    std::chrono::steady_clock::time_point last_used;
    uint32_t ref_count;
    bool is_valid;
};

// 擴展的 Event 處理器類別
// EventHandler no longer inherits MemoryMonitor to avoid dual-run race conditions.
class EventHandler {
public:
    // 構造函數和析構函數
    EventHandler();
    EventHandler(const MemoryMonitorConfig& config);
    ~EventHandler();
    
    // 友元函數聲明
    friend void enroll_and_schedule_attack_simulators(RealMemoryDetection::EventHandler* self);
    
    // 啟動和停止
    void start();
    void stop();

    // 新增：事件驅動架構接口
    bool push_raw_event(const RawEvent& raw_event);
    bool push_raw_events(const std::vector<RawEvent>& raw_events);
    const RawEventMPSCRingBuffer::Stats& get_raw_event_stats() const;
    
    // 新增：設置依賴項
    void set_memory_monitor(RealMemoryDetection::MemoryMonitor* monitor);
    void set_detection_engine(void* engine); // 使用 void* 避免循環依賴
    void log_to_detection_engine(const std::string& level, const std::string& message);
    
    // 新增：定時事件調度
    void schedule_periodic_scan();
    void schedule_comprehensive_detection();
    void schedule_status_output();
    void schedule_cycle_completion();
    // expose enqueue and scheduling APIs for external callers
    void enqueue_event(const Event& ev);
    void schedule_suspicious_region(DWORD pid, uint64_t address);
    
    // 新增：統計和監控
    const EventStats& get_stats() const { return stats_; }
    
    // 深度掃描方法 - 需要從外部調用
    void deep_scan_process(DWORD process_id);
    
    // 新增：定時器
    std::chrono::steady_clock::time_point last_scan_time_;
    std::chrono::steady_clock::time_point last_comprehensive_time_;
    std::chrono::steady_clock::time_point last_status_time_;
    std::chrono::steady_clock::time_point last_cycle_time_;
    
    // 新增：掃描配置
    const std::chrono::seconds scan_interval_ = std::chrono::seconds(1); // 縮短到1秒
    const std::chrono::seconds comprehensive_interval_ = std::chrono::seconds(5); // 縮短到5秒
    const std::chrono::seconds status_interval_ = std::chrono::seconds(30); // 縮短到30秒
    const std::chrono::seconds cycle_interval_ = std::chrono::seconds(60); // 縮短到60秒
    int max_regions_to_scan_ = 10;

    // Methods matching MemoryMonitor interface - now as regular methods
    void perform_comprehensive_attack_detection(DWORD process_id, HANDLE hProcess, MemoryDetectionEngine::ProcessCategory category);
    void detect_attack_simulator_patterns(DWORD process_id, HANDLE hProcess);
    void detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess);
    void detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess);
    void detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess);

    // 原有方法
private:
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
    void scan_process_memory(DWORD pid, HANDLE hProcess);
    void show_status();
    void cleanup_simulator_output_controls();
    void check_executable_integrity(LPVOID base_address, SIZE_T region_size, DWORD pid, int depth = 0);
    void check_heap_region(DWORD pid, LPVOID base_address, SIZE_T region_size);
    // 新增：檢測方法（已在 override 部分聲明）
    
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
    void add_exec_watch(uint64_t addr);
    
    // 新增：事件驅動架構相關
    RawEventMPSCRingBuffer raw_event_buffer_;
    std::thread real_time_ingest_thread_;
    std::atomic<bool> ingest_running_;

    // ====== 補齊缺失的內部狀態 ======
    std::atomic<bool> running_{false};
    std::atomic<bool> shutting_down_{false};
    std::atomic<bool> scheduler_running_{false};
    
    // 世代計數器
    std::atomic<uint64_t> handler_generation_{0};
    
    // 執行緒
    std::thread fast_event_thread_;
    std::thread deferred_analyzer_thread_;  
    std::thread scheduler_thread_;
    
    // 事件佇列和同步
    std::deque<Event> event_queue_;
    std::deque<Event> high_priority_queue_;
    std::mutex event_mutex_;  // 與 cpp 中使用的名稱一致
    std::mutex event_queue_mutex_;
    std::condition_variable event_cv_;
    
    // 快速事件處理配置
    size_t fast_batch_size_ = 128;
    int fast_interval_ms_ = 50;
    
    // 可疑區域管理配置
    size_t deferred_batch_limit_ = 200;
    std::chrono::seconds deferred_interval_ = std::chrono::seconds(1);
    std::chrono::seconds suspicious_cooldown_ = std::chrono::seconds(5);
    size_t max_suspicious_queue_ = 5000;
    
    // 進程句柄快取
    std::unordered_map<DWORD, ProcessHandleInfo> process_handle_cache_;
    std::mutex process_handle_mutex_;
    
    // 可疑區域管理
    std::mutex suspicious_mutex_;
    std::deque<SuspiciousKey> suspicious_regions_;
    std::unordered_set<SuspiciousKey, SuspiciousKeyHash> suspicious_set_;
    std::unordered_map<SuspiciousKey, std::chrono::steady_clock::time_point, SuspiciousKeyHash> suspicious_last_seen_;
    
    // 可執行頁面追蹤
    std::mutex exec_pages_mutex_;
    std::unordered_map<ExecKey, ExecPageInfo, ExecKeyHash> exec_pages_;
    
    // watchlist
    std::unordered_set<uint64_t> forced_watch_;
    std::mutex watch_mtx_;
    
    // 完整性檢查計數
    std::mutex integrity_mutex_;
    std::unordered_map<std::pair<DWORD, uint64_t>, uint8_t, IntegrityKeyHash> integrity_recheck_count_;
    
    // 依賴指針
    RealMemoryDetection::MemoryMonitor* memory_monitor_ = nullptr;
    void* detection_engine_ = nullptr;

    // 計數器和統計
    std::atomic<uint32_t> status_tick_counter_{0};
    std::atomic<uint32_t> comprehensive_tick_counter_{0};
    std::atomic<uint64_t> total_detections_{0};
    
    // EventHandler 專用統計
    EventStats stats_;
    
    // 新增：實時事件攝取方法
    void real_time_ingest_loop();
    void process_normalized_events();
    void convert_normalized_to_event(const PageTransitionEvent& normalized_event);
    void convert_normalized_to_event(const CrossProcessWriteEvent& normalized_event);
    void convert_normalized_to_event(const RemoteExecutionChainEvent& normalized_event);
    void convert_normalized_to_event(const DarkExecEvent& normalized_event);
};

} // namespace RealMemoryDetection
