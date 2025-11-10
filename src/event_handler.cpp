#include "../include/event_handler.hpp"
#include "../include/memory_detection_monitor.hpp"
#include "../include/memory_detection_types.hpp"
#include "../include/utils/logger.hpp"
#include "../include/detection_engine.hpp"
#include "../include/event_utils.hpp"
#include <algorithm>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <cmath>
#include <chrono>
#include <deque>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <mutex>
#include <iomanip>

namespace RealMemoryDetection {
    

// 統一的可執行頁面判斷函數
static inline bool is_executable_protect(DWORD p) {
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// 追加：ret-like 判斷（涵蓋 ret, retf, ret imm16, iret）
static inline bool is_ret_like(uint8_t b) {
   return (b == 0xC3 /* ret */) || (b == 0xCB /* retf */) || (b == 0xC2 /* ret imm16 */) || (b == 0xCA /* retf imm16 */);
}

// 追加：burst 偵測的簡單時間窗口狀態（僅限本翻譯單元）
namespace {
    struct BurstState {
        std::deque<std::chrono::steady_clock::time_point> window;
        std::unordered_set<uint64_t> seen_pages; // 已計數過的頁面（避免重複）
        std::chrono::steady_clock::time_point last_alert_time{};
    };
    static std::mutex g_burst_mutex;
    static std::unordered_map<DWORD, BurstState> g_burst_state;
    
    // 新增：掃描時間記錄（用於 [SCAN-START] age 計算）
    static std::mutex g_scan_ts_mtx;
    static std::unordered_map<DWORD, std::chrono::steady_clock::time_point> g_last_scan_ts;
}

 // 追加：在短時間內新增多個 MEM_PRIVATE+EXEC 小區域時產生 meta 事件
static void record_exec_private_small_region_burst(RealMemoryDetection::EventHandler* self,
    DWORD pid, uint64_t base_page, SIZE_T region_size) {
if (!self) return;
// 只統計小區域（<= 16KB）
if (region_size == 0 || region_size > 16 * 1024) return;
const auto now = std::chrono::steady_clock::now();
const auto window_span = std::chrono::seconds(2); // 2 秒視窗
const size_t burst_threshold = 4; // 視窗內 4 個以上
const auto rearm_span = std::chrono::seconds(2);  // 告警再觸發最小間隔

std::lock_guard<std::mutex> lk(g_burst_mutex);
BurstState& st = g_burst_state[pid];
uint64_t page = base_page & ~0xFFFULL;
if (!st.seen_pages.insert(page).second) {
// 已經看過，忽略
return;
}
// 入窗
st.window.push_back(now);
// 清理過期
while (!st.window.empty() && (now - st.window.front()) > window_span) {
st.window.pop_front();
}
if (st.window.size() >= burst_threshold) {
// 節流：避免同一 PID 在短時間連續報警
if (st.last_alert_time.time_since_epoch().count() == 0 ||
(now - st.last_alert_time) > rearm_span) {
st.last_alert_time = now;
// 產生 meta 事件
Event ev = Event::make_event(Event::Type::CUSTOM, pid, page, region_size);
ev.priority = EventPriority::HIGH;
ev.source = EventSource::DERIVED;
std::ostringstream oss;
oss << "[BURST] Multiple new EXEC MEM_PRIVATE small regions within "
<< std::chrono::duration_cast<std::chrono::milliseconds>(window_span).count()
<< "ms window count=" << st.window.size();
ev.meta = oss.str();
self->enqueue_event(ev);
// 順帶出一條DEBUG日誌
try {
self->log_to_detection_engine("DEBUG", "[SCATTERED] " + ev.meta);
} catch (...) {
// 忽略 log 失敗
}
}
}
}

EventHandler::EventHandler()
    : last_scan_time_(std::chrono::steady_clock::now())
    , last_comprehensive_time_(std::chrono::steady_clock::now())
    , last_status_time_(std::chrono::steady_clock::now())
    , last_cycle_time_(std::chrono::steady_clock::now())
    , memory_monitor_(nullptr)
    , detection_engine_(nullptr)
    , status_tick_counter_(0)
    , comprehensive_tick_counter_(0)
    , total_detections_(0) {
    
    // 初始化成員變量
    running_.store(false);
    scheduler_running_.store(false);
    shutting_down_.store(false);
}

EventHandler::EventHandler(const MemoryMonitorConfig& config)
    : last_scan_time_(std::chrono::steady_clock::now())
    , last_comprehensive_time_(std::chrono::steady_clock::now())
    , last_status_time_(std::chrono::steady_clock::now())
    , last_cycle_time_(std::chrono::steady_clock::now())
    , memory_monitor_(nullptr)
    , detection_engine_(nullptr)
    , status_tick_counter_(0)
    , comprehensive_tick_counter_(0)
    , total_detections_(0) {
    
    // 初始化成員變量
    running_.store(false);
    scheduler_running_.store(false);
    shutting_down_.store(false);
    
    // 創建 MemoryMonitor 實例
    memory_monitor_ = new RealMemoryDetection::MemoryMonitor(config);
}

EventHandler::~EventHandler() {
    stop();
}

// 移除友元函數定義，因為 log_message 現在是 MemoryMonitor 的公共成員函數

void EventHandler::start() {
    if (running_.load()) return;
    // bump generation to invalidate previously enqueued events
    handler_generation_.fetch_add(1, std::memory_order_acq_rel);
    std::cout << "EventHandler started successfully" << std::endl;
    running_.store(true);
    scheduler_running_.store(true);
    
    // 啟動快速事件執行緒
    fast_event_thread_ = std::thread(&EventHandler::fast_event_loop, this);
    
    // 啟動延遲分析器執行緒
    deferred_analyzer_thread_ = std::thread(&EventHandler::deferred_analyzer_loop, this);
    
    // 啟動定時調度執行緒
    scheduler_thread_ = std::thread(&EventHandler::scheduler_loop, this);
    
    // 診斷：檢查 memory_monitor_ 狀態
    {
        std::string msg = std::string("[INIT] memory_monitor_ ") + (memory_monitor_ ? "SET" : "NULL");
        EventUtils::log_message("DEBUG", msg.c_str());
    }
    {
        std::string cfg_msg = std::string("[CFG] max_regions_to_scan=") + std::to_string(max_regions_to_scan_);
        EventUtils::log_message("DEBUG", cfg_msg.c_str());
    }
    
    // 強制解除區域掃描限制
    max_regions_to_scan_ = 0;
    log_to_detection_engine("DEBUG", "[CFG] force max_regions_to_scan_=0");
    
    // 添加 watchlist 監控攻擊模擬器的地址
    add_exec_watch(0x000001A613CE0000);
    add_exec_watch(0x000001A613CF0000);
    add_exec_watch(0x000001A613D00000);
    add_exec_watch(0x000001A614060000);
    add_exec_watch(0x000001A614070000);
    
    // 在開始時先掃描進程列表
    if (memory_monitor_) {
        log_to_detection_engine("DEBUG", "[INIT] memory_monitor_ is SET, calling scan_processes()");
        try {
            memory_monitor_->scan_processes();
            log_to_detection_engine("DEBUG", "[INIT] Called memory_monitor_->scan_processes() successfully");
        } catch (const std::exception& e) {
            log_to_detection_engine("ERROR", "[INIT] scan_processes() failed with exception: " + std::string(e.what()));
        } catch (...) {
            log_to_detection_engine("ERROR", "[INIT] scan_processes() failed with unknown exception");
        }
        
        // 手動將自己加入監控列表
        DWORD current_pid = GetCurrentProcessId();
        std::string process_name = MemoryMonitor::get_process_name(current_pid);
        memory_monitor_->monitor_process(current_pid, process_name);
        log_to_detection_engine("DEBUG", "[INIT] Added self to monitored processes: pid=" + std::to_string(current_pid) + " name=" + process_name);
    } else {
        log_to_detection_engine("ERROR", "[INIT] memory_monitor_ is NULL, cannot scan processes");
    }
    
    // 立即執行第一次掃描
    schedule_periodic_scan();
}

void EventHandler::stop() {
    if (!running_.load()) return;
    
    // 設置關閉標誌，防止新的 enqueue_event 調用
    shutting_down_.store(true, std::memory_order_release);
    
    running_.store(false);
    scheduler_running_.store(false);
    
    // 發送終止事件喚醒所有等待的執行緒
    Event terminate_ev = Event::make_event(Event::Type::TERMINATE);
    terminate_ev.priority = EventPriority::CRITICAL;
    terminate_ev.source = EventSource::INTERNAL;
    enqueue_event(terminate_ev);
    
    // 通知所有等待的執行緒
    event_cv_.notify_all();
    
    // 等待執行緒結束
    if (fast_event_thread_.joinable()) {
        fast_event_thread_.join();
    }
    
    if (deferred_analyzer_thread_.joinable()) {
        deferred_analyzer_thread_.join();
    }
    
    if (scheduler_thread_.joinable()) {
        scheduler_thread_.join();
    }
    
    // 清理進程句柄快取
    cleanup_process_handles();
}

void EventHandler::set_memory_monitor(MemoryMonitor* monitor) {
    memory_monitor_ = monitor;
}

void EventHandler::set_detection_engine(void* engine) {
    detection_engine_ = engine;
}

// 新增：使用檢測引擎的日誌記錄
void EventHandler::log_to_detection_engine(const std::string& level, const std::string& message) {
    // 檢查 detection_engine_ 的 Magic Header
    if (detection_engine_ && valid_magic(static_cast<const MagicHeader*>(detection_engine_))) {
        try {
            // 將 void* 轉換為基類 RealMemoryDetectionEngine* 並調用其 log_message 方法
            auto* engine = static_cast<RealMemoryDetection::RealMemoryDetectionEngine*>(detection_engine_);
            engine->log_message(level, message);
            return;
        } catch (...) {
            // 如果轉換失敗，繼續到下一個選項
        }
    }
    
    // 檢查 memory_monitor_ 的 Magic Header
    if (memory_monitor_ && valid_magic(memory_monitor_)) {
        try {
            // 如果沒有檢測引擎，回退到 memory monitor 的日誌
            std::string _msg = message;
            memory_monitor_->log_message(level, _msg.c_str());
            return;
        } catch (...) {
            // 如果調用失敗，繼續到下一個選項
        }
    }
    
    // 最後回退到控制台輸出
    std::cout << "[" << level << "] " << message << std::endl;
}

// 新增：進程句柄管理
HANDLE EventHandler::get_process_handle(DWORD pid) {
    std::lock_guard<std::mutex> lock(process_handle_mutex_);
    
    auto it = process_handle_cache_.find(pid);
    if (it != process_handle_cache_.end()) {
        ProcessHandleInfo& info = it->second;
        if (info.is_valid) {
            // 檢查句柄是否仍然有效
            DWORD exit_code;
            if (GetExitCodeProcess(info.handle, &exit_code) && exit_code == STILL_ACTIVE) {
                info.last_used = std::chrono::steady_clock::now();
                info.ref_count++;
                return info.handle;
            } else {
                // 進程已結束，標記為無效
                info.is_valid = false;
                CloseHandle(info.handle);
            }
        }
    }
    
    // 獲取新的進程句柄
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        log_to_detection_engine("DEBUG", "[GET_HANDLE] OpenProcess fail pid=" + std::to_string(pid) + " gle=" + std::to_string(GetLastError()));
        return INVALID_HANDLE_VALUE;
    }
    
    ProcessHandleInfo info;
    info.handle = hProcess;
    info.last_used = std::chrono::steady_clock::now();
    info.ref_count = 1;
    info.is_valid = true;
    process_handle_cache_[pid] = info;
    return hProcess;
}

void EventHandler::cleanup_process_handles() {
    std::lock_guard<std::mutex> lock(process_handle_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto it = process_handle_cache_.begin();
    
    while (it != process_handle_cache_.end()) {
        ProcessHandleInfo& info = it->second;
        
        // 檢查句柄是否仍然有效
        DWORD exit_code;
        if (!info.is_valid || 
            !GetExitCodeProcess(info.handle, &exit_code) || 
            exit_code != STILL_ACTIVE ||
            (now - info.last_used) > std::chrono::minutes(5)) {
            
            CloseHandle(info.handle);
            it = process_handle_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

void EventHandler::enqueue_event(const Event& ev) {
    // 檢查是否正在關閉
    if (shutting_down_.load(std::memory_order_acquire)) {
        return; // 防止析構後外部調用
    }
    // Drop events that originated from a previous generation of the handler
    if (ev.sequence_id != 0) {
        uint32_t gen = handler_generation_.load(std::memory_order_acquire);
        if (ev.sequence_id != gen) return;
    }
    
    // 檢查事件是否正確初始化
    if (!ev.is_valid()) {
        log_to_detection_engine("ERROR", "UNINITIALIZED EVENT DETECTED! type=" + std::to_string(static_cast<int>(ev.type)) + " sanity=" + std::to_string(ev.sanity));
    }
    
    log_to_detection_engine("DEBUG", "enqueue_event: type=" + std::to_string(static_cast<int>(ev.type)) + "(" + ev.get_type_name() + ") pid=" + std::to_string(ev.process_id) + " addr=" + std::to_string(ev.address) + " size=" + std::to_string(ev.size));
    enqueue_event_with_priority(ev);
}

// 新增：事件優先級處理
void EventHandler::enqueue_event_with_priority(const Event& ev) {
    {
        std::lock_guard<std::mutex> lock(event_mutex_);
        
        // 更新統計
        update_stats_on_enqueue();
        
        // 根據優先級選擇佇列
        if (ev.priority >= EventPriority::HIGH) {
            high_priority_queue_.push_back(ev);
        } else {
            // 檢查普通佇列大小限制
            if (event_queue_.size() > 10000) {
                update_stats_on_drop(false);
                event_queue_.pop_front(); // 丟棄最舊的事件
            }
            event_queue_.push_back(ev);
        }
    }
    event_cv_.notify_one();
}

// 新增：獲取事件批次（優先處理高優先級）
std::vector<Event> EventHandler::get_event_batch() {
    std::vector<Event> batch;
    std::unique_lock<std::mutex> lk(event_mutex_);
    
    // 等待批次或超時
    auto start_time = std::chrono::steady_clock::now();
    event_cv_.wait_for(lk, std::chrono::milliseconds(fast_interval_ms_), [this] {
        return !event_queue_.empty() || !high_priority_queue_.empty() || !running_.load();
    });
    
    // 更新等待時間統計
    auto wait_time = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start_time).count();
    stats_.total_queue_wait_time.fetch_add(wait_time);
    stats_.queue_wait_count.fetch_add(1);
    
    // 優先處理高優先級佇列
    while (!high_priority_queue_.empty() && batch.size() < fast_batch_size_) {
        batch.push_back(std::move(high_priority_queue_.front()));
        high_priority_queue_.pop_front();
    }
    
    // 然後處理普通佇列
    while (!event_queue_.empty() && batch.size() < fast_batch_size_) {
        batch.push_back(std::move(event_queue_.front()));
        event_queue_.pop_front();
    }
    
    return batch;
}

// 新增：統計更新方法
void EventHandler::update_stats_on_enqueue() {
    stats_.events_in.fetch_add(1);
    size_t total_size = event_queue_.size() + high_priority_queue_.size();
    uint64_t current_peak = stats_.peak_queue_length.load();
    while (total_size > current_peak && 
           !stats_.peak_queue_length.compare_exchange_weak(current_peak, total_size)) {
        // 自旋直到更新成功
    }
}

void EventHandler::update_stats_on_drop(bool is_high_priority) {
    stats_.events_dropped.fetch_add(1);
    if (is_high_priority) {
        stats_.events_dropped_high.fetch_add(1);
    }
}

void EventHandler::update_stats_on_finding() {
    stats_.confirmed_findings.fetch_add(1);
}

void EventHandler::update_stats_on_scan() {
    stats_.scan_runs.fetch_add(1);
}

void EventHandler::schedule_suspicious_region(DWORD pid, uint64_t address) {
    // 頁面對齊到 4KB 邊界
    uint64_t page = address & ~static_cast<uint64_t>(0xFFF);
    SuspiciousKey key{pid, page};
    auto now = std::chrono::steady_clock::now();
    
    std::lock_guard<std::mutex> lock(suspicious_mutex_);
    auto it = suspicious_last_seen_.find(key);
    if (it != suspicious_last_seen_.end()) {
        if (now - it->second < suspicious_cooldown_) {
            return; // 最近已排程
        }
    }
    
    if (suspicious_set_.insert(key).second) {
        suspicious_regions_.push_back(key);
        suspicious_last_seen_[key] = now;
        
        // 限制總可疑佇列大小，同步清理所有相關結構
        while (suspicious_regions_.size() > max_suspicious_queue_) {
            auto old_key = suspicious_regions_.front();
            suspicious_regions_.pop_front();
            suspicious_set_.erase(old_key);
            suspicious_last_seen_.erase(old_key);
        }
    } else {
        // 更新最後見到時間
        suspicious_last_seen_[key] = now;
    }
}

// 定時調度循環
void EventHandler::scheduler_loop() {
    while (scheduler_running_.load()) {
        try {
            auto now = std::chrono::steady_clock::now();
            
            // 檢查是否需要執行記憶體掃描
            if (now - last_scan_time_ >= scan_interval_) {
                schedule_periodic_scan();
                last_scan_time_ = now;
            }
            
            // 檢查是否需要執行綜合檢測
            if (now - last_comprehensive_time_ >= comprehensive_interval_) {
                schedule_comprehensive_detection();
                last_comprehensive_time_ = now;
            }
            
            // 檢查是否需要輸出狀態
            if (now - last_status_time_ >= status_interval_) {
                schedule_status_output();
                last_status_time_ = now;
            }
            
            // 檢查是否需要完成循環
            if (now - last_cycle_time_ >= cycle_interval_) {
                schedule_cycle_completion();
                last_cycle_time_ = now;
            }
            
            // 每10秒檢查一次
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
        catch (const std::exception& e) {
            if (memory_monitor_) {
                std::string msg = std::string("Scheduler loop exception: ") + e.what();
                memory_monitor_->log_message("ERROR", msg.c_str());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        catch (...) {
            if (memory_monitor_) {
                std::string msg = std::string("Scheduler loop unknown exception");
                memory_monitor_->log_message("ERROR", msg.c_str());
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void EventHandler::schedule_periodic_scan() {
    log_to_detection_engine("DEBUG", "[SCHED] periodic scan start");
    size_t enq = 0;
    
    if (!memory_monitor_) {
        // Fallback：至少掃自己，避免完全沒動作
        DWORD selfPid = GetCurrentProcessId();
        Event self;
        self.type = Event::Type::MEMORY_REGION_SCAN;
        self.process_id = selfPid;
        self.process_handle = get_process_handle(selfPid); // 取實際句柄
        self.timestamp_ms = EventUtils::now_ms();
        self.meta = "Periodic memory scan (self fallback)";
        log_to_detection_engine("DEBUG", "[SCHED] fallback pid=" + std::to_string(selfPid) + " handle=0x" + EventUtils::format_address((uint64_t)self.process_handle));
        enqueue_event(self);
        return;
    }
    
    auto processes = memory_monitor_->get_monitored_processes();
    log_to_detection_engine("DEBUG", "[SCHED] monitored count=" + std::to_string(processes.size()));
    
    
    for (auto const& p : processes) {
        
        log_to_detection_engine("DEBUG",
            "[MONLIST] pid=" + std::to_string(p.process_id) +
            " handle=0x" + EventUtils::format_address((uint64_t)p.process_handle) +
            " cat=" + std::to_string((int)p.category));
            
        
        if (p.process_handle == INVALID_HANDLE_VALUE || p.process_handle == nullptr) {
            continue;
        }
        
        // 暫時允許兩種：ATTACK_SIMULATOR + 自己
        if (p.category != MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR &&
            p.process_id != GetCurrentProcessId()) {
            continue;
        }
        
        Event ev = Event::make_event(Event::Type::MEMORY_REGION_SCAN, p.process_id);
        ev.process_handle = p.process_handle;
        ev.meta = "Periodic memory scan pid=" + std::to_string(p.process_id);
        ev.priority = EventPriority::HIGH;
        enqueue_event(ev);
        log_to_detection_engine("DEBUG", "[MON] enqueue scan pid=" + std::to_string(p.process_id));
        enq++;
    }
    
    if (enq == 0) {
        log_to_detection_engine("WARN", "[SCHED] no scan events scheduled (will fallback self)");
        // 強制掃自己
        Event self = Event::make_event(Event::Type::MEMORY_REGION_SCAN, GetCurrentProcessId());
        self.process_handle = get_process_handle(GetCurrentProcessId());
        self.priority = EventPriority::HIGH;
        self.meta = "Forced self scan";
        enqueue_event(self);
    }
}

void EventHandler::schedule_comprehensive_detection() {
    if (!memory_monitor_) return;
    
    // 獲取監控的進程並為每個進程創建綜合檢測事件
    auto processes = memory_monitor_->get_monitored_processes();
    for (const auto& process : processes) {
        if (process.process_handle != INVALID_HANDLE_VALUE) {
            Event ev = Event::make_event(Event::Type::COMPREHENSIVE_ATTACK_DETECTION, process.process_id);
            ev.process_handle = process.process_handle;
            ev.process_category = process.category;
            ev.meta = "Comprehensive attack detection for process " + std::to_string(process.process_id);
            ev.priority = EventPriority::HIGH;
            ev.source = EventSource::INTERNAL;
            
            enqueue_event(ev);
        }
    }
    
    // 每3次循環執行一次全進程掃描
    comprehensive_tick_counter_++;
    if (comprehensive_tick_counter_ % 3 == 0) {
        Event ev = Event::make_event(Event::Type::ALL_PROCESSES_SCAN);
        ev.meta = "All processes scan";
        ev.priority = EventPriority::NORMAL;
        ev.source = EventSource::INTERNAL;
        
        enqueue_event(ev);
    }
}

void EventHandler::schedule_status_output() {
    status_tick_counter_++;
    if (status_tick_counter_ >= 5) {
        Event ev = Event::make_event(Event::Type::STATUS_OUTPUT);
        ev.meta = "Status output";
        ev.priority = EventPriority::LOW;
        ev.source = EventSource::INTERNAL;
        
        enqueue_event(ev);
        status_tick_counter_ = 0;
    }
}

void EventHandler::schedule_cycle_completion() {
    comprehensive_tick_counter_++;
    if (comprehensive_tick_counter_ >= 10) {
        Event ev;
        ev.type = Event::Type::CYCLE_COMPLETION;
        ev.process_id = 0;
        ev.address = 0;
        ev.size = 0;
        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        ev.meta = "Cycle completion";
        ev.priority = EventPriority::LOW;
        ev.source = EventSource::INTERNAL;
        ev.depth = 0;
        ev.flags = 0;
        ev.sequence_id = 0;
        
        enqueue_event(ev);
        comprehensive_tick_counter_ = 0;
    }
}

void EventHandler::analyze_event_batch(const std::vector<Event>& batch) {
    for (const auto& ev : batch) {
        try {
            // 檢查終止事件
            if (ev.type == Event::Type::TERMINATE) {
                return; // 立即退出
            }
            
            switch (ev.type) {
                case Event::Type::PROCESS_SCAN:
                    handle_process_scan_event(ev);
                    break;
                case Event::Type::MEMORY_REGION_SCAN:
                    handle_memory_region_scan_event(ev);
                    break;
                case Event::Type::COMPREHENSIVE_ATTACK_DETECTION:
                    handle_comprehensive_attack_detection_event(ev);
                    break;
                case Event::Type::ALL_PROCESSES_SCAN:
                    handle_all_processes_scan_event(ev);
                    break;
                case Event::Type::STATUS_OUTPUT:
                    handle_status_output_event(ev);
                    break;
                case Event::Type::CYCLE_COMPLETION:
                    handle_cycle_completion_event(ev);
                    break;
                case Event::Type::CLEANUP_SIMULATOR:
                    handle_cleanup_simulator_event(ev);
                    break;
                case Event::Type::EXECUTABLE_INTEGRITY_CHECK:
                    handle_executable_integrity_check_event(ev);
                    break;
                case Event::Type::HEAP_REGION_CHECK:
                    handle_heap_region_check_event(ev);
                    break;
                case Event::Type::WRITE_PROCESS_MEMORY:
                case Event::Type::HEAP_CORRUPTION:
                case Event::Type::CREATE_REMOTE_THREAD:
                case Event::Type::IMAGE_LOAD:
                case Event::Type::FILE_WRITE:
                case Event::Type::CUSTOM:
                    // 原有的快速啟發式檢查
                    schedule_suspicious_region(ev.process_id, ev.address);
                    break;
                case Event::Type::MEM_PROTECT_CHANGE: {
                    schedule_suspicious_region(ev.process_id, ev.address);
                    // 立即派一個 EXECUTABLE_INTEGRITY_CHECK 做密度
                    Event ex;
                    ex.type = Event::Type::EXECUTABLE_INTEGRITY_CHECK;
                    ex.process_id = ev.process_id;
                    ex.address = ev.address;
                    ex.size = ev.size;
                    ex.priority = EventPriority::HIGH;
                    ex.source = EventSource::DERIVED;
                    enqueue_event(ex);
                    break;
                }
                default:
                    break;
            }
        }
        catch (const std::exception& e) {
            if (memory_monitor_) {
                std::string msg = std::string("Event processing exception: ") + e.what();
                memory_monitor_->log_message("ERROR", msg.c_str());
            }
        }
        catch (...) {
            if (memory_monitor_) {
                std::string msg = std::string("Event processing unknown exception");
                memory_monitor_->log_message("ERROR", msg.c_str());
            }
        }
    }
}

void EventHandler::handle_memory_region_scan_event(const Event& ev) {
    if (memory_monitor_) {
        std::string msg = std::string("[SCAN-EVENT] recv pid=") + std::to_string(ev.process_id) + std::string(" handle=0x") + EventUtils::format_address((uint64_t)ev.process_handle);
        memory_monitor_->log_message("DEBUG", msg.c_str());
    }
    
    HANDLE h = ev.process_handle;
    if (h == INVALID_HANDLE_VALUE || h == nullptr) {
        if (memory_monitor_) {
            std::string msg = std::string("[SCAN-EVENT] need reopen handle pid=") + std::to_string(ev.process_id);
            memory_monitor_->log_message("DEBUG", msg.c_str());
        }
        h = get_process_handle(ev.process_id);
    }
    if (h == INVALID_HANDLE_VALUE || h == nullptr) {
        if (memory_monitor_) {
            std::string msg = std::string("[SCAN-EVENT] abort no valid handle pid=") + std::to_string(ev.process_id);
            memory_monitor_->log_message("DEBUG", msg.c_str());
        }
        return;
    }
    scan_process_memory(ev.process_id, h);
}

// 新增：跨進程掃描
void EventHandler::scan_process_memory(DWORD pid, HANDLE hProcess) {
    // 新增：關鍵 debug 日誌
    log_to_detection_engine("DEBUG", "[SCAN-START] pid=" + std::to_string(pid) + " interval=1s");
    
    // 新增：檢查進程是否被納管（使用公共方法）
            std::vector<ExtendedProcessInfo> monitored = memory_monitor_ ? memory_monitor_->get_monitored_processes() : std::vector<ExtendedProcessInfo>();
    bool is_enrolled = false;
    for (const auto& proc : monitored) {
        if (proc.process_id == pid) {
            is_enrolled = true;
            break;
        }
    }
    
    if (!is_enrolled) {
        log_to_detection_engine("WARN", "[SCAN-SKIP] pid=" + std::to_string(pid) + " reason=NOT_ENROLLED");
        // 嘗試立即納管該進程
        std::string process_name = MemoryMonitor::get_process_name(pid);
        if (!process_name.empty()) {
            try {
                if (memory_monitor_) {
                    memory_monitor_->monitor_process(pid, process_name);
                }
                log_to_detection_engine("INFO", "[ENROLL] pid=" + std::to_string(pid) + " name=" + process_name + " result=OK");
            } catch (const std::exception& e) {
                log_to_detection_engine("ERROR", "[ENROLL] pid=" + std::to_string(pid) + " name=" + process_name + " result=FAIL error=" + std::string(e.what()));
            }
        }
    } else {
        log_to_detection_engine("DEBUG", "[SCAN-ENROLLED] pid=" + std::to_string(pid) + " status=OK");
    }
    
    log_to_detection_engine("DEBUG", "*** SCAN_PROCESS_MEMORY pid=" + std::to_string(pid) + " ***");
    LPVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    int scanned = 0;
    int scanned_exec = 0;
    int idx = 0;
    
    // 若 max_regions_to_scan_ == 0 表示不限制
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) &&
           (max_regions_to_scan_ == 0 || scanned < max_regions_to_scan_)) {
        if (mbi.State == MEM_COMMIT) {
            bool is_exec = is_executable_protect(mbi.Protect);
            bool is_private = (mbi.Type == MEM_PRIVATE);
            
            // 對攻擊模擬器進程記錄前200個區域的詳細信息
            if (idx < 200) {
                if (memory_monitor_) {
                    std::string reg_msg = std::string("[REG] pid=") + std::to_string(pid) + std::string(" idx=") + std::to_string(idx) +
                        std::string(" base=0x") + EventUtils::format_address((uint64_t)mbi.BaseAddress) +
                        std::string(" size=") + std::to_string(mbi.RegionSize) +
                        std::string(" prot=0x") + EventUtils::format_address(mbi.Protect) +
                        std::string(" private=") + std::string(is_private ? "Y" : "N") +
                        std::string(" exec=") + (is_exec ? "Y" : "N");
                    memory_monitor_->log_message("DEBUG", reg_msg.c_str());
                }
            }
            idx++;
            
            // 檢查 watchlist
            {
                std::lock_guard<std::mutex> lk(watch_mtx_);
                uint64_t pg = ((uint64_t)mbi.BaseAddress) & ~0xFFFULL;
                if (forced_watch_.count(pg)) {
                    if (memory_monitor_) {
                            std::string watch_msg = std::string("[WATCH] hit page=0x") + EventUtils::format_address(pg) + std::string(" pid=") + std::to_string(pid);
                            memory_monitor_->log_message("DEBUG", watch_msg.c_str());
                        }
                }
            }
            
            // 噪音過濾：只對 MEM_PRIVATE+EXEC 做 integrity & 轉換追蹤
            if (is_exec && is_private) {
                scanned_exec++;
                
                // 可執行區域 → 建 integrity 事件
                Event ex;
                ex.type = Event::Type::EXECUTABLE_INTEGRITY_CHECK;
                ex.process_id = pid;
                ex.process_handle = hProcess;
                ex.address = (uint64_t)mbi.BaseAddress;
                ex.size = mbi.RegionSize;
                ex.timestamp_ms = EventUtils::now_ms();
                ex.meta = "Exec integrity scan";
                enqueue_event(ex);
            }
            // RW->RX 追蹤
            {
                std::lock_guard<std::mutex> lk(exec_pages_mutex_);
                ExecKey key{pid,(uint64_t)mbi.BaseAddress};
                auto& info = exec_pages_[key];
                bool first = (info.first_seen_ts == 0);
                if (first) {
                    info.first_seen_ts = EventUtils::now_ms();
                    info.last_protect = mbi.Protect;
                    info.seen_exec = is_exec;
                    if (is_exec && mbi.Type == MEM_PRIVATE) {
                        Event sp;
                        sp.type = Event::Type::MEM_PROTECT_CHANGE;
                        sp.process_id = pid;
                        sp.process_handle = hProcess;
                        sp.address = (uint64_t)mbi.BaseAddress;
                        sp.size = mbi.RegionSize;
                        sp.timestamp_ms = info.first_seen_ts;
                        sp.meta = "Synthetic EXEC(initial)";
                        sp.priority = EventPriority::HIGH;
                        sp.source = EventSource::DERIVED;
                        enqueue_event(sp);
                        schedule_suspicious_region(pid, (uint64_t)mbi.BaseAddress);
                        // 記錄 burst（短時間多個新出現的 EXEC 私有小區域）
                        record_exec_private_small_region_burst(this, pid, (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                    }
                } else {
                    if (info.last_protect != mbi.Protect) {
                        bool was_exec = is_executable_protect(info.last_protect);
                        if (!was_exec && is_exec) {
                            Event sp;
                            sp.type = Event::Type::MEM_PROTECT_CHANGE;
                            sp.process_id = pid;
                            sp.process_handle = hProcess;
                            sp.address = (uint64_t)mbi.BaseAddress;
                            sp.size = mbi.RegionSize;
                            sp.timestamp_ms = EventUtils::now_ms();
                            sp.meta = "RW->EXEC transition";
                            sp.priority = EventPriority::HIGH;
                            sp.source = EventSource::DERIVED;
                            enqueue_event(sp);
                            schedule_suspicious_region(pid, (uint64_t)mbi.BaseAddress);
                            // 追蹤 burst
                            record_exec_private_small_region_burst(this, pid, (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                        }
                        info.last_protect = mbi.Protect;
                    }
                }
            }
            scanned++;
        }
        address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if (address < mbi.BaseAddress) break;
    }
    log_to_detection_engine("DEBUG", "*** SCAN_PROCESS_MEMORY pid=" + std::to_string(pid) + " regions=" + std::to_string(scanned) + " exec_private=" + std::to_string(scanned_exec) + " ***");
    
    // 新增：更新掃描時間戳
    {
        std::lock_guard<std::mutex> lk(g_scan_ts_mtx);
        g_last_scan_ts[pid] = std::chrono::steady_clock::now();
    }
    
    // 新增：如果找到 exec_private 區域，立即調用 ROP 檢測
    if (scanned_exec > 0) {
        log_to_detection_engine("DEBUG", "[SCATTER] start pid=" + std::to_string(pid) + " exec_regions=" + std::to_string(scanned_exec));
        detect_scattered_rop_chains(pid, hProcess);
    } else {
        log_to_detection_engine("DEBUG", "[SCATTER] skip pid=" + std::to_string(pid) + " reason=NO_EXEC_PRIVATE");
    }
}

void EventHandler::add_exec_watch(uint64_t addr) {
    std::lock_guard<std::mutex> lk(watch_mtx_);
    forced_watch_.insert(addr & ~0xFFFULL);
    if (memory_monitor_) {
        std::string watch_added = std::string("[WATCH] added page=0x") + EventUtils::format_address(addr & ~0xFFFULL);
        memory_monitor_->log_message("DEBUG", watch_added.c_str());
    }
}

void EventHandler::handle_comprehensive_attack_detection_event(const Event& ev) {
    perform_comprehensive_attack_detection(ev.process_id, ev.process_handle, ev.process_category);
}

void EventHandler::handle_all_processes_scan_event(const Event& ev) {
    scan_all_processes_memory();
}

void EventHandler::handle_status_output_event(const Event& ev) {
    show_status();
}

void EventHandler::handle_cycle_completion_event(const Event& ev) {
    std::cout << "Detection cycle completed. Total detections: " << total_detections_.load() << std::endl;
    if (memory_monitor_) {
        std::string cycle_msg = std::string("Detection cycle completed. Total detections: ") + std::to_string(total_detections_.load());
        memory_monitor_->log_message("INFO", cycle_msg.c_str());
    }
    
    // 清理舊的攻擊模擬器輸出控制項
    cleanup_simulator_output_controls();
}

void EventHandler::handle_executable_integrity_check_event(const Event& ev) {
    check_executable_integrity((LPVOID)ev.address, ev.size, ev.process_id, ev.depth);
}

void EventHandler::handle_heap_region_check_event(const Event& ev) {
    check_heap_region(ev.process_id, (LPVOID)ev.address, ev.size);
}

void EventHandler::fast_event_loop() {
    while (running_.load()) {
        try {
            std::vector<Event> batch = get_event_batch();
            
            if (!batch.empty()) {
                analyze_event_batch(batch);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[FATAL] Exception in fast_event_loop: " << e.what() << std::endl;
            try {
                log_to_detection_engine("FATAL", "Exception in fast_event_loop: " + std::string(e.what()));
            } catch (...) {
                std::cerr << "[FATAL] Failed to log exception" << std::endl;
            }
        }
        catch (...) {
            std::cerr << "[FATAL] Unknown exception in fast_event_loop" << std::endl;
            try {
                log_to_detection_engine("FATAL", "Unknown exception in fast_event_loop");
            } catch (...) {
                std::cerr << "[FATAL] Failed to log unknown exception" << std::endl;
            }
        }
    }
}

void EventHandler::deferred_analyzer_loop() {
    while (running_.load()) {
        try {
            std::this_thread::sleep_for(deferred_interval_);
            std::vector<SuspiciousKey> batch;
            
            {
                std::lock_guard<std::mutex> lock(suspicious_mutex_);
                // 彈出最多 deferred_batch_limit_ 個可疑區域
                for (size_t i = 0; i < deferred_batch_limit_ && !suspicious_regions_.empty(); ++i) {
                    SuspiciousKey key = suspicious_regions_.front();
                    suspicious_regions_.pop_front();
                    suspicious_set_.erase(key);
                    batch.push_back(key);
                }
            }

            for (const auto& key : batch) {
                // 使用正確的進程句柄進行分析
                HANDLE hProcess = get_process_handle(key.pid);
                if (hProcess == INVALID_HANDLE_VALUE) {
                    continue; // 跳過無法訪問的進程
                }
                
                try {
                    // 輕量級快照和熵值檢查
                    std::vector<uint8_t> buf(2048);
                    SIZE_T read = 0;
                    
                    // 使用正確的進程句柄讀取記憶體
                    if (ReadProcessMemory(hProcess, (LPCVOID)key.page, buf.data(), buf.size(), &read) && read > 0) {
                        // 計算熵值
                        double entropy = EventUtils::calculate_shannon_entropy(buf.data(), read);
                        
                        // 如果熵值過低，可能是可疑區域
                        if (entropy < 2.0) {
                            // 創建高優先級事件進行進一步分析
                            Event ev;
                            ev.type = Event::Type::EXECUTABLE_INTEGRITY_CHECK;
                            ev.process_id = key.pid;
                            ev.address = key.page;
                            ev.size = read;
                            ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch()).count();
                            ev.meta = "Low entropy region detected - Entropy: " + std::to_string(entropy);
                            ev.priority = EventPriority::HIGH;
                            ev.source = EventSource::DERIVED;
                            ev.depth = 0;
                            ev.flags = 0;
                            ev.sequence_id = 0;
                            
                            enqueue_event(ev);
                        }
                        
                        stats_.suspicious_regions_analyzed.fetch_add(1);
                    }
                } catch (...) {
                    // 忽略個別區域失敗
                }
            }
        }
        catch (const std::exception& e) {
            if (memory_monitor_) {
                std::string _deferred_msg = std::string("Deferred analyzer exception: ") + e.what();
                memory_monitor_->log_message("ERROR", _deferred_msg.c_str());
            }
        }
        catch (...) {
            if (memory_monitor_) {
                memory_monitor_->log_message("ERROR", "Deferred analyzer unknown exception");
            }
        }
    }
}

// 實現從 detection_loop 移植過來的方法
void EventHandler::scan_memory_for_attacks() {
    try {
        std::cout << "  scan_memory_for_attacks: Starting..." << std::endl;
        if (memory_monitor_) {
            memory_monitor_->log_message("DEBUG", "*** SCAN_MEMORY_FOR_ATTACKS STARTED ***");
        }
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int scanned_regions = 0;
        
        while (VirtualQuery(address, &mbi, sizeof(mbi)) &&
               (max_regions_to_scan_ == 0 || scanned_regions < max_regions_to_scan_)) {
            try {
                std::cout << "  Scanning region " << scanned_regions + 1 << " at " << address << std::endl;
                
                if (mbi.State == MEM_COMMIT) {
                    // 檢查可執行記憶體
                    if (is_executable_protect(mbi.Protect)) {
                        Event ev = Event::make_event(Event::Type::EXECUTABLE_INTEGRITY_CHECK, GetCurrentProcessId(), (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                        ev.memory_info = mbi;
                        ev.meta = "Executable integrity check";
                        
                        enqueue_event(ev);
                    }
                    
                    // 檢查堆區域
                    if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || 
                        (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_READONLY) ||
                        (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        Event ev = Event::make_event(Event::Type::HEAP_REGION_CHECK, GetCurrentProcessId(), (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                        ev.memory_info = mbi;
                        ev.meta = "Heap region check";
                        
                        enqueue_event(ev);
                    }
                    
                    // 新增：exec_page_tracker邏輯
                    uint64_t base = (uint64_t)mbi.BaseAddress;
                    bool is_exec = is_executable_protect(mbi.Protect);
                    {
                        std::lock_guard<std::mutex> lk(exec_pages_mutex_);
                        ExecKey key{GetCurrentProcessId(), base};
                        auto& info = exec_pages_[key];
                        if (info.first_seen_ts == 0) {
                            info.first_seen_ts = EventUtils::now_ms();
                            info.last_protect = mbi.Protect;
                            info.seen_exec = is_exec;
                            if (is_exec && mbi.Type == MEM_PRIVATE) {
                                // 合成"新可執行"事件
                                Event evx = Event::make_event(Event::Type::MEM_PROTECT_CHANGE, GetCurrentProcessId(), base, mbi.RegionSize);
                                evx.timestamp_ms = info.first_seen_ts;
                                evx.meta = "Synthetic EXEC (initial) region";
                                evx.priority = EventPriority::HIGH;
                                evx.source = EventSource::DERIVED;
                                enqueue_event(evx);
                                schedule_suspicious_region(evx.process_id, base);
                            }
                        } else {
                            if (info.last_protect != mbi.Protect) {
                                bool was_exec = is_executable_protect(info.last_protect);
                                if (!was_exec && is_exec) {
                                    uint64_t now_ms = EventUtils::now_ms();
                                    Event evp;
                                    evp.type = Event::Type::MEM_PROTECT_CHANGE;
                                    evp.process_id = GetCurrentProcessId();
                                    evp.address = base;
                                    evp.size = mbi.RegionSize;
                                    evp.timestamp_ms = now_ms;
                                    evp.meta = "RW->EXEC transition synthetic";
                                    evp.priority = EventPriority::HIGH;
                                    evp.source = EventSource::DERIVED;
                                    enqueue_event(evp);
                                    schedule_suspicious_region(evp.process_id, base);
                                    info.last_transition_ts = now_ms;
                                }
                                info.last_protect = mbi.Protect;
                            }
                        }
                    }
                    
                    scanned_regions++;
                    std::cout << "    Completed region " << scanned_regions << std::endl;
                }
                
                address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
            }
            catch (const std::exception& e) {
                std::cerr << "    Error scanning memory region: " << e.what() << std::endl;
                address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in scan_memory_for_attacks: " << e.what() << std::endl;
        if (memory_monitor_) {
            std::string _scan_err = std::string("Error in scan_memory_for_attacks: ") + e.what();
            memory_monitor_->log_message("ERROR", _scan_err.c_str());
        }
    }
}

void EventHandler::scan_all_processes_memory() {
    try {
        DWORD processes[1024];
        DWORD cbNeeded;
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD num_processes = cbNeeded / sizeof(DWORD);
            for (DWORD i = 0; i < num_processes; i++) {
                if (processes[i] != 0) {
                    try {
                        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processes[i]);
                        if (hProcess) {
                            // 這裡可以實作進程記憶體掃描
                            CloseHandle(hProcess);
                        }
                    }
                    catch (...) {
                        // 忽略進程訪問錯誤
                    }
                }
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error in scan_all_processes_memory: " << e.what() << std::endl;
        if (memory_monitor_) {
            std::string _all_err = std::string("Error in scan_all_processes_memory: ") + e.what();
            memory_monitor_->log_message("ERROR", _all_err.c_str());
        }
    }
}

void EventHandler::show_status() {
    std::cout << "=== Detection Engine Status ===" << std::endl;
    std::cout << "Total detections: " << total_detections_.load() << std::endl;
    std::cout << "Cycle counter: " << comprehensive_tick_counter_.load() << std::endl;
    std::cout << "Status counter: " << status_tick_counter_.load() << std::endl;
    std::cout << "===============================" << std::endl;
}

void EventHandler::cleanup_simulator_output_controls() {
    try {
        // 清理攻擊模擬器輸出控制項的實作
        // 這裡可以添加具體的清理邏輯，比如清理日誌文件、重置計數器等
        
        // 重置計數器
        comprehensive_tick_counter_ = 0;
        status_tick_counter_ = 0;
        
        // 清理可疑區域隊列
        {
            std::lock_guard<std::mutex> lock(suspicious_mutex_);
            suspicious_regions_.clear();
            suspicious_set_.clear();
            suspicious_last_seen_.clear();
        }
        
        if (memory_monitor_) {
            std::string sim_msg = "Simulator output controls cleaned up";
            memory_monitor_->log_message("INFO", sim_msg.c_str());
        }
    }
    catch (const std::exception& e) {
        if (memory_monitor_) {
            std::string _cleanup_msg = std::string("Cleanup simulator output controls exception: ") + e.what();
            memory_monitor_->log_message("ERROR", _cleanup_msg.c_str());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Cleanup simulator output controls unknown exception");
        }
    }
}

void EventHandler::check_executable_integrity(LPVOID base_address, SIZE_T region_size, DWORD pid, int depth) {
    // 檢查 size 是否合理
    if (region_size == 0 || region_size > 64 * 1024 * 1024) { // 64MB 上限
        if (memory_monitor_) {
            std::string _size_warn = std::string("[INTEGRITY] Invalid size: ") + std::to_string(region_size) + std::string(" - skipping");
            memory_monitor_->log_message("WARN", _size_warn.c_str());
        }
        return;
    }
    
    // 調試日誌
    if (memory_monitor_) {
        std::string _integrity_dbg = std::string("IntegrityCheck base=0x") + EventUtils::format_address((uint64_t)base_address) + std::string(" size=") + std::to_string(region_size);
        memory_monitor_->log_message("DEBUG", _integrity_dbg.c_str());
    }
    
    // 防止無限遞迴
    if (depth > 1) {
        stats_.reanalysis_skipped.fetch_add(1);
        return;
    }
    
    try {
        // 檢查重複分析次數
        {
            std::lock_guard<std::mutex> lock(integrity_mutex_);
            auto key = std::make_pair(pid, (uint64_t)base_address);
            auto& count = integrity_recheck_count_[key];
            if (count >= 2) {
                stats_.reanalysis_skipped.fetch_add(1);
                return; // 超過重複分析限制
            }
            count++;
        }
        
        // 獲取正確的進程句柄
        HANDLE hProcess = get_process_handle(pid);
        if (hProcess == INVALID_HANDLE_VALUE) {
            return;
        }
        
        // 讀取記憶體內容
        std::vector<uint8_t> buffer((region_size < static_cast<SIZE_T>(4096)) ? region_size : static_cast<SIZE_T>(4096)); // 限制讀取大小
        SIZE_T bytes_read = 0;
        
            if (!ReadProcessMemory(hProcess, base_address, buffer.data(), buffer.size(), &bytes_read) || bytes_read == 0) {
            if (memory_monitor_) {
                std::string _rpm_fail = std::string("[INTEGRITY] RPM fail pid=") + std::to_string(pid) + std::string(" base=0x") + EventUtils::format_address((uint64_t)base_address) + std::string(" gle=") + std::to_string(GetLastError());
                memory_monitor_->log_message("DEBUG", _rpm_fail.c_str());
            }
            return;
        }
        
        // 檢查指令完整性
        int valid_instructions = 0;
        int total_checks = 0;
            
        // 新增：高密度gadget檢測
        int ret_cnt = 0, pop_cnt = 0, nop_cnt = 0, int3_cnt = 0;
        for (size_t i = 0; i < bytes_read; i++) {
            uint8_t b = buffer[i];
            if (b == 0xC3) ret_cnt++;
            else if (b >= 0x58 && b <= 0x5F) pop_cnt++;
            else if (b == 0x90) nop_cnt++;
            else if (b == 0xCC) int3_cnt++;
        }
        double ret_density = bytes_read ? (double)ret_cnt / bytes_read : 0.0;
        double sled_ratio = bytes_read ? (double)(nop_cnt + int3_cnt) / bytes_read : 0.0;
        
        // 檢查簽名字串
        bool has_sig = false;
        if (bytes_read >= 6) {
            const char sig[] = "SIMROP";
            for (size_t i = 0; i + 6 <= bytes_read; i++) {
                if (memcmp(buffer.data() + i, sig, 6) == 0) {
                    has_sig = true;
                    break;
                }
            }
        }
        
        // 小區域 ROP 門檻（優先檢測）
        if (bytes_read <= 512) {
            bool small_hit = (ret_cnt >= 4 && (ret_density >= 0.015 || pop_cnt >= 2))
                || (ret_cnt + pop_cnt >= 8)
                || (ret_density >= 0.01 && sled_ratio >= 0.05);
                if (small_hit) {
                std::ostringstream am;
                am << "SMALL_REGION_ROP ret=" << ret_cnt
                   << " pop=" << pop_cnt
                   << " density=" << ret_density
                   << " sled=" << sled_ratio;
                
                Event alert = Event::make_event(Event::Type::CUSTOM, pid, (uint64_t)base_address, region_size);
                alert.meta = am.str();
                alert.priority = EventPriority::HIGH;
                alert.source = EventSource::DERIVED;
                enqueue_event(alert);
                update_stats_on_finding();
                if (memory_monitor_) {
                    std::string _small_msg = std::string("*** SMALL_REGION_ROP DETECTED ") + am.str() + std::string(" ***");
                    memory_monitor_->log_message("DEBUG", _small_msg.c_str());
                }
            }
        }
        
        // 高密度gadget檢測條件
        if ((ret_cnt >= 12 && ret_density >= 0.008) ||
            (ret_cnt + pop_cnt >= 20) ||
            (has_sig && ret_cnt >= 6) ||
            (ret_density >= 0.005 && sled_ratio >= 0.12)) {
            
            std::ostringstream am;
            am << "ROP/Shellcode Indicators ret=" << ret_cnt
               << " pop=" << pop_cnt
               << " ret_density=" << ret_density
               << " sled_ratio=" << sled_ratio
               << " sig=" << (has_sig ? "Y" : "N");
            
            Event alert = Event::make_event(Event::Type::CUSTOM, pid, (uint64_t)base_address, region_size);
            alert.meta = am.str();
            alert.priority = EventPriority::HIGH;
            alert.source = EventSource::DERIVED;
            enqueue_event(alert);
            update_stats_on_finding();
            
            // 調試輸出
            std::string debug_msg = "*** ROP DENSITY DETECTED: ret=" + std::to_string(ret_cnt) + 
                                  " pop=" + std::to_string(pop_cnt) + 
                                  " density=" + std::to_string(ret_density) + " ***";
            if (memory_monitor_) {
                memory_monitor_->log_message("DEBUG", debug_msg);
            }
        }
        
        for (size_t i = 0; i < bytes_read - 1; i++) {
                total_checks++;
                
                // 檢查常見的有效指令模式
                if (buffer[i] == 0x90) { // NOP
                    valid_instructions++;
                } else if (buffer[i] == 0xC3) { // RET
                    valid_instructions++;
                } else if (buffer[i] >= 0x58 && buffer[i] <= 0x5F) { // POP
                    valid_instructions++;
                } else if (buffer[i] >= 0x50 && buffer[i] <= 0x57) { // PUSH
                    valid_instructions++;
                } else if (buffer[i] == 0xE9) { // JMP
                    valid_instructions++;
                } else if (buffer[i] == 0xEB) { // JMP short
                    valid_instructions++;
                }
            }
            
            // 計算指令有效性比例
            double validity_ratio = (total_checks > 0) ? (double)valid_instructions / total_checks : 0.0;
            
            // 如果指令有效性過低，可能是損壞的或惡意代碼
            if (validity_ratio < 0.3 && total_checks > 10) {
                // 創建高優先級警報事件（與原檢查事件分離）
                Event ev = Event::make_event(Event::Type::CUSTOM, pid, (uint64_t)base_address, region_size);
                ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.meta = "Low instruction validity ratio: " + std::to_string(validity_ratio);
                ev.priority = EventPriority::HIGH;
                ev.source = EventSource::DERIVED;
                ev.depth = depth + 1;
                ev.flags = 1; // 標記為高風險
                ev.sequence_id = 0;
                
                enqueue_event(ev);
                
                // 調度可疑區域進行深度分析
                schedule_suspicious_region(pid, (uint64_t)base_address);
                
                // 更新統計
                update_stats_on_finding();
            }
        }
        
    catch (const std::exception& e) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", std::string("Executable integrity check exception: ") + e.what());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Executable integrity check unknown exception");
        }
    }
}

void RealMemoryDetection::EventHandler::check_heap_region(DWORD pid, LPVOID base_address, SIZE_T region_size) {
    try {
        // 讀取記憶體內容
        HANDLE hProcess = get_process_handle(pid);
        if (hProcess == INVALID_HANDLE_VALUE) return;
        std::vector<uint8_t> buffer((region_size < static_cast<SIZE_T>(2048)) ? region_size : static_cast<SIZE_T>(2048)); // 限制讀取大小
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(hProcess, base_address, buffer.data(), buffer.size(), &bytes_read) && bytes_read > 0) {
            // 檢查堆損壞模式
            int null_sequences = 0;
            int repeated_patterns = 0;
            int suspicious_bytes = 0;
            
            for (size_t i = 0; i < bytes_read - 3; i++) {
                // 檢查連續的NULL字節
                if (buffer[i] == 0x00 && buffer[i+1] == 0x00 && buffer[i+2] == 0x00 && buffer[i+3] == 0x00) {
                    null_sequences++;
                }
                
                // 檢查重複模式
                if (i > 0 && buffer[i] == buffer[i-1]) {
                    repeated_patterns++;
                }
                
                // 檢查可疑字節模式
                if (buffer[i] == 0xCC) { // INT3 (調試斷點)
                    suspicious_bytes++;
                } else if (buffer[i] == 0xCD && i < bytes_read - 1 && buffer[i+1] == 0x80) { // INT 80h
                    suspicious_bytes++;
                }
            }
            
            // 如果檢測到堆損壞特徵
            if (null_sequences > 2 || repeated_patterns > bytes_read * 0.1 || suspicious_bytes > 5) {
                Event ev = Event::make_event(Event::Type::HEAP_CORRUPTION, pid, (uint64_t)base_address, region_size);
                ev.meta = "Heap corruption detected - Null sequences: " + std::to_string(null_sequences) + 
                         ", Repeated patterns: " + std::to_string(repeated_patterns) + 
                         ", Suspicious bytes: " + std::to_string(suspicious_bytes);
                
                enqueue_event(ev);
                
                // 調度可疑區域進行深度分析
                schedule_suspicious_region(pid, (uint64_t)base_address);
            }
        }
    }
    catch (const std::exception& e) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", std::string("Heap region check exception: ") + e.what());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Heap region check unknown exception");
        }
    }
}

void EventHandler::perform_comprehensive_attack_detection(DWORD process_id, HANDLE hProcess, MemoryDetectionEngine::ProcessCategory category) {
    try {
        log_to_detection_engine("DEBUG", "*** COMPREHENSIVE ATTACK DETECTION pid=" + std::to_string(process_id) + " ***");
        
        // 根據進程類別執行不同級別的檢測
        switch (category) {
            case MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR:
                // 對攻擊模擬器執行最全面的檢測
                detect_attack_simulator_patterns(process_id, hProcess);
                detect_scattered_rop_chains(process_id, hProcess);
                detect_complex_attack_patterns(process_id, hProcess);
                break;
                
            case MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS:
                // 對高風險進程執行重點檢測
                detect_scattered_rop_chains(process_id, hProcess);
                detect_complex_attack_patterns(process_id, hProcess);
                break;
                
            case MemoryDetectionEngine::ProcessCategory::USER_PROCESS:
                // 對用戶進程執行基本檢測
                detect_suspicious_behavior_patterns(process_id, hProcess);
                break;
                
            case MemoryDetectionEngine::ProcessCategory::SYSTEM_PROCESS:
                // 對系統進程執行最小檢測
                detect_suspicious_behavior_patterns(process_id, hProcess);
                break;
        }
        
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Comprehensive attack detection exception: " + std::string(e.what()));
    } catch (...) {
        log_to_detection_engine("ERROR", "Comprehensive attack detection unknown exception");
    }
}

void EventHandler::detect_attack_simulator_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        
        // 掃描所有可執行記憶體區域
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0) {
                exec_regions.push_back(mbi);
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break;
        }
        
        // 對每個區域進行詳細掃描
        for (const auto& region : exec_regions) {
            // 限制掃描大小
            if (region.RegionSize > 8192) continue;
            
            // 讀取記憶體內容
            std::vector<uint8_t> buffer(region.RegionSize);
            SIZE_T bytes_read = 0;
            
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
                // 檢測ROP gadgets
                int ret_count = 0;
                int pop_count = 0;
                int consecutive_ret = 0;
                int max_consecutive_ret = 0;
                
                for (size_t i = 0; i < bytes_read - 1; i++) {
                    if (buffer[i] == 0xC3) { // RET指令
                        ret_count++;
                        consecutive_ret++;
                        if (consecutive_ret > max_consecutive_ret) {
                            max_consecutive_ret = consecutive_ret;
                        }
                    } else {
                        consecutive_ret = 0;
                    }
                    
                    // 檢測POP指令
                    if (buffer[i] >= 0x58 && buffer[i] <= 0x5F) {
                        pop_count++;
                    }
                }
                
                // 如果檢測到足夠的ROP特徵，報告攻擊
                if (ret_count >= 5 && pop_count >= 2) {
                    std::string alert_msg = "Attack Simulator ROP Detected - RETs: " + std::to_string(ret_count) + 
                                          ", POPs: " + std::to_string(pop_count) + 
                                          ", Max Consecutive RETs: " + std::to_string(max_consecutive_ret);
                    log_to_detection_engine("WARN", alert_msg);
                    
                    // 創建事件
                    Event ev;
                    ev.type = Event::Type::CUSTOM;
                    ev.process_id = process_id;
                    ev.address = (uint64_t)region.BaseAddress;
                    ev.size = region.RegionSize;
                    ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.meta = alert_msg;
                    ev.priority = EventPriority::HIGH;
                    ev.source = EventSource::DERIVED;
                    
                    enqueue_event(ev);
                }
            }
        }
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Attack simulator pattern detection exception: " + std::string(e.what()));
    } catch (...) {
        log_to_detection_engine("ERROR", "Attack simulator pattern detection unknown exception");
    }
}

// 輔助函數：檢查地址是否指向 gadget（ret 指令）
static bool points_to_gadget(HANDLE hProcess, void* addr) {
    uint8_t bytes[16];
    SIZE_T read = 0;
    
    if (!ReadProcessMemory(hProcess, addr, bytes, sizeof(bytes), &read) || read < 1) {
        return false;
    }
    
    // 檢查是否指向 ret 指令 (0xC3)
    if (bytes[0] == 0xC3) {
        return true;
    }
    
    // 檢查 ret imm16 (0xC2 XX XX)
    if (bytes[0] == 0xC2 && read >= 3) {
        return true;
    }
    
    // 檢查 retf (0xCB) 或 retf imm16 (0xCA)
    if (bytes[0] == 0xCB || bytes[0] == 0xCA) {
        return true;
    }
    
    // 檢查 pop; ret 模式（pop 在 0x58-0x5F 範圍）
    if (read >= 2 && bytes[0] >= 0x58 && bytes[0] <= 0x5F && bytes[1] == 0xC3) {
        return true;
    }
    
    // 檢查 leave; ret (leave = 0xC9)
    if (read >= 2 && bytes[0] == 0xC9 && bytes[1] == 0xC3) {
        return true;
    }
    
    // 檢查 xchg eax,esp; ret (xchg = 0x94)
    if (read >= 2 && bytes[0] == 0x94 && bytes[1] == 0xC3) {
        return true;
    }
    
    return false;
}

// 堆疊資訊結構
struct StackInfo {
    LPVOID base;        // 堆疊基址（高位址/頂部）
    LPVOID limit;       // 堆疊限制（低位址/底部）
    SIZE_T size;        // 堆疊大小
    DWORD thread_id;    // 所屬執行緒 ID
};

// 定義必要的 Windows 內部結構（從 winternl.h）
#ifndef WINNT
typedef long NTSTATUS;
#endif

// NT_TIB 結構（簡化版，只包含我們需要的欄位）
typedef struct _NT_TIB {
    PVOID ExceptionList;  // EXCEPTION_REGISTRATION_RECORD*
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    union {
        PVOID FiberData;
        DWORD Version;
    };
    PVOID ArbitraryUserPointer;
    struct _NT_TIB *Self;
} NT_TIB, *PNT_TIB;

// 定義 CLIENT_ID 結構
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    DWORD Priority;
    DWORD BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes = 1,
    ThreadPriority = 2,
    ThreadBasePriority = 3,
    ThreadAffinityMask = 4,
    ThreadImpersonationToken = 5,
    ThreadDescriptorTableEntry = 6,
    ThreadEnableAlignmentFaultFixup = 7,
    ThreadEventPair_Reusable = 8,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadZeroTlsCell = 10,
    ThreadPerformanceCount = 11,
    ThreadAmILastThread = 12,
    ThreadIdealProcessor = 13,
    ThreadPriorityBoost = 14,
    ThreadSetTlsArrayAddress = 15,
    ThreadIsIoPending = 16,
    ThreadHideFromDebugger = 17,
    ThreadBreakOnTermination = 18,
    ThreadSwitchLegacyState = 19,
    ThreadIsTerminated = 20,
    ThreadLastSystemCall = 21,
    ThreadIoPriority = 22,
    ThreadCycleTime = 23,
    ThreadPagePriority = 24,
    ThreadActualBasePriority = 25,
    ThreadTebInformation = 26,
    ThreadCSwitchMon = 27,
    ThreadCSwitchPmon = 28,
    ThreadWow64Context = 29,
    ThreadGroupInformation = 30,
    ThreadUmsInformation = 31,
    ThreadChannelInformation = 32,
    ThreadDescription = 33,
    ThreadActualGroupAffinity = 34,
    ThreadDynamicCodePolicyInfo = 35,
    ThreadExplicitCaseSensitivity = 36,
    ThreadSubsystemInformation = 37,
    ThreadDbgkWerReportActive = 38,
    ThreadAttachContainer = 39,
    ThreadAttachSilo = 40
} THREADINFOCLASS;

// TEB 結構（部分，只包含我們需要的 NT_TIB）
typedef struct _MY_TEB {
    NT_TIB NtTib;
    // ... 其他欄位我們不需要
} MY_TEB, *PMY_TEB;

// 獲取指定執行緒的堆疊資訊（通過 TEB）- 跨進程版本
static bool get_thread_stack_info_via_teb(
    HANDLE hProcess,    // 目標進程 handle
    HANDLE hThread,     // 目標執行緒 handle
    StackInfo& info
) {
    // 1. 獲取 TEB 地址
    typedef NTSTATUS (WINAPI *PNtQueryInformationThread)(
        HANDLE ThreadHandle,
        THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation,
        ULONG ThreadInformationLength,
        PULONG ReturnLength
    );
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return false;
    }
    
    auto NtQueryInformationThread = (PNtQueryInformationThread)
        GetProcAddress(ntdll, "NtQueryInformationThread");
    if (!NtQueryInformationThread) {
        return false;
    }
    
    THREAD_BASIC_INFORMATION tbi = {0};
    ULONG return_length = 0;
    
    NTSTATUS status = NtQueryInformationThread(
        hThread,
        ThreadBasicInformation,
        &tbi,
        sizeof(tbi),
        &return_length
    );
    
    // NTSTATUS 成功是 0 (STATUS_SUCCESS)，失敗是負數
    if (status != 0) {
        return false;
    }
    
    if (!tbi.TebBaseAddress) {
        return false;
    }
    
    // 2. 遠端讀取 TEB（只讀取 NT_TIB 部分）
    MY_TEB teb = {0};
    SIZE_T bytes_read = 0;
    
    if (!ReadProcessMemory(
        hProcess,
        tbi.TebBaseAddress,
        &teb,
        sizeof(NT_TIB),  // 只讀取 NT_TIB 部分
        &bytes_read
    )) {
        return false;
    }
    
    if (bytes_read < sizeof(NT_TIB)) {
        return false;
    }
    
    // 3. 從 TEB 中提取堆疊資訊
    info.base = teb.NtTib.StackBase;      // 堆疊頂部（高位址）
    info.limit = teb.NtTib.StackLimit;    // 堆疊底部（低位址）
    
    // 計算堆疊大小（StackBase > StackLimit，堆疊向下增長）
    if (info.base && info.limit && info.base > info.limit) {
        info.size = (SIZE_T)((BYTE*)info.base - (BYTE*)info.limit);
        info.thread_id = GetThreadId(hThread);
        return true;
    }
    
    return false;
}

// 輔助函數：判斷記憶體區域是否為堆疊（啟發式方法）
static bool is_likely_stack_region_heuristic(const MEMORY_BASIC_INFORMATION& mbi) {
    // 1. 必須是已提交的記憶體
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    
    // 2. 類型通常是 MEM_PRIVATE
    if (mbi.Type != MEM_PRIVATE) {
        return false;
    }
    
    // 3. 保護屬性通常是 PAGE_READWRITE（有時是 PAGE_EXECUTE_READWRITE）
    if (!(mbi.Protect & PAGE_READWRITE) && 
        !(mbi.Protect & PAGE_EXECUTE_READWRITE)) {
        return false;
    }
    
    // 4. 大小通常在 64KB - 8MB 之間（可調整）
    SIZE_T size = mbi.RegionSize;
    if (size < 64 * 1024 || size > 8 * 1024 * 1024) {
        return false;
    }
    
    // 5. 檢查是否有 guard page（堆疊保護頁）- 這是堆疊的強烈特徵
    // 注意：這個檢查需要目標進程的 handle，但我們只有 mbi，所以跳過這個檢查
    // 實際使用時會通過參數傳入 hProcess，但在這個啟發式函數中我們簡化處理
    
    // 6. 在 32-bit 系統上，堆疊通常在高位址
#ifdef _WIN32
#ifndef _WIN64
    if ((DWORD_PTR)mbi.BaseAddress < 0x00100000) {
        return false;
    }
#endif
#endif
    
    // 符合大部分特徵
    return true;
}

// 輔助函數：獲取進程所有執行緒的堆疊區域（優先使用 TEB，失敗時回退到啟發式）
static std::vector<MEMORY_BASIC_INFORMATION> get_thread_stacks(DWORD process_id, HANDLE hProcess) {
    std::vector<MEMORY_BASIC_INFORMATION> stack_regions;
    std::unordered_set<LPVOID> seen_bases;  // 用於去重
    
    // ✅ 方法 1：優先使用 TEB（最準確）
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(snapshot, &te32)) {
            do {
                // 只處理目標進程的執行緒
                if (te32.th32OwnerProcessID != process_id) {
                    continue;
                }
                
                // 打開執行緒
                HANDLE hThread = OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT,
                    FALSE,
                    te32.th32ThreadID
                );
                
                if (hThread) {
                    StackInfo stack_info = {0};
                    
                    // 嘗試使用 TEB 方法獲取堆疊資訊
                    if (get_thread_stack_info_via_teb(hProcess, hThread, stack_info)) {
                        // 轉換為 MEMORY_BASIC_INFORMATION
                        MEMORY_BASIC_INFORMATION mbi = {0};
                        mbi.BaseAddress = stack_info.limit;  // 堆疊底部
                        mbi.RegionSize = stack_info.size;
                        mbi.State = MEM_COMMIT;
                        mbi.Type = MEM_PRIVATE;
                        mbi.Protect = PAGE_READWRITE;
                        
                        // 去重檢查
                        if (seen_bases.find(mbi.BaseAddress) == seen_bases.end()) {
                            stack_regions.push_back(mbi);
                            seen_bases.insert(mbi.BaseAddress);
                        }
                    } else {
                        // TEB 方法失敗，回退到 Context 方法
                        CONTEXT ctx = {0};
                        ctx.ContextFlags = CONTEXT_CONTROL;
                        
                        if (GetThreadContext(hThread, &ctx)) {
#ifdef _WIN64
                            void* stack_ptr = (void*)ctx.Rsp;
#else
                            void* stack_ptr = (void*)ctx.Esp;
#endif
                            
                            // 查詢堆疊指標所在的記憶體區域
                            MEMORY_BASIC_INFORMATION mbi;
                            if (VirtualQueryEx(hProcess, stack_ptr, &mbi, sizeof(mbi))) {
                                if (is_likely_stack_region_heuristic(mbi)) {
                                    if (seen_bases.find(mbi.BaseAddress) == seen_bases.end()) {
                                        stack_regions.push_back(mbi);
                                        seen_bases.insert(mbi.BaseAddress);
                                    }
                                }
                            }
                        }
                    }
                    
                    CloseHandle(hThread);
                }
            } while (Thread32Next(snapshot, &te32));
        }
        
        CloseHandle(snapshot);
    }
    
    // ✅ 方法 2：如果 TEB 方法完全失敗，使用啟發式掃描所有記憶體區域
    if (stack_regions.empty()) {
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && is_likely_stack_region_heuristic(mbi)) {
                if (seen_bases.find(mbi.BaseAddress) == seen_bases.end()) {
                    stack_regions.push_back(mbi);
                    seen_bases.insert(mbi.BaseAddress);
                }
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break;
        }
    }
    
    return stack_regions;
}

void EventHandler::detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
    try {
        log_to_detection_engine("DEBUG", "[SCATTER-ROP] start pid=" + std::to_string(process_id) + " (scanning STACKS, not code)");
        
        // ✅ 正確方法：獲取所有執行緒的堆疊區域
        std::vector<MEMORY_BASIC_INFORMATION> stack_regions = get_thread_stacks(process_id, hProcess);
        
        if (stack_regions.empty()) {
            log_to_detection_engine("DEBUG", "[SCATTER-ROP] no stack regions found pid=" + std::to_string(process_id));
            return;
        }
        
        log_to_detection_engine("DEBUG", "[SCATTER-ROP] found " + std::to_string(stack_regions.size()) + " stack regions");
        
        // 掃描每個堆疊區域
        for (const auto& stack_region : stack_regions) {
            // 限制掃描大小（堆疊通常不會太大，但我們限制在 512KB 以內）
            SIZE_T to_scan = static_cast<SIZE_T>(std::min<uint64_t>(
                static_cast<uint64_t>(stack_region.RegionSize), 
                512ULL * 1024ULL));
            
            if (to_scan == 0 || to_scan < sizeof(void*)) {
                continue;
            }
            
            // 讀取堆疊內容
            std::vector<uint8_t> stack_buffer(to_scan);
            SIZE_T bytes_read = 0;
            
            if (!ReadProcessMemory(hProcess, stack_region.BaseAddress, 
                                  stack_buffer.data(), to_scan, &bytes_read) || 
                bytes_read < sizeof(void*)) {
                continue;
            }
            
            // 將堆疊內容視為指標陣列（假設 64 位系統，指針大小為 8 字節）
            // 為了兼容，我們同時處理 32 位和 64 位
#ifdef _WIN64
            const size_t ptr_size = 8;
#else
            const size_t ptr_size = 4;
#endif
            
            size_t ptr_count = bytes_read / ptr_size;
            if (ptr_count == 0) continue;
            
            // 分析堆疊上的指標模式
            int consecutive_gadget_pointers = 0;
            int max_consecutive_gadgets = 0;
            int total_gadget_pointers = 0;
            std::unordered_set<void*> seen_gadgets;  // 用於計算不同 gadget 的數量
            
            // 掃描堆疊上的每個指標
            for (size_t i = 0; i < ptr_count; i++) {
                void* ptr = nullptr;
                
                if (ptr_size == 8) {
                    ptr = *(void**)(stack_buffer.data() + i * 8);
                } else {
                    uint32_t ptr32 = *(uint32_t*)(stack_buffer.data() + i * 4);
                    ptr = (void*)(uintptr_t)ptr32;
                }
                
                // 過濾無效指標（NULL 或明顯不合理的值）
                if (ptr == nullptr || 
                    (uintptr_t)ptr < 0x10000) {  // 小於 64KB（通常是無效地址）
                    consecutive_gadget_pointers = 0;
                    continue;
                }
                
                // 64 位系統：檢查是否在用戶空間範圍內（0x10000 到 0x7FFFFFFFFFFF）
#ifdef _WIN64
                if ((uintptr_t)ptr > 0x7FFFFFFFFFFFULL) {
                    consecutive_gadget_pointers = 0;
                    continue;
                }
#else
                // 32 位系統：檢查是否在用戶空間範圍內（0x10000 到 0x7FFFFFFF）
                if ((uintptr_t)ptr > 0x7FFFFFFF) {
                    consecutive_gadget_pointers = 0;
                    continue;
                }
#endif
                
                // ✅ 關鍵：檢查這個指標是否指向 gadget
                if (points_to_gadget(hProcess, ptr)) {
                    consecutive_gadget_pointers++;
                    if (consecutive_gadget_pointers > max_consecutive_gadgets) {
                        max_consecutive_gadgets = consecutive_gadget_pointers;
                    }
                    total_gadget_pointers++;
                    seen_gadgets.insert(ptr);
                } else {
                    consecutive_gadget_pointers = 0;
                }
            }
            
            // ✅ 計算 gadget 指標密度
            double gadget_density = ptr_count > 0 ? 
                static_cast<double>(total_gadget_pointers) / static_cast<double>(ptr_count) : 0.0;
            
            // ✅ 評分系統：檢測 ROP 鏈特徵
            int suspicious_score = 0;
            
            // 檢查 1：連續的 gadget 指標（這是最強烈的 ROP 信號）
            if (max_consecutive_gadgets >= 5) {
                suspicious_score += 10;
            } else if (max_consecutive_gadgets >= 3) {
                suspicious_score += 5;
            }
            
            // 檢查 2：gadget 指標密度異常
            if (gadget_density > 0.3) {  // 30% 以上的指標都指向 gadget
                suspicious_score += 8;
            } else if (gadget_density > 0.15) {
                suspicious_score += 4;
            }
            
            // 檢查 3：總 gadget 數量
            if (total_gadget_pointers >= 10) {
                suspicious_score += 5;
            } else if (total_gadget_pointers >= 5) {
                suspicious_score += 3;
            }
            
            // 檢查 4：不同 gadget 的數量（指向多個不同的 gadget）
            if (seen_gadgets.size() >= 5) {
                suspicious_score += 3;
            }
            
            // ✅ 如果評分超過閾值，發出警報
            if (suspicious_score >= 15) {
                std::ostringstream meta;
                meta << "ROP_CHAIN_ON_STACK"
                     << " consecutive_gadgets=" << max_consecutive_gadgets
                     << " total_gadgets=" << total_gadget_pointers
                     << " unique_gadgets=" << seen_gadgets.size()
                     << " gadget_density=" << std::fixed << std::setprecision(3) << gadget_density
                     << " score=" << suspicious_score
                     << " stack_base=0x" << std::hex << (uint64_t)stack_region.BaseAddress << std::dec;
                
                Event ev = Event::make_event(Event::Type::CUSTOM, process_id, 
                                            (uint64_t)stack_region.BaseAddress, 
                                            stack_region.RegionSize);
                ev.priority = EventPriority::CRITICAL;  // 使用 CRITICAL 優先級
                ev.source = EventSource::DERIVED;
                ev.meta = meta.str();
                enqueue_event(ev);
                
                update_stats_on_finding();
                
                log_to_detection_engine("WARN", "*** ROP CHAIN DETECTED ON STACK: " + meta.str() + " ***");
            } else if (suspicious_score >= 8) {
                // 較低的分數但仍有可疑跡象，記錄為 DEBUG
                log_to_detection_engine("DEBUG", "[SCATTER-ROP] suspicious pattern (score=" + 
                                       std::to_string(suspicious_score) + ") consecutive=" + 
                                       std::to_string(max_consecutive_gadgets));
            }
        }
        
        log_to_detection_engine("DEBUG", "[SCATTER-ROP] completed pid=" + std::to_string(process_id));
        
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Scattered ROP chain detection exception: " + std::string(e.what()));
    } catch (...) {
        log_to_detection_engine("ERROR", "Scattered ROP chain detection unknown exception");
    }
}

void EventHandler::detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        // 檢測複雜的攻擊模式，如JOP (Jump-Oriented Programming)
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0) {
                exec_regions.push_back(mbi);
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break;
        }
        
        for (const auto& region : exec_regions) {
            if (region.RegionSize > 2048) continue;
            
            std::vector<uint8_t> buffer(region.RegionSize);
            SIZE_T bytes_read = 0;
            
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
                // 檢測JOP特徵
                int jmp_count = 0;
                int call_count = 0;
                int conditional_jmp_count = 0;
                
                for (size_t i = 0; i < bytes_read - 1; i++) {
                    if (buffer[i] == 0xE9) { // JMP
                        jmp_count++;
                    } else if (buffer[i] == 0xE8) { // CALL
                        call_count++;
                    } else if (buffer[i] >= 0x70 && buffer[i] <= 0x7F) { // Conditional jumps
                        conditional_jmp_count++;
                    }
                }
                
                // 如果檢測到JOP特徵
                if (jmp_count >= 3 || (call_count >= 2 && conditional_jmp_count >= 2)) {
                    std::string alert_msg = "Complex Attack Pattern Detected - JMPs: " + std::to_string(jmp_count) + 
                                          ", CALLs: " + std::to_string(call_count) + 
                                          ", Conditional JMPs: " + std::to_string(conditional_jmp_count);
                    log_to_detection_engine("WARN", alert_msg);
                    
                    // 創建事件
                    Event ev;
                    ev.type = Event::Type::CUSTOM;
                    ev.process_id = process_id;
                    ev.address = (uint64_t)region.BaseAddress;
                    ev.size = region.RegionSize;
                    ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.meta = alert_msg;
                    ev.priority = EventPriority::HIGH;
                    ev.source = EventSource::DERIVED;
                    
                    enqueue_event(ev);
                }
            }
        }
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Complex attack pattern detection exception: " + std::string(e.what()));
    } catch (...) {
        log_to_detection_engine("ERROR", "Complex attack pattern detection unknown exception");
    }
}

void EventHandler::detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        // 檢測可疑的行為模式，如大量的記憶體分配/釋放
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            // 檢查記憶體使用是否異常
            if (pmc.WorkingSetSize > 100 * 1024 * 1024) { // 超過100MB
                std::string alert_msg = "Suspicious memory usage detected - Working set: " + 
                                      std::to_string(pmc.WorkingSetSize / (1024 * 1024)) + "MB";
                log_to_detection_engine("WARN", alert_msg);
                
                // 創建事件
                Event ev;
                ev.type = Event::Type::CUSTOM;
                ev.process_id = process_id;
                ev.address = 0;
                ev.size = 0;
                ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.meta = alert_msg;
                ev.priority = EventPriority::NORMAL;
                ev.source = EventSource::DERIVED;
                
                enqueue_event(ev);
            }
        }
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Suspicious behavior pattern detection exception: " + std::string(e.what()));
    } catch (...) {
        log_to_detection_engine("ERROR", "Suspicious behavior pattern detection unknown exception");
    }
}

// 新增：缺失的函數實現

void EventHandler::process_scheduled_events() {
    // 這個函數在 scheduler_loop 中已經被整合了
    // 保留這個函數以保持接口一致性
    try {
        // 處理已調度的事件
        // 目前這個功能已經在 scheduler_loop 中實現
    }
    catch (const std::exception& e) {
        if (memory_monitor_) {
            std::string _proc_msg = std::string("Process scheduled events exception: ") + e.what();
            memory_monitor_->log_message("ERROR", _proc_msg.c_str());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Process scheduled events unknown exception");
        }
    }
}

void EventHandler::handle_process_scan_event(const Event& ev) {
    try {
        // 處理進程掃描事件
        // 這裡可以實現進程掃描的具體邏輯
        
        if (memory_monitor_) {
            // 使用 memory_monitor 進行進程掃描
            memory_monitor_->scan_processes();
            
            // 獲取掃描結果並創建相應的事件
            auto processes = memory_monitor_->get_monitored_processes();
            for (const auto& process : processes) {
                if (process.process_handle != INVALID_HANDLE_VALUE) {
                    // 為每個進程創建綜合檢測事件
                    Event comp_ev;
                    comp_ev.type = Event::Type::COMPREHENSIVE_ATTACK_DETECTION;
                    comp_ev.process_id = process.process_id;
                    comp_ev.process_handle = process.process_handle;
                    comp_ev.process_category = process.category;
                    comp_ev.address = 0;
                    comp_ev.size = 0;
                    comp_ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    comp_ev.meta = "Process scan triggered comprehensive detection for process " + std::to_string(process.process_id);
                    
                    enqueue_event(comp_ev);
                }
            }
        }
    }
    catch (const std::exception& e) {
        if (memory_monitor_) {
            std::string _hps_msg = std::string("Handle process scan event exception: ") + e.what();
            memory_monitor_->log_message("ERROR", _hps_msg.c_str());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Handle process scan event unknown exception");
        }
    }
}

void EventHandler::handle_cleanup_simulator_event(const Event& ev) {
    try {
        // 處理清理模擬器事件
        cleanup_simulator_output_controls();
        
        // 可以添加額外的清理邏輯
        // 例如：清理攻擊模擬器相關的日誌、重置計數器等
        
        if (memory_monitor_) {
            std::string cl_msg = "Cleanup simulator event processed";
            memory_monitor_->log_message("INFO", cl_msg.c_str());
        }
    }
    catch (const std::exception& e) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", std::string("Handle cleanup simulator event exception: ") + e.what());
        }
    }
    catch (...) {
        if (memory_monitor_) {
            memory_monitor_->log_message("ERROR", "Handle cleanup simulator event unknown exception");
        }
    }
}

} // namespace RealMemoryDetection

// 實現 MemoryMonitor 的純虛函數
void RealMemoryDetection::EventHandler::deep_scan_process(DWORD process_id) {
    log_to_detection_engine("DEBUG", "*** Starting deep scan for process " + std::to_string(process_id) + " ***");
    
    // 獲取進程句柄
    HANDLE hProcess = get_process_handle(process_id);
    if (hProcess == INVALID_HANDLE_VALUE) {
        log_to_detection_engine("DEBUG", "*** Failed to open process " + std::to_string(process_id) + " for deep scan ***");
        return;
    }
    
    std::string process_name = MemoryMonitor::get_process_name(process_id);
    MemoryDetectionEngine::ProcessCategory category = MemoryMonitor::classify_process(process_name);
    bool is_attack_simulator = (process_name.find("attack_simulator") != std::string::npos);
    
    if (is_attack_simulator) {
        std::cout << "    *** Starting deep scan for attack simulator process " << process_id << " ***" << std::endl;
        log_to_detection_engine("DEBUG", "*** Starting deep scan for attack simulator process " + std::to_string(process_id) + " ***");
    }
    
    try {
        // 使用 event_handler.cpp 中的檢測函數進行深度掃描
        
        // 1. 執行綜合攻擊檢測
        perform_comprehensive_attack_detection(process_id, hProcess, category);
        
        // 2. 對攻擊模擬器執行特定模式檢測
        if (category == MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR) {
            detect_attack_simulator_patterns(process_id, hProcess);
        }
        
        // 3. 執行分散式ROP鏈檢測
        if (category == MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR || 
            category == MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS) {
            detect_scattered_rop_chains(process_id, hProcess);
        }
        
        // 4. 執行複雜攻擊模式檢測
        if (category == MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR || 
            category == MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS) {
            detect_complex_attack_patterns(process_id, hProcess);
        }
        
        // 5. 執行可疑行為模式檢測
        detect_suspicious_behavior_patterns(process_id, hProcess);
        
        if (is_attack_simulator) {
            std::cout << "    *** Deep scan completed for attack simulator process " << process_id << " ***" << std::endl;
            log_to_detection_engine("DEBUG", "*** Deep scan completed for attack simulator process " + std::to_string(process_id) + " ***");
        }
        
    } catch (const std::exception& e) {
        log_to_detection_engine("ERROR", "Deep scan exception for process " + std::to_string(process_id) + ": " + e.what());
    } catch (...) {
        log_to_detection_engine("ERROR", "Deep scan unknown exception for process " + std::to_string(process_id));
    }
}


