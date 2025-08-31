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

namespace RealMemoryDetection {

EventHandler::EventHandler() 
    : running_(false)
    , scheduler_running_(false)
    , memory_monitor_(nullptr)
    , detection_engine_(nullptr)
    , status_tick_counter_(0)
    , comprehensive_tick_counter_(0)
    , total_detections_(0)
    , last_scan_time_(std::chrono::steady_clock::now())
    , last_comprehensive_time_(std::chrono::steady_clock::now())
    , last_status_time_(std::chrono::steady_clock::now())
    , last_cycle_time_(std::chrono::steady_clock::now()) {
}

EventHandler::~EventHandler() {
    stop();
}

void EventHandler::start() {
    if (running_.load()) return;
    std::cout << "EventHandler started successfully" << std::endl;
    running_.store(true);
    scheduler_running_.store(true);
    
    // 啟動快速事件執行緒
    fast_event_thread_ = std::thread(&EventHandler::fast_event_loop, this);
    
    // 啟動延遲分析器執行緒
    deferred_analyzer_thread_ = std::thread(&EventHandler::deferred_analyzer_loop, this);
    
    // 啟動定時調度執行緒
    scheduler_thread_ = std::thread(&EventHandler::scheduler_loop, this);
}

void EventHandler::stop() {
    if (!running_.load()) return;
    
    running_.store(false);
    scheduler_running_.store(false);
    
    // 發送終止事件喚醒所有等待的執行緒
    Event terminate_ev;
    terminate_ev.type = Event::Type::TERMINATE;
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
    if (hProcess) {
        ProcessHandleInfo info;
        info.handle = hProcess;
        info.last_used = std::chrono::steady_clock::now();
        info.ref_count = 1;
        info.is_valid = true;
        process_handle_cache_[pid] = info;
        return hProcess;
    }
    
    return INVALID_HANDLE_VALUE;
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
            
            // 每100ms檢查一次
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        catch (const std::exception& e) {
            MemoryDetectionEngine::log_message("ERROR", std::string("Scheduler loop exception: ") + e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        catch (...) {
            MemoryDetectionEngine::log_message("ERROR", "Scheduler loop unknown exception");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void EventHandler::schedule_periodic_scan() {
    // 創建記憶體掃描事件
    Event ev;
    ev.type = Event::Type::MEMORY_REGION_SCAN;
    ev.process_id = GetCurrentProcessId();
    ev.address = 0;
    ev.size = 0;
    ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    ev.meta = "Periodic memory scan";
    ev.priority = EventPriority::NORMAL;
    ev.source = EventSource::INTERNAL;
    ev.depth = 0;
    ev.flags = 0;
    ev.sequence_id = 0;
    
    enqueue_event(ev);
}

void EventHandler::schedule_comprehensive_detection() {
    if (!memory_monitor_) return;
    
    // 獲取監控的進程並為每個進程創建綜合檢測事件
    auto processes = memory_monitor_->get_monitored_processes();
    for (const auto& process : processes) {
        if (process.process_handle != INVALID_HANDLE_VALUE) {
            Event ev;
            ev.type = Event::Type::COMPREHENSIVE_ATTACK_DETECTION;
            ev.process_id = process.process_id;
            ev.process_handle = process.process_handle;
            ev.process_category = process.category;
            ev.address = 0;
            ev.size = 0;
            ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            ev.meta = "Comprehensive attack detection for process " + std::to_string(process.process_id);
            ev.priority = EventPriority::HIGH;
            ev.source = EventSource::INTERNAL;
            ev.depth = 0;
            ev.flags = 0;
            ev.sequence_id = 0;
            
            enqueue_event(ev);
        }
    }
    
    // 每3次循環執行一次全進程掃描
    comprehensive_tick_counter_++;
    if (comprehensive_tick_counter_ % 3 == 0) {
        Event ev;
        ev.type = Event::Type::ALL_PROCESSES_SCAN;
        ev.process_id = 0;
        ev.address = 0;
        ev.size = 0;
        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        ev.meta = "All processes scan";
        ev.priority = EventPriority::NORMAL;
        ev.source = EventSource::INTERNAL;
        ev.depth = 0;
        ev.flags = 0;
        ev.sequence_id = 0;
        
        enqueue_event(ev);
    }
}

void EventHandler::schedule_status_output() {
    status_tick_counter_++;
    if (status_tick_counter_ >= 5) {
        Event ev;
        ev.type = Event::Type::STATUS_OUTPUT;
        ev.process_id = 0;
        ev.address = 0;
        ev.size = 0;
        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        ev.meta = "Status output";
        ev.priority = EventPriority::LOW;
        ev.source = EventSource::INTERNAL;
        ev.depth = 0;
        ev.flags = 0;
        ev.sequence_id = 0;
        
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
                case Event::Type::MEM_PROTECT_CHANGE:
                case Event::Type::HEAP_CORRUPTION:
                case Event::Type::CREATE_REMOTE_THREAD:
                case Event::Type::IMAGE_LOAD:
                case Event::Type::FILE_WRITE:
                case Event::Type::CUSTOM:
                    // 原有的快速啟發式檢查
                    schedule_suspicious_region(ev.process_id, ev.address);
                    break;
                default:
                    break;
            }
        }
        catch (const std::exception& e) {
            MemoryDetectionEngine::log_message("ERROR", std::string("Event processing exception: ") + e.what());
        }
        catch (...) {
            MemoryDetectionEngine::log_message("ERROR", "Event processing unknown exception");
        }
    }
}

void EventHandler::handle_memory_region_scan_event(const Event& ev) {
    scan_memory_for_attacks();
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
    MemoryDetectionEngine::log_message("INFO", "Detection cycle completed. Total detections: " + std::to_string(total_detections_.load()));
    
    // 清理舊的攻擊模擬器輸出控制項
    cleanup_simulator_output_controls();
}

void EventHandler::handle_executable_integrity_check_event(const Event& ev) {
    check_executable_integrity((LPVOID)ev.address, ev.size, ev.process_id, ev.depth);
}

void EventHandler::handle_heap_region_check_event(const Event& ev) {
    check_heap_region((LPVOID)ev.address, ev.size);
}

void EventHandler::fast_event_loop() {
    while (running_.load()) {
        try {
            std::vector<Event> batch = get_event_batch();
            
            if (!batch.empty()) {
                analyze_event_batch(batch);
            }
        }
        catch (...) {
            MemoryDetectionEngine::log_message("ERROR", "Exception in fast_event_loop");
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
            MemoryDetectionEngine::log_message("ERROR", std::string("Deferred analyzer exception: ") + e.what());
        }
        catch (...) {
            MemoryDetectionEngine::log_message("ERROR", "Deferred analyzer unknown exception");
        }
    }
}

// 實現從 detection_loop 移植過來的方法
void EventHandler::scan_memory_for_attacks() {
    try {
        std::cout << "  scan_memory_for_attacks: Starting..." << std::endl;
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int scanned_regions = 0;
        
        while (VirtualQuery(address, &mbi, sizeof(mbi)) && scanned_regions < max_regions_to_scan_) {
            try {
                std::cout << "  Scanning region " << scanned_regions + 1 << " at " << address << std::endl;
                
                if (mbi.State == MEM_COMMIT) {
                    // 檢查可執行記憶體
                    if (mbi.Protect & PAGE_EXECUTE) {
                        Event ev;
                        ev.type = Event::Type::EXECUTABLE_INTEGRITY_CHECK;
                        ev.process_id = GetCurrentProcessId();
                        ev.address = (uint64_t)mbi.BaseAddress;
                        ev.size = mbi.RegionSize;
                        ev.memory_info = mbi;
                        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        ev.meta = "Executable integrity check";
                        
                        enqueue_event(ev);
                    }
                    
                    // 檢查堆區域
                    if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || 
                        (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_READONLY) ||
                        (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                        Event ev;
                        ev.type = Event::Type::HEAP_REGION_CHECK;
                        ev.process_id = GetCurrentProcessId();
                        ev.address = (uint64_t)mbi.BaseAddress;
                        ev.size = mbi.RegionSize;
                        ev.memory_info = mbi;
                        ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count();
                        ev.meta = "Heap region check";
                        
                        enqueue_event(ev);
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
        MemoryDetectionEngine::log_message("ERROR", "Error in scan_memory_for_attacks: " + std::string(e.what()));
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
        MemoryDetectionEngine::log_message("ERROR", "Error in scan_all_processes_memory: " + std::string(e.what()));
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
        
        MemoryDetectionEngine::log_message("INFO", "Simulator output controls cleaned up");
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Cleanup simulator output controls exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Cleanup simulator output controls unknown exception");
    }
}

void EventHandler::check_executable_integrity(LPVOID base_address, SIZE_T region_size, DWORD pid, int depth) {
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
        
        if (ReadProcessMemory(hProcess, base_address, buffer.data(), buffer.size(), &bytes_read) && bytes_read > 0) {
            // 檢查指令完整性
            int valid_instructions = 0;
            int total_checks = 0;
            
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
                Event ev;
                ev.type = Event::Type::CUSTOM; // 改為 CUSTOM 避免無限遞迴
                ev.process_id = pid;
                ev.address = (uint64_t)base_address;
                ev.size = region_size;
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
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Executable integrity check exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Executable integrity check unknown exception");
    }
}

void EventHandler::check_heap_region(LPVOID base_address, SIZE_T region_size) {
    try {
        // 讀取記憶體內容
        std::vector<uint8_t> buffer((region_size < static_cast<SIZE_T>(2048)) ? region_size : static_cast<SIZE_T>(2048)); // 限制讀取大小
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(GetCurrentProcess(), base_address, buffer.data(), buffer.size(), &bytes_read) && bytes_read > 0) {
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
                Event ev;
                ev.type = Event::Type::HEAP_CORRUPTION;
                ev.process_id = GetCurrentProcessId();
                ev.address = (uint64_t)base_address;
                ev.size = region_size;
                ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.meta = "Heap corruption detected - Null sequences: " + std::to_string(null_sequences) + 
                         ", Repeated patterns: " + std::to_string(repeated_patterns) + 
                         ", Suspicious bytes: " + std::to_string(suspicious_bytes);
                
                enqueue_event(ev);
                
                // 調度可疑區域進行深度分析
                schedule_suspicious_region(GetCurrentProcessId(), (uint64_t)base_address);
            }
        }
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Heap region check exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Heap region check unknown exception");
    }
}

void EventHandler::perform_comprehensive_attack_detection(DWORD process_id, HANDLE hProcess, MemoryDetectionEngine::ProcessCategory category) {
    try {
        // 更新掃描運行計數（而不是檢測計數）
        update_stats_on_scan();
        
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
        
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Comprehensive attack detection exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Comprehensive attack detection unknown exception");
    }
}

// 新增：攻擊模擬器特定模式檢測
void EventHandler::detect_attack_simulator_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        
        // 檢查是否為攻擊模擬器進程
        if (process_name.find("attack_simulator") == std::string::npos) {
            return;
        }
        
        // 掃描所有可執行記憶體區域
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
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
                    Event ev;
                    ev.type = Event::Type::CUSTOM;
                    ev.process_id = process_id;
                    ev.address = (uint64_t)region.BaseAddress;
                    ev.size = region.RegionSize;
                    ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.meta = "Attack Simulator ROP Detected - RETs: " + std::to_string(ret_count) + 
                             ", POPs: " + std::to_string(pop_count) + 
                             ", Max Consecutive RETs: " + std::to_string(max_consecutive_ret);
                    
                    enqueue_event(ev);
                    
                    // 調度可疑區域進行深度分析
                    schedule_suspicious_region(process_id, (uint64_t)region.BaseAddress);
                }
            }
        }
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Attack simulator pattern detection exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Attack simulator pattern detection unknown exception");
    }
}

// 新增：分散式ROP鏈檢測
void EventHandler::detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
    try {
        // 檢測字串寫入操作
        EventUtils::detect_string_write_operations(process_id, hProcess);
        
        // 分散式ROP檢測邏輯
        // std::lock_guard<std::mutex> lock(rop_chain_mutex_); // 需要添加這個mutex
        
        // 獲取進程的所有可執行記憶體區域
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                exec_regions.push_back(mbi);
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break; // 溢出檢查
        }
        
        // 調試輸出：顯示找到的可執行區域數量
        std::string debug_msg = "*** SCATTERED ROP SCAN: Process=" + std::to_string(process_id) + 
                              ", Found " + std::to_string(exec_regions.size()) + " executable regions ***";
        MemoryDetectionEngine::log_message("DEBUG", debug_msg);
        
        // 掃描每個可執行區域尋找gadgets
        std::vector<ROPGadget> found_gadgets;
        std::vector<AttackChain> syscall_chains;
        
        // 獲取進程類別
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        MemoryDetectionEngine::ProcessCategory category = MemoryDetectionEngine::ProcessCategory::USER_PROCESS; // 簡化處理
        bool is_simulator = (process_name.find("attack_simulator") != std::string::npos);
        
        for (const auto& region : exec_regions) {
            // 使用性能優化參數限制掃描大小
            if (region.RegionSize > 8192) continue; // MAX_SCAN_SIZE
            
            // 對於攻擊模擬器，添加額外的過濾條件
            if (is_simulator) {
                // 檢查記憶體保護屬性，優先掃描可寫可執行區域
                if (!(region.Protect & PAGE_EXECUTE_READWRITE)) {
                    continue;
                }
                
                // 簡單的熵值檢查
                std::vector<uint8_t> entropy_buffer((region.RegionSize < static_cast<SIZE_T>(1024)) ? region.RegionSize : static_cast<SIZE_T>(1024));
                SIZE_T entropy_bytes_read = 0;
                if (ReadProcessMemory(hProcess, region.BaseAddress, entropy_buffer.data(), entropy_buffer.size(), &entropy_bytes_read)) {
                    // 使用 EventUtils 進行熵值計算
                    double entropy = EventUtils::calculate_shannon_entropy(entropy_buffer.data(), entropy_bytes_read);
                    
                    if (entropy < 2.0) { // 降低熵值閾值，適應更多攻擊模式
                        MemoryDetectionEngine::log_message("DEBUG", 
                            "*** LOW ENTROPY REGION SKIPPED: Base=0x" + EventUtils::format_address((uint64_t)region.BaseAddress) + 
                            ", Entropy=" + std::to_string(entropy) + " ***");
                        continue;
                    }
                }
            }
            
            // 調試輸出：顯示正在掃描的區域（改為DEBUG級別，減少輸出頻率）
            std::string region_debug = "*** SCANNING REGION: Base=0x" + EventUtils::format_address((uint64_t)region.BaseAddress) + 
                                     ", Size=" + std::to_string(region.RegionSize) + 
                                     ", Protection=0x" + std::to_string(region.Protect) + " ***";
            MemoryDetectionEngine::log_message("DEBUG", region_debug);
            
            std::vector<uint8_t> buffer(region.RegionSize);
            SIZE_T bytes_read = 0;
            
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
                // 同時進行一般ROP檢測和系統調用ROP檢測
                for (size_t i = 0; i < bytes_read - 8; i += 4) { // SCAN_STEP_SIZE
                    // 檢查RET指令
                    if (buffer[i] == 0xC3) {
                        // 分析前面的指令
                        std::vector<uint8_t> gadget_bytes;
                        std::string instruction = "";
                        
                        // 收集gadget字節（使用優化的最大大小）
                        size_t start = (i >= 16) ? i - 16 : 0; // MAX_GADGET_SIZE
                        for (size_t j = start; j <= i; j++) {
                            gadget_bytes.push_back(buffer[j]);
                        }
                        
                        // 使用增強的指令分析
                        if (gadget_bytes.size() >= 2) {
                            uint8_t prev = gadget_bytes[gadget_bytes.size() - 2];
                            if (prev >= 0x58 && prev <= 0x5F) {
                                instruction = "pop r32; ret";
                            } else if (prev == 0x94) {
                                instruction = "xchg eax, esp; ret";
                            } else if (gadget_bytes.size() >= 4) {
                                if (gadget_bytes[gadget_bytes.size() - 4] == 0x83 && 
                                    gadget_bytes[gadget_bytes.size() - 3] == 0xC4) {
                                    instruction = "add esp, XX; ret";
                                }
                            } else {
                                instruction = "ret";
                            }
                        }
                        
                        uint64_t gadget_address = (uint64_t)region.BaseAddress + i;
                        ROPGadget gadget(gadget_address, gadget_bytes, instruction);
                        found_gadgets.push_back(gadget);
                    }
                }
                
                // 在相同的緩衝區中檢測系統調用ROP鏈
                EventUtils::detect_syscall_rop_chains(buffer, (uint64_t)region.BaseAddress, syscall_chains);
            }
        }
        
        // 分析gadget分佈模式（改為DEBUG級別）
        std::string gadget_debug = "*** GADGET SCAN COMPLETE: Found " + std::to_string(found_gadgets.size()) + " gadgets ***";
        MemoryDetectionEngine::log_message("DEBUG", gadget_debug);
        
        // 報告系統調用ROP鏈檢測結果
        if (!syscall_chains.empty()) {
            EventUtils::report_syscall_rop_detection(process_id, syscall_chains);
        }
        
        if (found_gadgets.size() >= 5) { // MIN_GADGET_COUNT
            EventUtils::analyze_gadget_distribution(process_id, found_gadgets);
        }
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Scattered ROP chain detection exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Scattered ROP chain detection unknown exception");
    }
}

// 新增：複雜攻擊模式檢測
void EventHandler::detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        // 檢測複雜的攻擊模式，如JOP (Jump-Oriented Programming)
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
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
                    Event ev;
                    ev.type = Event::Type::CUSTOM;
                    ev.process_id = process_id;
                    ev.address = (uint64_t)region.BaseAddress;
                    ev.size = region.RegionSize;
                    ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    ev.meta = "Complex Attack Pattern Detected - JMPs: " + std::to_string(jmp_count) + 
                             ", CALLs: " + std::to_string(call_count) + 
                             ", Conditional JMPs: " + std::to_string(conditional_jmp_count);
                    
                    enqueue_event(ev);
                    
                    // 調度可疑區域進行深度分析
                    schedule_suspicious_region(process_id, (uint64_t)region.BaseAddress);
                }
            }
        }
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Complex attack pattern detection exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Complex attack pattern detection unknown exception");
    }
}

// 新增：可疑行為模式檢測
void EventHandler::detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess) {
    try {
        // 檢測可疑的行為模式，如大量的記憶體分配/釋放
        // 這裡可以實現更複雜的行為分析邏輯
        
        // 簡單的實現：檢查進程的記憶體使用模式
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            // 檢查記憶體使用是否異常
            if (pmc.WorkingSetSize > 100 * 1024 * 1024) { // 超過100MB
                Event ev;
                ev.type = Event::Type::CUSTOM;
                ev.process_id = process_id;
                ev.address = 0;
                ev.size = 0;
                ev.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                ev.meta = "Suspicious memory usage detected - Working set: " + 
                         std::to_string(pmc.WorkingSetSize / (1024 * 1024)) + "MB";
                
                enqueue_event(ev);
            }
        }
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Suspicious behavior pattern detection exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Suspicious behavior pattern detection unknown exception");
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
        MemoryDetectionEngine::log_message("ERROR", std::string("Process scheduled events exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Process scheduled events unknown exception");
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
        MemoryDetectionEngine::log_message("ERROR", std::string("Handle process scan event exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Handle process scan event unknown exception");
    }
}

void EventHandler::handle_cleanup_simulator_event(const Event& ev) {
    try {
        // 處理清理模擬器事件
        cleanup_simulator_output_controls();
        
        // 可以添加額外的清理邏輯
        // 例如：清理攻擊模擬器相關的日誌、重置計數器等
        
        MemoryDetectionEngine::log_message("INFO", "Cleanup simulator event processed");
    }
    catch (const std::exception& e) {
        MemoryDetectionEngine::log_message("ERROR", std::string("Handle cleanup simulator event exception: ") + e.what());
    }
    catch (...) {
        MemoryDetectionEngine::log_message("ERROR", "Handle cleanup simulator event unknown exception");
    }
}

} // namespace RealMemoryDetection

