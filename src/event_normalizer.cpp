#include "event_normalizer.hpp"
#include "event_utils.hpp"
#include <algorithm>
#include <iostream>

namespace RealMemoryDetection {

// 全局事件標準化器實例
EventNormalizer g_event_normalizer;

// EventNormalizer 實現
EventNormalizer::EventNormalizer() {
    // 初始化統計信息
    reset_stats();
}

EventNormalizer::~EventNormalizer() = default;

void EventNormalizer::process_raw_event(const RawEvent& raw_event) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.raw_events_processed++;
    
    uint64_t current_qpc = RawEventUtils::get_timestamp_qpc();
    
    switch (raw_event.kind) {
        case RawEventKind::PROTECT: {
            auto transition_event = page_tracker_.on_protect(
                raw_event.pid, raw_event.base, raw_event.old_protect, 
                raw_event.new_protect, raw_event.ts_qpc);
            
            if (transition_event) {
                add_page_transition_event(*transition_event);
            }
            break;
        }
        
        case RawEventKind::WRITE: {
            page_tracker_.on_write(raw_event.pid, raw_event.base, raw_event.size, raw_event.ts_qpc);
            
            // 檢查是否為跨進程寫入
            if (raw_event.flags & 1) { // cross_process flag
                auto write_event = cross_process_tracker_.on_cross_process_write(
                    raw_event.pid, raw_event.tid, raw_event.base, raw_event.size, raw_event.ts_qpc);
                
                if (write_event) {
                    add_cross_process_write_event(*write_event);
                }
            }
            break;
        }
        
        case RawEventKind::ALLOC: {
            page_tracker_.on_alloc(raw_event.pid, raw_event.base, raw_event.size, 
                                 raw_event.new_protect, raw_event.ts_qpc);
            break;
        }
        
        case RawEventKind::REMOTE_THREAD: {
            auto chain_event = remote_exec_tracker_.on_remote_thread(
                raw_event.pid, raw_event.tid, raw_event.aux, raw_event.ts_qpc);
            
            if (chain_event) {
                add_remote_execution_chain_event(*chain_event);
            }
            break;
        }
        
        default:
            break;
    }
    
    // 定期清理過期事件
    if (stats_.raw_events_processed % 1000 == 0) {
        cleanup_expired_events(current_qpc);
    }
}

void EventNormalizer::process_raw_events(const std::vector<RawEvent>& raw_events) {
    for (const auto& event : raw_events) {
        process_raw_event(event);
    }
}

std::vector<PageTransitionEvent> EventNormalizer::get_page_transition_events() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<PageTransitionEvent> events;
    events.swap(page_transition_events_);
    return events;
}

std::vector<CrossProcessWriteEvent> EventNormalizer::get_cross_process_write_events() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<CrossProcessWriteEvent> events;
    events.swap(cross_process_write_events_);
    return events;
}

std::vector<RemoteExecutionChainEvent> EventNormalizer::get_remote_execution_chain_events() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<RemoteExecutionChainEvent> events;
    events.swap(remote_execution_chain_events_);
    return events;
}

std::vector<DarkExecEvent> EventNormalizer::get_dark_exec_events() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<DarkExecEvent> events;
    events.swap(dark_exec_events_);
    return events;
}

void EventNormalizer::cleanup_expired_events(uint64_t current_qpc) {
    page_tracker_.cleanup_expired(current_qpc, MAX_EVENT_AGE_QPC);
    cross_process_tracker_.cleanup_expired(current_qpc, MAX_EVENT_AGE_QPC);
    remote_exec_tracker_.cleanup_expired(current_qpc, MAX_EVENT_AGE_QPC);
    dark_exec_detector_.cleanup_expired(current_qpc, MAX_EVENT_AGE_QPC);
}

void EventNormalizer::reset() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    page_transition_events_.clear();
    cross_process_write_events_.clear();
    remote_execution_chain_events_.clear();
    dark_exec_events_.clear();
    reset_stats();
}

EventNormalizer::NormalizerStats EventNormalizer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void EventNormalizer::reset_stats() {
    stats_ = {};
}

void EventNormalizer::add_page_transition_event(const PageTransitionEvent& event) {
    stats_.page_transitions_generated++;
    
    // 檢查是否需要合併
    auto it = std::find_if(page_transition_events_.begin(), page_transition_events_.end(),
        [&](const PageTransitionEvent& existing) {
            return should_merge_protect_events(existing, event);
        });
    
    if (it != page_transition_events_.end()) {
        // 合併事件
        it->suspicion_score = std::max(it->suspicion_score, event.suspicion_score);
        it->is_suspicious = it->is_suspicious || event.is_suspicious;
        stats_.events_merged++;
    } else {
        // 添加新事件
        if (page_transition_events_.size() >= MAX_EVENTS_PER_TYPE) {
            page_transition_events_.erase(page_transition_events_.begin());
            stats_.events_dropped++;
        }
        page_transition_events_.push_back(event);
    }
}

void EventNormalizer::add_cross_process_write_event(const CrossProcessWriteEvent& event) {
    stats_.cross_process_writes_generated++;
    
    // 檢查是否需要合併
    auto it = std::find_if(cross_process_write_events_.begin(), cross_process_write_events_.end(),
        [&](const CrossProcessWriteEvent& existing) {
            return should_merge_write_events(existing, event);
        });
    
    if (it != cross_process_write_events_.end()) {
        // 合併事件
        it->size += event.size;
        it->is_suspicious = it->is_suspicious || event.is_suspicious;
        stats_.events_merged++;
    } else {
        // 添加新事件
        if (cross_process_write_events_.size() >= MAX_EVENTS_PER_TYPE) {
            cross_process_write_events_.erase(cross_process_write_events_.begin());
            stats_.events_dropped++;
        }
        cross_process_write_events_.push_back(event);
    }
}

void EventNormalizer::add_remote_execution_chain_event(const RemoteExecutionChainEvent& event) {
    stats_.remote_execution_chains_generated++;
    
    if (remote_execution_chain_events_.size() >= MAX_EVENTS_PER_TYPE) {
        remote_execution_chain_events_.erase(remote_execution_chain_events_.begin());
        stats_.events_dropped++;
    }
    remote_execution_chain_events_.push_back(event);
}

void EventNormalizer::add_dark_exec_event(const DarkExecEvent& event) {
    stats_.dark_exec_events_generated++;
    
    if (dark_exec_events_.size() >= MAX_EVENTS_PER_TYPE) {
        dark_exec_events_.erase(dark_exec_events_.begin());
        stats_.events_dropped++;
    }
    dark_exec_events_.push_back(event);
}

bool EventNormalizer::should_merge_protect_events(const PageTransitionEvent& existing, 
                                                 const PageTransitionEvent& new_event) const {
    return existing.pid == new_event.pid && 
           existing.base == new_event.base &&
           (new_event.timestamp_qpc - existing.timestamp_qpc) < MERGE_WINDOW_QPC;
}

bool EventNormalizer::should_merge_write_events(const CrossProcessWriteEvent& existing, 
                                               const CrossProcessWriteEvent& new_event) const {
    return existing.source_pid == new_event.source_pid &&
           existing.target_pid == new_event.target_pid &&
           existing.base == new_event.base &&
           (new_event.timestamp_qpc - existing.timestamp_qpc) < MERGE_WINDOW_QPC;
}

uint32_t EventNormalizer::calculate_suspicion_score(const RawEvent& raw_event) const {
    uint32_t score = 0;
    
    switch (raw_event.kind) {
        case RawEventKind::PROTECT:
            score = calculate_protection_suspicion_score(raw_event.old_protect, raw_event.new_protect);
            break;
        case RawEventKind::REMOTE_THREAD:
            score = calculate_cross_process_suspicion_score(raw_event.pid, raw_event.tid);
            break;
        default:
            break;
    }
    
    return score;
}

uint32_t EventNormalizer::calculate_protection_suspicion_score(uint32_t old_protect, uint32_t new_protect) const {
    uint32_t score = 0;
    
    // RW -> RX 轉換
    if ((old_protect & PAGE_READWRITE) && (new_protect & PAGE_EXECUTE_READ)) {
        score += 40;
    }
    
    // 直接分配 RWX
    if (new_protect == PAGE_EXECUTE_READWRITE) {
        score += 60;
    }
    
    return score;
}

uint32_t EventNormalizer::calculate_cross_process_suspicion_score(uint32_t source_pid, uint32_t target_pid) const {
    uint32_t score = 0;
    
    // 跨進程操作
    if (source_pid != target_pid) {
        score += 30;
    }
    
    // 遠程線程創建
    score += 60;
    
    return score;
}

// PageStateTracker 實現
EventNormalizer::PageStateTracker::PageStateTracker() = default;
EventNormalizer::PageStateTracker::~PageStateTracker() = default;

std::optional<PageTransitionEvent> EventNormalizer::PageStateTracker::on_protect(
    uint32_t pid, uint64_t base, uint32_t old_protect, uint32_t new_protect, uint64_t ts_qpc) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t key = make_page_key(pid, base);
    auto it = page_states_.find(key);
    
    PageTransitionEvent event;
    event.pid = pid;
    event.base = base;
    event.old_protect = old_protect;
    event.new_protect = new_protect;
    event.timestamp_qpc = ts_qpc;
    event.is_suspicious = RawEventUtils::is_suspicious_protection_transition(old_protect, new_protect);
    event.suspicion_score = 0; // 將由外部計算
    
    if (it != page_states_.end()) {
        // 更新現有頁面狀態
        PageState& state = it->second;
        state.last_protect = new_protect;
        
        // 檢查是否為執行轉換
        if ((new_protect & PAGE_EXECUTE) && !(old_protect & PAGE_EXECUTE)) {
            state.exec_transition_qpc = ts_qpc;
            state.flags |= 2; // seen_exec flag
        }
    } else {
        // 創建新的頁面狀態
        PageState state;
        state.base = base;
        state.pid = pid;
        state.last_protect = new_protect;
        state.first_seen_qpc = ts_qpc;
        state.last_write_qpc = 0;
        state.exec_transition_qpc = 0;
        state.write_count = 0;
        state.flags = 0;
        state.pre_exec_hash = 0;
        
        page_states_[key] = state;
    }
    
    return event;
}

void EventNormalizer::PageStateTracker::on_write(uint32_t pid, uint64_t base, size_t len, uint64_t ts_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t key = make_page_key(pid, base);
    auto it = page_states_.find(key);
    
    if (it != page_states_.end()) {
        PageState& state = it->second;
        state.last_write_qpc = ts_qpc;
        state.write_count++;
        state.flags |= 1; // seen_write flag
    }
}

void EventNormalizer::PageStateTracker::on_alloc(uint32_t pid, uint64_t base, uint64_t size, 
                                                uint32_t protect, uint64_t ts_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t key = make_page_key(pid, base);
    auto it = page_states_.find(key);
    
    if (it == page_states_.end()) {
        PageState state;
        state.base = base;
        state.pid = pid;
        state.last_protect = protect;
        state.first_seen_qpc = ts_qpc;
        state.last_write_qpc = 0;
        state.exec_transition_qpc = 0;
        state.write_count = 0;
        state.flags = 0;
        state.pre_exec_hash = 0;
        
        page_states_[key] = state;
    }
}

void EventNormalizer::PageStateTracker::cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = page_states_.begin();
    while (it != page_states_.end()) {
        if (current_qpc - it->second.first_seen_qpc > max_age_qpc) {
            it = page_states_.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<PageState> EventNormalizer::PageStateTracker::get_page_state(uint32_t pid, uint64_t base) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    uint64_t key = make_page_key(pid, base);
    auto it = page_states_.find(key);
    
    if (it != page_states_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

// CrossProcessWriteTracker 實現
EventNormalizer::CrossProcessWriteTracker::CrossProcessWriteTracker() = default;
EventNormalizer::CrossProcessWriteTracker::~CrossProcessWriteTracker() = default;

std::optional<CrossProcessWriteEvent> EventNormalizer::CrossProcessWriteTracker::on_cross_process_write(
    uint32_t source_pid, uint32_t target_pid, uint64_t base, uint64_t size, uint64_t ts_qpc) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    CrossProcessWriteEvent event;
    event.source_pid = source_pid;
    event.target_pid = target_pid;
    event.base = base;
    event.size = size;
    event.timestamp_qpc = ts_qpc;
    event.is_suspicious = true; // 跨進程寫入通常都是可疑的
    
    return event;
}

void EventNormalizer::CrossProcessWriteTracker::cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    recent_writes_.erase(
        std::remove_if(recent_writes_.begin(), recent_writes_.end(),
            [current_qpc, max_age_qpc](const WriteRecord& record) {
                return current_qpc - record.timestamp_qpc > max_age_qpc;
            }),
        recent_writes_.end()
    );
}

// RemoteExecutionChainTracker 實現
EventNormalizer::RemoteExecutionChainTracker::RemoteExecutionChainTracker() = default;
EventNormalizer::RemoteExecutionChainTracker::~RemoteExecutionChainTracker() = default;

std::optional<RemoteExecutionChainEvent> EventNormalizer::RemoteExecutionChainTracker::on_remote_thread(
    uint32_t source_pid, uint32_t target_pid, uint64_t start_address, uint64_t ts_qpc) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    RemoteExecutionChainEvent event;
    event.source_pid = source_pid;
    event.target_pid = target_pid;
    event.start_address = start_address;
    event.timestamp_qpc = ts_qpc;
    event.is_suspicious = true; // 遠程線程創建通常都是可疑的
    event.suspicion_score = 90; // 高可疑性評分
    
    return event;
}

void EventNormalizer::RemoteExecutionChainTracker::cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    recent_chains_.erase(
        std::remove_if(recent_chains_.begin(), recent_chains_.end(),
            [current_qpc, max_age_qpc](const ChainRecord& record) {
                return current_qpc - record.timestamp_qpc > max_age_qpc;
            }),
        recent_chains_.end()
    );
}

// DarkExecDetector 實現
EventNormalizer::DarkExecDetector::DarkExecDetector() = default;
EventNormalizer::DarkExecDetector::~DarkExecDetector() = default;

std::optional<DarkExecEvent> EventNormalizer::DarkExecDetector::check_dark_exec(
    uint32_t pid, uint64_t base, uint64_t size, uint64_t ts_qpc) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // 檢查是否為已知的可執行頁面
    for (const auto& known_page : known_exec_pages_) {
        if (known_page.pid == pid && 
            base >= known_page.base && 
            base < known_page.base + known_page.size) {
            return std::nullopt; // 不是暗執行
        }
    }
    
    // 發現暗執行
    DarkExecEvent event;
    event.pid = pid;
    event.base = base;
    event.size = size;
    event.timestamp_qpc = ts_qpc;
    event.suspicion_score = 80; // 高可疑性評分
    
    return event;
}

void EventNormalizer::DarkExecDetector::record_known_exec_page(uint32_t pid, uint64_t base, uint64_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    KnownExecPage page;
    page.pid = pid;
    page.base = base;
    page.size = size;
    page.timestamp_qpc = RawEventUtils::get_timestamp_qpc();
    
    known_exec_pages_.push_back(page);
}

void EventNormalizer::DarkExecDetector::cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    known_exec_pages_.erase(
        std::remove_if(known_exec_pages_.begin(), known_exec_pages_.end(),
            [current_qpc, max_age_qpc](const KnownExecPage& page) {
                return current_qpc - page.timestamp_qpc > max_age_qpc;
            }),
        known_exec_pages_.end()
    );
}

} // namespace RealMemoryDetection
