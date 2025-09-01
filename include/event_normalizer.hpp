#pragma once

#include <unordered_map>
#include <mutex>
#include <vector>
#include <chrono>
#include "raw_event_types.hpp"
#include "ring_buffer.hpp"

namespace RealMemoryDetection {

// 事件標準化器類
class EventNormalizer {
public:
    EventNormalizer();
    ~EventNormalizer();
    
    // 處理原始事件
    void process_raw_event(const RawEvent& raw_event);
    
    // 批量處理原始事件
    void process_raw_events(const std::vector<RawEvent>& raw_events);
    
    // 獲取標準化事件
    std::vector<PageTransitionEvent> get_page_transition_events();
    std::vector<CrossProcessWriteEvent> get_cross_process_write_events();
    std::vector<RemoteExecutionChainEvent> get_remote_execution_chain_events();
    std::vector<DarkExecEvent> get_dark_exec_events();
    
    // 清理過期事件
    void cleanup_expired_events(uint64_t current_qpc);
    
    // 重置狀態
    void reset();
    
    // 獲取統計信息
    struct NormalizerStats {
        uint64_t raw_events_processed;
        uint64_t page_transitions_generated;
        uint64_t cross_process_writes_generated;
        uint64_t remote_execution_chains_generated;
        uint64_t dark_exec_events_generated;
        uint64_t events_merged;
        uint64_t events_dropped;
    };
    
    NormalizerStats get_stats() const;
    void reset_stats();

private:
    // 頁面狀態追蹤器
    class PageStateTracker {
    public:
        PageStateTracker();
        ~PageStateTracker();
        
        // 處理保護變更事件
        std::optional<PageTransitionEvent> on_protect(uint32_t pid, uint64_t base, 
                                                     uint32_t old_protect, uint32_t new_protect, 
                                                     uint64_t ts_qpc);
        
        // 處理寫入事件
        void on_write(uint32_t pid, uint64_t base, size_t len, uint64_t ts_qpc);
        
        // 處理分配事件
        void on_alloc(uint32_t pid, uint64_t base, uint64_t size, uint32_t protect, uint64_t ts_qpc);
        
        // 清理過期頁面狀態
        void cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc);
        
        // 獲取頁面狀態
        std::optional<PageState> get_page_state(uint32_t pid, uint64_t base) const;
        
    private:
        mutable std::mutex mutex_;
        std::unordered_map<uint64_t, PageState> page_states_; // key = ((uint64_t)pid << 32) | (base >> 12)
        
        // 生成頁面鍵值
        static uint64_t make_page_key(uint32_t pid, uint64_t base) {
            return ((uint64_t)pid << 32) | (base >> 12);
        }
    };
    
    // 跨進程寫入追蹤器
    class CrossProcessWriteTracker {
    public:
        CrossProcessWriteTracker();
        ~CrossProcessWriteTracker();
        
        // 處理跨進程寫入事件
        std::optional<CrossProcessWriteEvent> on_cross_process_write(uint32_t source_pid, 
                                                                     uint32_t target_pid, 
                                                                     uint64_t base, uint64_t size, 
                                                                     uint64_t ts_qpc);
        
        // 清理過期事件
        void cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc);
        
    private:
        struct WriteRecord {
            uint32_t source_pid;
            uint32_t target_pid;
            uint64_t base;
            uint64_t size;
            uint64_t timestamp_qpc;
            uint32_t count;
        };
        
        mutable std::mutex mutex_;
        std::vector<WriteRecord> recent_writes_;
    };
    
    // 遠程執行鏈追蹤器
    class RemoteExecutionChainTracker {
    public:
        RemoteExecutionChainTracker();
        ~RemoteExecutionChainTracker();
        
        // 處理遠程線程創建事件
        std::optional<RemoteExecutionChainEvent> on_remote_thread(uint32_t source_pid, 
                                                                  uint32_t target_pid, 
                                                                  uint64_t start_address, 
                                                                  uint64_t ts_qpc);
        
        // 清理過期事件
        void cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc);
        
    private:
        struct ChainRecord {
            uint32_t source_pid;
            uint32_t target_pid;
            uint64_t start_address;
            uint64_t timestamp_qpc;
            bool has_write_before;
        };
        
        mutable std::mutex mutex_;
        std::vector<ChainRecord> recent_chains_;
    };
    
    // 暗執行檢測器
    class DarkExecDetector {
    public:
        DarkExecDetector();
        ~DarkExecDetector();
        
        // 檢查是否為暗執行
        std::optional<DarkExecEvent> check_dark_exec(uint32_t pid, uint64_t base, 
                                                    uint64_t size, uint64_t ts_qpc);
        
        // 記錄已知的可執行頁面
        void record_known_exec_page(uint32_t pid, uint64_t base, uint64_t size);
        
        // 清理過期記錄
        void cleanup_expired(uint64_t current_qpc, uint64_t max_age_qpc);
        
    private:
        struct KnownExecPage {
            uint32_t pid;
            uint64_t base;
            uint64_t size;
            uint64_t timestamp_qpc;
        };
        
        mutable std::mutex mutex_;
        std::vector<KnownExecPage> known_exec_pages_;
    };
    
    // 成員變量
    PageStateTracker page_tracker_;
    CrossProcessWriteTracker cross_process_tracker_;
    RemoteExecutionChainTracker remote_exec_tracker_;
    DarkExecDetector dark_exec_detector_;
    
    // 事件緩衝區
    std::vector<PageTransitionEvent> page_transition_events_;
    std::vector<CrossProcessWriteEvent> cross_process_write_events_;
    std::vector<RemoteExecutionChainEvent> remote_execution_chain_events_;
    std::vector<DarkExecEvent> dark_exec_events_;
    
    // 統計信息
    mutable std::mutex stats_mutex_;
    NormalizerStats stats_;
    
    // 配置參數
    static constexpr uint64_t MAX_EVENT_AGE_QPC = 10000000; // 約 1 秒（假設 QPC 頻率為 10MHz）
    static constexpr uint64_t MERGE_WINDOW_QPC = 500000;    // 約 50ms
    static constexpr size_t MAX_EVENTS_PER_TYPE = 1000;     // 每種類型最大事件數
    
    // 輔助方法
    void add_page_transition_event(const PageTransitionEvent& event);
    void add_cross_process_write_event(const CrossProcessWriteEvent& event);
    void add_remote_execution_chain_event(const RemoteExecutionChainEvent& event);
    void add_dark_exec_event(const DarkExecEvent& event);
    
    // 事件合併邏輯
    bool should_merge_protect_events(const PageTransitionEvent& existing, const PageTransitionEvent& new_event) const;
    bool should_merge_write_events(const CrossProcessWriteEvent& existing, const CrossProcessWriteEvent& new_event) const;
    
    // 可疑性評分
    uint32_t calculate_suspicion_score(const RawEvent& raw_event) const;
    uint32_t calculate_protection_suspicion_score(uint32_t old_protect, uint32_t new_protect) const;
    uint32_t calculate_cross_process_suspicion_score(uint32_t source_pid, uint32_t target_pid) const;
};

// 全局事件標準化器實例
extern EventNormalizer g_event_normalizer;

// 便捷函數
inline void push_raw_event(const RawEvent& raw_event) {
    g_event_normalizer.process_raw_event(raw_event);
}

inline void push_raw_events(const std::vector<RawEvent>& raw_events) {
    g_event_normalizer.process_raw_events(raw_events);
}

} // namespace RealMemoryDetection
