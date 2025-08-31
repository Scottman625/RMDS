# 事件驅動架構 (Event-Driven Architecture)

## 概述

本項目已成功將原本基於 `detection_loop` 的同步檢測架構重構為事件驅動架構。新的架構使用 `EventHandler` 類別來管理所有檢測功能，提供更好的模組化、可擴展性和性能。

## 架構對比

### 舊架構 (detection_loop)
```cpp
void detection_loop() {
    while (running_) {
        // 同步執行所有檢測邏輯
        memory_monitor_->scan_processes();
        memory_monitor_->scan_memory_regions();
        
        // 執行高層檢測邏輯
        for (const auto& process : processes) {
            perform_comprehensive_attack_detection(process.process_id, 
                                                 process.process_handle, 
                                                 process.category);   
        }
        
        // 記憶體掃描
        scan_memory_for_attacks();
        
        // 全進程掃描
        if (cycle_output_counter_ % 3 == 0) {
            scan_all_processes_memory();
        }
        
        // 狀態輸出
        if (status_output_counter_ >= 5) {
            show_status();
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}
```

### 新架構 (EventHandler)
```cpp
class EventHandler {
    // 三線程架構
    std::thread fast_event_thread_;        // 快速事件處理
    std::thread deferred_analyzer_thread_; // 延遲分析
    std::thread scheduler_thread_;         // 定時調度
    
    // 事件隊列
    std::deque<Event> event_queue_;
    
    // 定時調度
    void scheduler_loop();
    void schedule_periodic_scan();
    void schedule_comprehensive_detection();
};
```

## 核心組件

### 1. Event 結構
```cpp
struct Event {
    enum class Type : uint8_t {
        // 原有事件類型
        MEM_PROTECT_CHANGE,
        WRITE_PROCESS_MEMORY,
        CREATE_REMOTE_THREAD,
        IMAGE_LOAD,
        FILE_WRITE,
        HEAP_CORRUPTION,
        CUSTOM,
        
        // 新增事件類型 - 對應 detection_loop 功能
        PROCESS_SCAN,                    // 進程掃描事件
        MEMORY_REGION_SCAN,              // 記憶體區域掃描事件
        EXECUTABLE_INTEGRITY_CHECK,      // 可執行檔案完整性檢查
        HEAP_REGION_CHECK,               // 堆區域檢查
        COMPREHENSIVE_ATTACK_DETECTION,  // 綜合攻擊檢測
        ALL_PROCESSES_SCAN,              // 全進程掃描
        STATUS_OUTPUT,                   // 狀態輸出
        CYCLE_COMPLETION,                // 循環完成
        CLEANUP_SIMULATOR                // 清理模擬器
    };
    
    Type type;
    DWORD process_id;
    uint64_t address;
    size_t size;
    uint64_t timestamp_ms;
    std::string meta;
    
    // 擴展欄位
    HANDLE process_handle;
    MemoryDetectionEngine::ProcessCategory process_category;
    MEMORY_BASIC_INFORMATION memory_info;
    std::vector<uint8_t> memory_data;
};
```

### 2. 三線程架構

#### 快速事件線程 (fast_event_thread_)
- **功能**: 處理即時事件，執行輕量級檢測
- **頻率**: 每50ms處理一批事件
- **批次大小**: 最多128個事件

#### 延遲分析線程 (deferred_analyzer_thread_)
- **功能**: 對可疑區域進行深度分析
- **頻率**: 每1秒執行一次
- **批次大小**: 最多200個可疑區域

#### 定時調度線程 (scheduler_thread_)
- **功能**: 定期創建檢測事件
- **頻率**: 每100ms檢查一次
- **調度項目**:
  - 記憶體掃描: 每10秒
  - 綜合檢測: 每10秒
  - 狀態輸出: 每60秒
  - 循環完成: 每300秒

## 功能遷移對照表

| 原 detection_loop 功能 | 新 EventHandler 實現 | 說明 |
|----------------------|-------------------|------|
| `memory_monitor_->scan_processes()` | `schedule_comprehensive_detection()` | 通過事件調度進程掃描 |
| `perform_comprehensive_attack_detection()` | `handle_comprehensive_attack_detection_event()` | 事件驅動的綜合檢測 |
| `scan_memory_for_attacks()` | `handle_memory_region_scan_event()` | 記憶體掃描事件處理 |
| `scan_all_processes_memory()` | `handle_all_processes_scan_event()` | 全進程掃描事件處理 |
| `show_status()` | `handle_status_output_event()` | 狀態輸出事件處理 |
| 循環完成處理 | `handle_cycle_completion_event()` | 循環完成事件處理 |

## 檢測功能實現

### 1. 可執行檔案完整性檢查
```cpp
void EventHandler::check_executable_integrity(LPVOID base_address, SIZE_T region_size) {
    // 檢查指令有效性比例
    // 檢測常見的有效指令模式 (NOP, RET, POP, PUSH, JMP)
    // 如果指令有效性過低，調度可疑區域進行深度分析
}
```

### 2. 堆區域檢查
```cpp
void EventHandler::check_heap_region(LPVOID base_address, SIZE_T region_size) {
    // 檢查堆損壞模式
    // 檢測連續NULL字節、重複模式、可疑字節
    // 報告堆損壞事件
}
```

### 3. 攻擊模擬器特定檢測
```cpp
void EventHandler::detect_attack_simulator_patterns(DWORD process_id, HANDLE hProcess) {
    // 專門檢測攻擊模擬器創建的特定攻擊模式
    // 掃描可執行記憶體區域尋找ROP gadgets
    // 檢測RET、POP指令的分布模式
}
```

### 4. 分散式ROP鏈檢測
```cpp
void EventHandler::detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
    // 檢測分散在不同記憶體區域的ROP鏈
    // 掃描可執行區域尋找gadgets
    // 分析RET、POP、MOV、XOR指令的分布
}
```

### 5. 複雜攻擊模式檢測
```cpp
void EventHandler::detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess) {
    // 檢測JOP (Jump-Oriented Programming) 等複雜攻擊
    // 分析JMP、CALL、條件跳轉指令的模式
}
```

### 6. 可疑行為模式檢測
```cpp
void EventHandler::detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess) {
    // 檢測可疑的行為模式
    // 檢查記憶體使用是否異常
    // 分析進程行為特徵
}
```

## 使用方式

### 初始化
```cpp
// 在 DetectionEngineImpl 中
event_handler_ = std::make_unique<EventHandler>();
event_handler_->set_memory_monitor(memory_monitor_.get());
event_handler_->set_detection_engine(this);
event_handler_->start();
```

### 事件觸發
```cpp
// 在 report_attack 中
if (event_handler_) {
    Event ev;
    ev.type = Event::Type::HEAP_CORRUPTION;
    ev.process_id = target_process_id;
    ev.address = address;
    ev.meta = description + " (confidence: " + std::to_string(confidence) + ")";
    
    event_handler_->enqueue_event(ev);
    
    // 高風險攻擊立即調度深度分析
    if (confidence > 0.7) {
        event_handler_->schedule_suspicious_region(target_process_id, address);
    }
}
```

## 優勢

### 1. 模組化
- 每個檢測功能都是獨立的事件處理器
- 易於添加新的檢測類型
- 清晰的職責分離

### 2. 可擴展性
- 可以輕鬆添加新的事件類型
- 支持不同級別的檢測策略
- 靈活的調度機制

### 3. 性能優化
- 異步處理避免阻塞主線程
- 批次處理提高效率
- 智能調度減少資源消耗

### 4. 可維護性
- 代碼結構清晰
- 易於調試和測試
- 良好的錯誤處理

## 配置參數

```cpp
// 快速事件處理配置
size_t fast_batch_size_ = 128;           // 批次大小
int fast_interval_ms_ = 50;              // 處理間隔

// 延遲分析配置
size_t deferred_batch_limit_ = 200;      // 批次限制
std::chrono::seconds deferred_interval_ = std::chrono::seconds(1); // 分析間隔

// 定時調度配置
const std::chrono::seconds scan_interval_ = std::chrono::seconds(10);
const std::chrono::seconds comprehensive_interval_ = std::chrono::seconds(10);
const std::chrono::seconds status_interval_ = std::chrono::seconds(60);
const std::chrono::seconds cycle_interval_ = std::chrono::seconds(300);
```

## 未來改進方向

1. **事件優先級**: 實現事件優先級系統
2. **動態配置**: 支持運行時配置調整
3. **統計分析**: 添加詳細的性能統計
4. **插件系統**: 支持第三方檢測插件
5. **機器學習**: 集成ML模型進行智能檢測

## 總結

新的事件驅動架構成功將原本的同步檢測邏輯轉換為異步事件處理系統，提供了更好的性能、可維護性和可擴展性。所有原有的 `detection_loop` 功能都已成功遷移到事件驅動架構中，並保持了完整的功能性。
