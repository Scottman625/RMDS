# 實時內存攻擊檢測引擎 API 參考

## 概述

實時內存攻擊檢測引擎是一個基於C++23的高性能內存安全檢測系統，專為檢測和防護ROP/JOP攻擊而設計。

## 核心組件

### MemoryDetectionEngine

主要的檢測引擎類，負責協調各個組件進行實時攻擊檢測。

#### 構造函數

```cpp
MemoryDetectionEngine(const EngineConfig& config = EngineConfig{});
```

#### 主要方法

##### 初始化和控制

- `bool initialize()` - 初始化引擎
- `bool start()` - 啟動檢測
- `void stop()` - 停止檢測
- `bool is_running() const` - 檢查運行狀態

##### 配置和回調

- `void register_detection_callback(std::function<void(const DetectionResult&)> callback)` - 註冊檢測回調
- `void update_config(const EngineConfig& config)` - 更新配置
- `void set_attack_type_enabled(AttackType type, bool enabled)` - 啟用/禁用攻擊類型

##### 模式管理

- `void add_custom_pattern(const std::vector<uint8_t>& pattern, AttackType type)` - 添加自定義模式

##### 統計和監控

- `PerformanceStats get_performance_stats() const` - 獲取性能統計
- `static std::string get_version()` - 獲取版本信息

### MTEManager

硬件內存標籤擴展管理器，負責MTE相關功能。

#### 主要方法

- `bool initialize()` - 初始化MTE管理器
- `static bool is_supported()` - 檢查系統支援
- `std::pair<void*, uint32_t> allocate_tagged_memory(size_t size, MTETagType type)` - 分配帶標籤內存
- `void deallocate_tagged_memory(void* ptr, uint32_t tag)` - 釋放帶標籤內存
- `bool validate_tag(void* ptr, uint32_t expected_tag)` - 驗證內存標籤

### LLVMInstrumentation

LLVM插樁工具，負責動態插樁和堆棧指針追蹤。

#### 主要方法

- `bool initialize()` - 初始化插樁管理器
- `static bool is_available()` - 檢查LLVM可用性
- `bool instrument_module(std::unique_ptr<llvm::Module> module)` - 插樁模組
- `void register_event_callback(std::function<void(const TrackingEvent&)> callback)` - 註冊事件回調

### PatternMatcher

攻擊模式匹配器，負責ROP/JOP攻擊模式檢測。

#### 主要方法

- `bool initialize()` - 初始化模式匹配器
- `bool load_pattern_library(const std::string& library_path)` - 加載模式庫
- `std::vector<MatchResult> scan_memory(const uint8_t* data, size_t size, uint64_t base_address)` - 掃描內存
- `bool start_realtime_scanning(std::function<void(const MatchResult&)> callback)` - 啟動實時掃描

## 數據結構

### EngineConfig

引擎配置結構：

```cpp
struct EngineConfig {
    bool enable_mte = true;
    bool enable_llvm_instrumentation = true;
    bool enable_pattern_matching = true;
    bool enable_performance_monitoring = true;
    uint32_t detection_threshold = 80;
    uint32_t max_latency_us = 3;
    std::string log_level = "INFO";
};
```

### DetectionResult

檢測結果結構：

```cpp
struct DetectionResult {
    AttackType type;
    uint64_t timestamp;
    uint64_t address;
    std::string description;
    double confidence;
    bool is_false_positive;
};
```

### PerformanceStats

性能統計結構：

```cpp
struct PerformanceStats {
    uint64_t total_detections;
    uint64_t false_positives;
    double average_latency_us;
    double max_latency_us;
    double min_latency_us;
    uint64_t memory_usage_bytes;
};
```

## 枚舉類型

### AttackType

攻擊類型枚舉：

```cpp
enum class AttackType {
    ROP,        // Return-Oriented Programming
    JOP,        // Jump-Oriented Programming
    CALLOP,     // Call-Oriented Programming
    STACK_PIVOT, // Stack Pivot Attack
    UNKNOWN     // 未知攻擊類型
};
```

### PatternType

模式類型枚舉：

```cpp
enum class PatternType {
    ROP_GADGET,      // ROP小工具
    JOP_GADGET,      // JOP小工具
    CALLOP_GADGET,   // CALLOP小工具
    STACK_PIVOT,     // 堆棧轉向
    RET2LIBC,        // Ret2libc攻擊
    SHELLCODE,       // Shellcode
    CUSTOM           // 自定義模式
};
```

## 使用範例

### 基本使用

```cpp
#include "memory_detection_engine.hpp"

int main() {
    // 配置引擎
    EngineConfig config;
    config.enable_mte = true;
    config.enable_pattern_matching = true;
    config.max_latency_us = 3;

    // 創建引擎
    auto engine = create_engine(config);

    // 註冊檢測回調
    engine->register_detection_callback([](const DetectionResult& result) {
        std::cout << "檢測到攻擊: " << result.description << std::endl;
    });

    // 初始化和啟動
    if (engine->initialize() && engine->start()) {
        // 引擎運行中...
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        // 停止引擎
        engine->stop();
    }

    return 0;
}
```

### 添加自定義模式

```cpp
// 添加ROP攻擊模式
std::vector<uint8_t> rop_pattern = {0xC3, 0x90, 0x90, 0x90}; // ret + nop
engine->add_custom_pattern(rop_pattern, AttackType::ROP);

// 添加JOP攻擊模式
std::vector<uint8_t> jop_pattern = {0xFF, 0xE0, 0x90, 0x90}; // jmp eax + nop
engine->add_custom_pattern(jop_pattern, AttackType::JOP);
```

### 性能監控

```cpp
// 獲取性能統計
auto stats = engine->get_performance_stats();
std::cout << "總檢測數: " << stats.total_detections << std::endl;
std::cout << "平均延遲: " << stats.average_latency_us << " μs" << std::endl;
std::cout << "記憶體使用: " << stats.memory_usage_bytes << " bytes" << std::endl;
```

## 錯誤處理

引擎使用異常安全設計，所有方法都提供適當的錯誤處理：

- 初始化失敗時返回 `false`
- 配置錯誤時拋出 `std::invalid_argument`
- 內存分配失敗時拋出 `std::bad_alloc`
- 線程相關錯誤時拋出 `std::runtime_error`

## 性能考慮

- 檢測延遲目標：<3μs
- 記憶體使用：最小化開銷
- 線程安全：所有公共方法都是線程安全的
- 異常安全：強異常安全保證

## 平台支援

- Windows (x64)
- Linux (x64, ARM64)
- macOS (x64, ARM64)

## 編譯要求

- C++23 編譯器
- LLVM 16+
- CMake 3.20+
- 支援MTE的ARM64硬體（可選） 