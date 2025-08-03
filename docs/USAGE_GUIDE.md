# Real-Time Memory Attack Detection Engine - 使用指南

## 概述

Real-Time Memory Attack Detection Engine 是一個高性能的記憶體攻擊檢測引擎，專為實時檢測 ROP/JOP 攻擊而設計。本引擎使用 C++23 標準，支援硬件記憶體標籤（MTE）擴展和 LLVM 插樁技術。

## 核心特性

- **超低延遲**：檢測延遲 < 3μs（相比傳統方案 20μs+）
- **硬件支援**：支援 ARM MTE 硬件記憶體標籤
- **LLVM 插樁**：動態代碼插樁進行堆棧指針追蹤
- **模式匹配**：ROP/JOP 攻擊模式匹配模板庫
- **DDR5 ECC**：支援 DDR5 記憶體的 ECC 糾錯協同檢測

## 使用情境

### 1. 遊戲反外掛模組

**適用場景**：Unity/Unreal 引擎整合

```cpp
// 配置引擎 - 針對遊戲反外掛優化
EngineConfig config;
config.enable_mte = true;
config.enable_llvm_instrumentation = true;
config.enable_pattern_matching = true;
config.detection_threshold = 70;  // 較低的閾值，更敏感
config.max_latency_us = 5;        // 允許稍高的延遲
config.detection_interval_ms = 50; // 更頻繁的檢測

// 創建引擎
auto anticheat_engine = std::make_unique<MemoryDetectionEngine>(config);
anticheat_engine->start();

// 在遊戲主循環中監控
while (game_running) {
    // 正常遊戲邏輯
    update_game_state();
    
    // 獲取檢測統計
    auto stats = anticheat_engine->get_stats();
    if (stats.total_detections > 0) {
        handle_cheat_detection();
    }
}
```

**優勢**：
- 實時檢測記憶體修改嘗試
- 低性能影響（< 1ms per frame）
- 支援多種攻擊模式檢測

### 2. 金融交易系統保護

**適用場景**：高頻交易系統記憶體保護

```cpp
// 配置引擎 - 針對金融系統的高安全性要求
EngineConfig config;
config.enable_mte = true;
config.enable_llvm_instrumentation = true;
config.enable_pattern_matching = true;
config.detection_threshold = 90;  // 高閾值，減少誤報
config.max_latency_us = 1;        // 極低延遲要求
config.detection_interval_ms = 10; // 極高頻率檢測

// 創建引擎
auto trading_protection = std::make_unique<MemoryDetectionEngine>(config);
trading_protection->start();

// 在交易執行前檢查
void execute_trade(const Trade& trade) {
    auto stats = trading_protection->get_stats();
    if (stats.total_detections > 0) {
        // 檢測到攻擊，中止交易
        abort_transaction();
        return;
    }
    
    // 執行正常交易邏輯
    process_trade(trade);
}
```

**優勢**：
- 極低延遲（< 1μs）
- 高精度檢測
- 符合監管要求

### 3. 企業安全系統

**適用場景**：企業級應用程式保護

```cpp
// 配置引擎 - 平衡性能和安全性
EngineConfig config;
config.enable_mte = true;
config.enable_llvm_instrumentation = true;
config.enable_pattern_matching = true;
config.enable_performance_monitoring = true;
config.detection_threshold = 80;
config.max_latency_us = 3;
config.detection_interval_ms = 100;

// 創建引擎
auto security_engine = std::make_unique<MemoryDetectionEngine>(config);
security_engine->start();

// 監控應用程式
while (application_running) {
    auto stats = security_engine->get_stats();
    
    // 記錄安全事件
    if (stats.total_detections > 0) {
        log_security_event(stats);
        notify_security_team();
    }
    
    // 定期報告
    if (should_generate_report()) {
        generate_security_report(stats);
    }
}
```

## 配置選項

### EngineConfig 結構

```cpp
struct EngineConfig {
    bool enable_mte = true;                    // 啟用 MTE 硬件支援
    bool enable_llvm_instrumentation = true;   // 啟用 LLVM 插樁
    bool enable_pattern_matching = true;       // 啟用模式匹配
    bool enable_performance_monitoring = true; // 啟用性能監控
    uint32_t detection_threshold = 80;         // 檢測閾值 (0-100)
    uint32_t max_latency_us = 3;              // 最大延遲 (微秒)
    uint32_t detection_interval_ms = 100;      // 檢測間隔 (毫秒)
    std::string log_level = "INFO";           // 日誌級別
};
```

### 性能調優建議

| 使用場景 | 檢測閾值 | 最大延遲 | 檢測間隔 | 說明 |
|---------|---------|---------|---------|------|
| 遊戲反外掛 | 70 | 5μs | 50ms | 平衡敏感度和性能 |
| 金融交易 | 90 | 1μs | 10ms | 極低延遲，高精度 |
| 企業安全 | 80 | 3μs | 100ms | 平衡性能和安全性 |
| 開發測試 | 60 | 10μs | 200ms | 高敏感度，寬鬆性能 |

## 統計數據

### EngineStats 結構

```cpp
struct EngineStats {
    uint64_t total_detections;        // 總檢測次數
    uint64_t total_false_positives;   // 誤報次數
    uint64_t average_detection_time_us; // 平均檢測時間 (微秒)
    uint64_t uptime_seconds;          // 運行時間 (秒)
};
```

### 性能指標

- **檢測延遲**：目標 < 3μs
- **誤報率**：目標 < 1%
- **記憶體使用**：< 10MB
- **CPU 使用率**：< 5%

## 編譯和安裝

### 系統要求

- **編譯器**：支援 C++23 的編譯器（MSVC 2022, GCC 12+, Clang 15+）
- **LLVM**：可選，用於代碼插樁功能
- **CMake**：3.20 或更高版本

### 編譯步驟

```bash
# 1. 克隆專案
git clone <repository-url>
cd RealTimeMemoryAttackDetectEngine

# 2. 配置 CMake
cmake -B build -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake

# 3. 編譯
cmake --build build --config Release

# 4. 運行範例
./build/examples/Release/simple_example.exe
```

### 依賴項

- **Google Test**：用於單元測試（通過 vcpkg 安裝）
- **LLVM**：可選，用於代碼插樁功能

## 故障排除

### 常見問題

1. **LLVM 未找到**
   ```
   CMake Warning: LLVM not found, some features will be disabled
   ```
   **解決方案**：安裝 LLVM 或禁用 LLVM 相關功能

2. **Google Test 未找到**
   ```
   CMake Error: Could not find a package configuration file provided by "GTest"
   ```
   **解決方案**：使用 vcpkg 安裝 Google Test

3. **編譯錯誤**
   ```
   error C2872: 'MemoryDetectionEngine': 模稜兩可的符號
   ```
   **解決方案**：使用完整的命名空間路徑

### 性能調優

1. **降低延遲**：減少檢測間隔，禁用不必要的功能
2. **提高精度**：增加檢測閾值，啟用更多檢測模式
3. **減少誤報**：調整閾值，優化模式匹配規則

## 授權

本專案採用 MIT 授權條款。詳見 [LICENSE](LICENSE) 文件。

## 支援

如有問題或建議，請提交 Issue 或 Pull Request。 