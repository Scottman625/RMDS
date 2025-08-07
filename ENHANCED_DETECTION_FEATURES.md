# 增強檢測引擎功能文檔

## 概述

本文檔詳細說明了實時記憶體攻擊檢測引擎的新增功能，包括針對攻擊模擬器的專用過濾條件、複雜攻擊鏈檢測、可疑行為模式識別等。

## 新增功能

### 1. 攻擊模擬器專用過濾條件

#### 1.1 熵值檢測
- **功能**: 檢查記憶體區域的熵值，高熵值區域更可能是shellcode
- **實現**: 使用 `calculate_shannon_entropy()` 函數
- **閾值**: 熵值 < 3.0 的區域被認為是正常代碼，跳過掃描
- **位置**: `detection_engine.cpp:3120-3127`

#### 1.2 動態堆積區域檢測
- **功能**: 識別動態分配的堆積區域
- **實現**: `is_dynamic_heap_region()` 函數
- **特徵**: 
  - 記憶體類型為 `MEM_PRIVATE`
  - 保護屬性為 `PAGE_READWRITE` 或 `PAGE_EXECUTE_READWRITE`
- **優化**: 對動態堆積區域降低掃描頻率（5秒間隔）

#### 1.3 執行活動檢測
- **功能**: 檢測記憶體區域的執行歷史
- **實現**: `has_recent_execution_activity()` 函數
- **機制**: 
  - 使用靜態映射追蹤執行活動
  - 30秒內有執行活動的區域被標記為可疑
  - 模擬5%機率的執行活動檢測

#### 1.4 合法代碼區域檢測
- **功能**: 識別合法的代碼區域，避免誤報
- **實現**: `is_legitimate_code_region()` 函數
- **檢測邏輯**:
  - 檢查是否為系統模組區域 (`MEM_IMAGE`)
  - 檢查是否為系統DLL區域 (高地址範圍)
  - 檢查是否為已知的合法進程區域
- **優化**: 跳過合法區域的掃描，提高性能

#### 1.5 最近分配記憶體檢測
- **功能**: 識別最近分配的記憶體區域
- **實現**: `is_recently_allocated_memory()` 函數
- **機制**:
  - 使用靜態映射追蹤記憶體分配時間
  - 60秒內分配的記憶體被認為是最近的
  - 模擬10%機率的最近分配檢測
- **用途**: 優先掃描最近分配的記憶體，更可能包含攻擊代碼

### 2. 複雜攻擊鏈檢測

#### 2.1 多層攻擊模式
- **功能**: 檢測 ROP + Shellcode + 記憶體破壞的組合攻擊
- **實現**: `detect_complex_attack_patterns()` 函數
- **檢測邏輯**:
  ```cpp
  if (has_rop && has_shellcode && has_memory_corruption) {
      report_attack(AttackType::COMPLEX_ATTACK, address, description, 0.95);
  }
  ```

#### 2.2 攻擊序列追蹤
- **功能**: 追蹤進程的攻擊序列
- **存儲**: 使用靜態映射 `attack_sequences`
- **清理**: 超過5分鐘的記錄自動清理

### 3. 可疑行為模式檢測

#### 3.1 異常記憶體分配模式
- **功能**: 檢測大量連續的記憶體分配
- **實現**: `detect_suspicious_behavior_patterns()` 函數
- **檢測條件**:
  - 分配歷史 >= 10 次
  - 小於1KB間隔的分配 >= 5 次
- **報告**: 置信度 0.7 的可疑行為攻擊

#### 3.2 分配間隔分析
- **算法**: 計算連續分配之間的間隔
- **閾值**: 間隔 < 1024 字節被認為異常

### 4. 整合檢測函數

#### 4.1 全面檢測策略
- **功能**: `perform_comprehensive_attack_detection()` 函數
- **分類策略**:
  - **攻擊模擬器**: 執行所有檢測功能
  - **高風險進程**: 重點檢測 ROP 和複雜攻擊鏈
  - **用戶進程**: 基本可疑行為檢測
  - **系統進程**: 最小檢測，減少性能影響

#### 4.2 自適應檢測
- **輸出控制**: 根據進程類別調整輸出頻率
- **性能優化**: 系統進程使用較長的檢測間隔

## 新增枚舉值

### AttackType 枚舉擴展
```cpp
enum class AttackType {
    // ... 原有枚舉值 ...
    COMPLEX_ATTACK,         // 複雜攻擊鏈
    SUSPICIOUS_BEHAVIOR     // 可疑行為模式
};
```

## 性能優化

### 1. 緩存機制
- **記憶體區域緩存**: 5秒更新間隔
- **執行歷史緩存**: 靜態映射，自動清理

### 2. 輸出控制
- **調試輸出**: 使用 `controlled_log_output()` 控制頻率
- **攻擊模擬器**: 每分鐘最多3次輸出
- **系統進程**: 5分鐘間隔的調試輸出

### 3. 掃描優化
- **步長優化**: `SCAN_STEP_SIZE = 2`
- **最大掃描尺寸**: `MAX_SCAN_SIZE = 8192`
- **最小gadget數量**: `MIN_GADGET_COUNT = 3`

## 使用示例

### 編譯和運行
```bash
# 編譯增強檢測引擎
test_enhanced_detection.bat

# 運行檢測引擎
enhanced_detection_engine.exe
```

### 預期輸出
```
=== Enhanced Memory Attack Detection Engine ===
*** COMPREHENSIVE DETECTION COMPLETED: Process=1234, Category=ATTACK_SIMULATOR ***
*** EXECUTION ACTIVITY DETECTED: Base=0x7fff1234, Size=4096 ***
*** Complex Attack Chain Detected - ROP + Shellcode + Memory Corruption Pattern ***
```

## 配置參數

### 自適應閾值
```cpp
struct AdaptiveThresholds {
    // 攻擊模擬器閾值
    int simulator_rop_suspicious_patterns = 8;
    int simulator_rop_ret_count = 12;
    int simulator_consecutive_ret = 2;
    int simulator_gadget_chains = 1;
    double simulator_entropy_threshold = 2.5;
};
```

### 性能配置
```cpp
struct PerformanceConfig {
    static constexpr size_t MAX_SCAN_SIZE = 8192;
    static constexpr int MIN_TRIGGER_THRESHOLD = 3;
    static constexpr int SCAN_STEP_SIZE = 2;
    static constexpr size_t MAX_GADGET_SIZE = 16;
    static constexpr int MIN_GADGET_COUNT = 3;
};
```

## 注意事項

1. **權限要求**: 需要調試權限 (`SeDebugPrivilege`)
2. **性能影響**: 對系統進程使用最小檢測以減少影響
3. **誤報控制**: 使用多層過濾條件減少誤報
4. **記憶體使用**: 緩存機制會佔用少量記憶體

## 未來改進

1. **機器學習**: 整合ML模型進行更精確的攻擊檢測
2. **實時學習**: 根據檢測結果動態調整閾值
3. **雲端協作**: 多台機器共享攻擊模式
4. **API鉤子**: 檢測API調用模式的異常
