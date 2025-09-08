# EventUtils 架構文檔

## 概述

`EventUtils` 是一個專門的事件工具函數類別，用於存放所有與事件處理相關的輔助函數。這個架構的設計目的是將原本分散在 `EventHandler` 中的工具函數進行模組化，提高代碼的可維護性和重用性。

## 架構設計

### 1. 文件結構

```
include/
├── event_utils.hpp          # 事件工具函數頭文件
└── event_handler.hpp        # 事件處理器頭文件（已更新）

src/
├── event_utils.cpp          # 事件工具函數實現
└── event_handler.cpp        # 事件處理器實現（已更新）
```

### 2. 類別設計

#### EventUtils 類別

`EventUtils` 是一個靜態工具類別，提供以下功能分類：

##### 2.1 字串寫入操作檢測
- `detect_string_write_operations()`: 檢測常見的shell字串寫入模式

##### 2.2 系統調用ROP鏈檢測
- `detect_syscall_rop_chains()`: 檢測系統調用相關的ROP鏈
- `report_syscall_rop_detection()`: 報告系統調用ROP檢測結果

##### 2.3 分析功能
- `analyze_gadget_distribution()`: 分析gadget分佈模式

##### 2.4 記憶體區域分析
- `is_legitimate_code_region()`: 檢查是否為合法的代碼區域
- `is_recently_allocated_memory()`: 檢查是否為最近分配的記憶體
- `is_dynamic_heap_region()`: 檢查是否為動態分配的堆積區域
- `has_recent_execution_activity()`: 檢查記憶體區域是否有最近的執行活動
- `is_near_executable_region()`: 檢查是否在可執行區域附近

##### 2.5 地址格式化
- `format_address()`: 格式化地址為十六進制字串

##### 2.6 熵值計算
- `calculate_shannon_entropy()`: 計算香農熵值

##### 2.7 指令分析
- `analyze_instruction_pattern()`: 分析指令模式
- `is_valid_instruction_sequence()`: 檢查是否為有效的指令序列

##### 2.8 攻擊模式檢測
- `detect_rop_pattern()`: 檢測ROP模式
- `detect_jop_pattern()`: 檢測JOP模式
- `detect_shellcode_pattern()`: 檢測shellcode模式

##### 2.9 記憶體保護檢查
- `is_executable_region()`: 檢查是否為可執行區域
- `is_writable_region()`: 檢查是否為可寫區域
- `is_readable_region()`: 檢查是否為可讀區域

##### 2.10 進程分析
- `get_process_name_safe()`: 安全獲取進程名稱
- `is_system_process()`: 檢查是否為系統進程
- `is_high_risk_process()`: 檢查是否為高風險進程

##### 2.11 時間相關工具
- `format_timestamp()`: 格式化時間戳
- `get_current_timestamp_ms()`: 獲取當前時間戳

##### 2.12 統計和分析
- `update_detection_statistics()`: 更新檢測統計
- `get_detection_statistics()`: 獲取檢測統計

##### 2.13 日誌和調試
- `log_detection_event()`: 記錄檢測事件

##### 2.14 配置管理
- `set_detection_threshold()`: 設置檢測閾值
- `get_detection_threshold()`: 獲取檢測閾值

## 使用方式

### 1. 在 EventHandler 中使用

```cpp
#include "event_utils.hpp"

// 在 EventHandler 的方法中使用
void EventHandler::detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
    // 使用 EventUtils 進行字串寫入檢測
    EventUtils::detect_string_write_operations(process_id, hProcess);
    
    // 使用 EventUtils 進行熵值計算
    double entropy = EventUtils::calculate_shannon_entropy(buffer.data(), buffer.size());
    
    // 使用 EventUtils 進行地址格式化
    std::string addr_str = EventUtils::format_address(address);
    
    // 使用 EventUtils 進行系統調用ROP檢測
    EventUtils::detect_syscall_rop_chains(buffer, base_address, syscall_chains);
}
```

### 2. 在其他地方使用

```cpp
#include "event_utils.hpp"

// 在任何需要的地方使用 EventUtils
bool is_suspicious = EventUtils::is_high_risk_process(process_name);
double threshold = EventUtils::get_detection_threshold("rop_detection");
EventUtils::log_detection_event("CUSTOM", process_id, address, description);
```

## 優勢

### 1. 模組化
- 將工具函數從 `EventHandler` 中分離出來
- 提高代碼的模組化程度
- 便於單獨測試和維護

### 2. 重用性
- 靜態方法可以在任何地方使用
- 避免代碼重複
- 統一的工具函數接口

### 3. 可維護性
- 集中管理所有工具函數
- 便於添加新功能
- 便於修改現有功能

### 4. 性能優化
- 靜態方法避免對象創建開銷
- 統一的緩存和統計管理
- 線程安全的實現

## 配置和統計

### 1. 檢測閾值配置

```cpp
// 設置檢測閾值
EventUtils::set_detection_threshold("rop_detection", 0.7);
EventUtils::set_detection_threshold("shellcode_detection", 0.8);

// 獲取檢測閾值
double rop_threshold = EventUtils::get_detection_threshold("rop_detection");
```

### 2. 檢測統計

```cpp
// 更新統計
EventUtils::update_detection_statistics("ROP_DETECTED", 0.8);

// 獲取統計
auto stats = EventUtils::get_detection_statistics();
for (const auto& [type, count] : stats) {
    std::cout << type << ": " << count << std::endl;
}
```

## 線程安全

`EventUtils` 中的靜態成員變數使用互斥鎖保護，確保在多線程環境下的安全性：

- `stats_mutex_`: 保護檢測統計數據
- `threshold_mutex_`: 保護檢測閾值配置

## 未來擴展

### 1. 新增檢測模式
- 可以輕鬆添加新的攻擊模式檢測函數
- 支持自定義檢測邏輯

### 2. 配置系統
- 可以擴展為支持從文件讀取配置
- 支持動態配置更新

### 3. 插件系統
- 可以設計為支持插件式的檢測模組
- 便於第三方擴展

## 總結

`EventUtils` 架構的引入大大提高了代碼的組織性和可維護性。通過將工具函數模組化，我們實現了：

1. **更好的代碼組織**: 相關功能集中在一個類別中
2. **更高的重用性**: 靜態方法可以在任何地方使用
3. **更強的擴展性**: 便於添加新功能和修改現有功能
4. **更好的測試性**: 工具函數可以單獨測試
5. **更安全的線程處理**: 統一的線程安全機制

這個架構為未來的功能擴展奠定了良好的基礎。
