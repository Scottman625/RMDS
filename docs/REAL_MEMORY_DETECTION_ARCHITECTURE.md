# 真正的記憶體攻擊檢測引擎架構

## 概述

這個專案實現了一個真正的記憶體攻擊檢測引擎，使用底層 Windows API 來實現真實的記憶體監控和攻擊檢測，而不是模擬系統。

## 核心特性

### 1. 底層系統 API 整合
- **Virtual Memory API**: 使用 `VirtualQuery`, `VirtualAlloc`, `VirtualProtect` 等 API 進行記憶體監控
- **Process API**: 使用 `CreateToolhelp32Snapshot`, `Process32First/Next` 進行進程監控
- **Exception Handling**: 使用 VEH (Vectored Exception Handler) 捕獲記憶體異常
- **Memory Protection**: 啟用 DEP (Data Execution Prevention) 和 ASLR

### 2. 真實攻擊檢測
- **ROP/JOP 檢測**: 分析執行流程和堆疊內容
- **緩衝區溢出檢測**: 監控堆疊邊界和頁面保護違規
- **堆積破壞檢測**: 使用 `HeapValidate` 檢查堆積完整性
- **Shellcode 注入檢測**: 掃描可執行記憶體區域的可疑代碼
- **API Hook 檢測**: 檢查關鍵系統函數是否被修改

### 3. 模組化架構

```
include/
├── real_memory_detection_types.hpp      # 類型定義
├── real_memory_detection_utils.hpp      # 工具函數
├── real_memory_detection_veh.hpp        # VEH 異常處理
├── real_memory_detection_monitor.hpp    # 記憶體和進程監控
└── real_memory_detection_engine.hpp     # 主引擎

src/
├── real_memory_detection_utils.cpp      # 工具函數實現
└── real_memory_detection_engine_simple.cpp  # 簡化引擎實現

examples/
├── real_detection_engine.cpp            # 原始單檔案實現
├── real_detection_engine_modular.cpp    # 模組化實現
└── test_real_memory_detection.cpp       # 測試檔案
```

## 核心組件

### 1. 類型定義 (`real_memory_detection_types.hpp`)
```cpp
enum class AttackType {
    ROP_CHAIN,              // Return-Oriented Programming 鏈
    JOP_CHAIN,              // Jump-Oriented Programming 鏈
    BUFFER_OVERFLOW,        // 緩衝區溢出
    HEAP_CORRUPTION,        // 堆積破壞
    STACK_OVERFLOW,         // 堆疊溢出
    USE_AFTER_FREE,         // 釋放後使用
    DOUBLE_FREE,            // 重複釋放
    SHELLCODE_INJECTION,    // Shellcode 注入
    API_HOOK,               // API Hook
    MEMORY_CORRUPTION       // 記憶體破壞
};
```

### 2. 工具函數 (`real_memory_detection_utils.hpp`)
- 記憶體地址驗證
- 進程名稱獲取
- 時間戳格式化
- ROP/JOP gadget 檢測
- Shellcode 特徵識別
- API Hook 檢測

### 3. VEH 異常處理 (`real_memory_detection_veh.hpp`)
```cpp
class VEHHandler {
    // 處理存取違規
    void handle_access_violation(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 處理堆疊溢出
    void handle_stack_overflow(PCONTEXT ctx);
    
    // 處理頁面保護違規
    void handle_guard_page_violation(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 分析執行流程
    bool analyze_execution_flow(PCONTEXT ctx);
};
```

### 4. 記憶體監控 (`real_memory_detection_monitor.hpp`)
```cpp
class MemoryMonitor {
    // 掃描記憶體區域
    void scan_memory_regions();
    
    // 檢查可執行區域完整性
    void check_executable_integrity(LPVOID base, SIZE_T size);
    
    // 檢查堆積完整性
    void check_heap_integrity();
    
    // 檢查堆疊完整性
    void check_stack_integrity();
};
```

### 5. 進程監控 (`real_memory_detection_monitor.hpp`)
```cpp
class ProcessMonitor {
    // 掃描進程
    void scan_processes();
    
    // 檢查 API Hook
    void check_api_hooks();
    
    // 檢查系統完整性
    void check_system_integrity();
};
```

## 使用方式

### 1. 基本使用
```cpp
#include "real_memory_detection_engine.hpp"

using namespace RealMemoryDetection;

int main() {
    // 配置引擎
    EngineConfig config;
    config.enable_veh_handler = true;
    config.enable_dep = true;
    config.enable_memory_monitoring = true;
    config.enable_process_monitoring = true;
    config.enable_api_hook_detection = true;
    
    // 創建引擎
    auto engine = create_engine(config);
    
    // 設置攻擊檢測回調
    engine->set_attack_callback([](const DetectionResult& result) {
        std::cout << "Attack detected: " << DetectionUtils::attack_type_to_string(result.type) << std::endl;
    });
    
    // 啟動引擎
    engine->start();
    
    // 主迴圈
    while (engine->is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}
```

### 2. 模組化使用
```cpp
#include "real_memory_detection_engine.hpp"

class ModularRealMemoryDetectionEngine {
private:
    std::unique_ptr<RealMemoryDetectionEngine> engine_;
    
public:
    ModularRealMemoryDetectionEngine() {
        EngineConfig config;
        // 配置引擎...
        
        engine_ = create_engine(config);
        engine_->set_attack_callback([this](const DetectionResult& result) {
            handle_attack_detection(result);
        });
    }
    
    bool start() {
        return engine_->start();
    }
    
    void stop() {
        engine_->stop();
    }
};
```

## 檢測機制

### 1. ROP/JOP 攻擊檢測
- 分析堆疊上的返回地址
- 檢查是否指向 ret/jmp 指令
- 分析執行流程中的可疑模式

### 2. 緩衝區溢出檢測
- 監控堆疊邊界
- 檢測頁面保護違規
- 分析記憶體存取模式

### 3. 堆積破壞檢測
- 使用 `HeapValidate` 檢查堆積完整性
- 監控堆積分配和釋放
- 檢測 Use-After-Free 和 Double-Free

### 4. Shellcode 注入檢測
- 掃描可執行記憶體區域
- 檢測 NOP sled 和常見 shellcode 特徵
- 分析代碼注入模式

### 5. API Hook 檢測
- 檢查關鍵系統函數的完整性
- 檢測函數開頭的 jmp 指令
- 驗證函數序言

## 性能考量

### 1. 記憶體掃描優化
- 只掃描可執行和私有記憶體區域
- 使用頁面粒度掃描
- 實現增量掃描

### 2. 異常處理優化
- VEH 處理器只處理關鍵異常
- 快速路徑處理常見異常
- 避免過度捕獲

### 3. 進程監控優化
- 只監控關鍵進程
- 實現進程過濾
- 減少系統開銷

## 安全考量

### 1. 權限要求
- 需要管理員權限進行系統級監控
- 需要調試權限進行進程監控
- 需要記憶體讀取權限

### 2. 誤報處理
- 實現白名單機制
- 使用多層檢測減少誤報
- 提供誤報反饋機制

### 3. 性能影響
- 監控開銷控制在可接受範圍
- 避免影響正常應用程序運行
- 實現可配置的監控強度

## 未來改進

### 1. 機器學習整合
- 使用 ML 模型識別攻擊模式
- 實現行為分析
- 動態調整檢測閾值

### 2. 雲端整合
- 上傳攻擊數據到雲端分析
- 實現威脅情報共享
- 提供遠程監控能力

### 3. 更多平台支援
- 支援 Linux 系統
- 支援 macOS 系統
- 實現跨平台統一 API

## 結論

這個真正的記憶體攻擊檢測引擎提供了：

1. **真實的底層監控**: 使用 Windows API 實現真正的記憶體監控
2. **模組化架構**: 便於維護和擴展
3. **多種攻擊檢測**: 支援 ROP、JOP、緩衝區溢出等多種攻擊
4. **高效能設計**: 優化的掃描和檢測機制
5. **易於使用**: 提供簡潔的 API 介面

這個架構為真正的記憶體攻擊檢測提供了堅實的基礎，可以根據實際需求進行進一步的擴展和優化。 