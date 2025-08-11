# RMDS 專案架構與技術特點 - Notion 筆記

## 📁 第一層級：專案目錄架構與技術特點

### 🏗️ 專案整體架構
```
RMDS/
├── 📁 include/                    # 核心頭檔案
├── 📁 src/                       # 源碼實現
├── 📁 docs/                      # 技術文檔
├── 📁 build/                     # 建置輸出
├── 📄 CMakeLists.txt            # 建置配置
├── 📄 RealTimeMemoryAttackDetectEngine.sln  # Visual Studio 解決方案
└── 📄 README.md                 # 專案說明
```

### 🔧 核心技術特點
1. **C++23 現代化開發**
2. **Windows API 底層整合**
3. **模組化架構設計**
4. **多線程安全機制**
5. **實時記憶體攻擊檢測**
6. **攻擊模擬器整合**
7. **分級日誌系統**
8. **性能監控與優化**

---

## 📋 第二層級：技術特點詳細說明

### 1. C++23 現代化開發

#### 1.1 語言標準與特性
- **C++23 標準支援**：使用最新的 C++ 語言特性
- **智能指針管理**：`std::unique_ptr`, `std::shared_ptr` 自動記憶體管理
- **RAII 資源管理**：自動資源獲取與釋放
- **模板元編程**：泛型程式設計提升代碼重用性
- **Lambda 表達式**：函數式程式設計風格

#### 1.2 編譯器配置
```cmake
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
```
- **MSVC 2022 支援**：Windows 平台優化編譯
- **警告等級設定**：`/W4` 嚴格警告檢查
- **UTF-8 編碼支援**：國際化字符處理

### 2. Windows API 底層整合

#### 2.1 核心 API 使用
- **Virtual Memory API**：
  - `VirtualQuery`：查詢記憶體區域資訊
  - `VirtualAlloc`：分配虛擬記憶體
  - `VirtualProtect`：修改記憶體保護屬性
- **Process API**：
  - `CreateToolhelp32Snapshot`：創建進程快照
  - `Process32First/Next`：枚舉系統進程
- **Exception Handling**：
  - VEH (Vectored Exception Handler)：向量化異常處理
  - SEH (Structured Exception Handling)：結構化異常處理

#### 2.2 系統安全機制
- **DEP (Data Execution Prevention)**：數據執行保護
- **ASLR (Address Space Layout Randomization)**：地址空間佈局隨機化
- **Memory Protection**：記憶體保護機制

### 3. 模組化架構設計

#### 3.1 核心模組結構
```
include/
├── real_memory_detection_engine.hpp    # 主引擎介面
├── real_memory_detection_types.hpp     # 類型定義
├── real_memory_detection_utils.hpp     # 工具函數
├── real_memory_detection_veh.hpp       # 異常處理
├── real_memory_detection_monitor.hpp   # 監控模組
└── utils/
    ├── logger.hpp                      # 日誌系統
    └── performance_monitor.hpp         # 性能監控
```

#### 3.2 模組職責分離
- **引擎核心**：協調各模組運作
- **類型系統**：統一的數據結構定義
- **工具模組**：通用功能函數
- **異常處理**：系統異常捕獲與處理
- **監控模組**：記憶體與進程監控
- **日誌系統**：分級日誌記錄
- **性能監控**：系統性能統計

### 4. 多線程安全機制

#### 4.1 線程安全設計
- **原子操作**：`std::atomic<bool>` 無鎖同步
- **互斥鎖**：`std::mutex` 保護共享資源
- **條件變數**：`std::condition_variable` 線程同步
- **線程池**：管理多個檢測線程

#### 4.2 並發控制
```cpp
std::atomic<bool> running_;
std::mutex results_mutex_;
std::thread detection_thread_;
```

### 5. 實時記憶體攻擊檢測

#### 5.1 支援的攻擊類型
```cpp
enum class AttackType {
    ROP_CHAIN,              // Return-Oriented Programming
    JOP_CHAIN,              // Jump-Oriented Programming
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

#### 5.2 檢測機制
- **模式識別**：識別已知攻擊模式
- **行為分析**：分析異常行為模式
- **記憶體掃描**：深度掃描記憶體區域
- **進程監控**：實時監控進程活動

### 6. 攻擊模擬器整合

#### 6.1 模擬器功能
- **多種攻擊模擬**：ROP、JOP、緩衝區溢出等
- **記憶體注入**：模擬惡意代碼注入
- **攻擊驗證**：驗證攻擊是否成功
- **統計分析**：攻擊成功率統計

#### 6.2 整合機制
- **進程識別**：自動識別模擬器進程
- **優先掃描**：高優先級掃描模擬器
- **實時監控**：持續監控模擬器活動

### 7. 分級日誌系統

#### 7.1 日誌等級
```cpp
enum class LogLevel {
    DEBUG,      // 調試信息
    INFO,       // 一般信息
    ALERT,      // 警告信息
    CRITICAL    // 嚴重警告
};
```

#### 7.2 日誌功能
- **分級輸出**：不同等級不同處理方式
- **文件記錄**：持久化日誌存儲
- **控制台輸出**：實時日誌顯示
- **性能統計**：系統性能數據記錄

### 8. 性能監控與優化

#### 8.1 性能指標
- **檢測延遲**：<10μs 實時響應
- **記憶體使用**：優化掃描策略
- **CPU 使用率**：控制掃描頻率
- **系統影響**：最小化對系統影響

#### 8.2 優化策略
- **智能掃描**：只掃描高風險進程
- **頻率控制**：動態調整掃描頻率
- **範圍限制**：限制掃描範圍大小
- **緩存機制**：緩存掃描結果

### 9. 建置系統

#### 9.1 CMake 配置
- **跨平台支援**：Windows/Linux 建置
- **依賴管理**：自動處理依賴關係
- **編譯選項**：優化編譯設定
- **安裝規則**：自動安裝配置

#### 9.2 目標配置
```cmake
# 靜態庫
add_library(real_memory_detection_engine STATIC ...)

# 可執行檔
add_executable(real_detection_engine ...)
add_executable(attack_simulator ...)
add_executable(memory_monitor ...)
```

### 10. 開發工具整合

#### 10.1 Visual Studio 支援
- **解決方案文件**：`.sln` 專案管理
- **專案配置**：`.vcxproj` 詳細設定
- **調試支援**：完整的調試功能
- **IntelliSense**：智能代碼提示

#### 10.2 開發工作流程
- **版本控制**：Git 整合
- **持續整合**：自動化建置
- **代碼品質**：靜態分析工具
- **文檔生成**：自動文檔生成

---

## 📊 專案優勢總結

### 🎯 技術優勢
1. **底層整合**：直接使用 Windows API，無中間層
2. **高性能**：C++23 優化，毫秒級響應
3. **模組化**：易於維護和擴展
4. **線程安全**：多線程並發安全
5. **實時檢測**：真正的實時攻擊檢測

### 🛡️ 安全優勢
1. **多層防護**：多種攻擊類型檢測
2. **誤報控制**：智能白名單機制
3. **性能平衡**：安全與性能最佳平衡
4. **可配置性**：靈活的配置選項

### 🔧 開發優勢
1. **現代化**：使用最新 C++ 標準
2. **跨平台**：CMake 建置系統
3. **文檔完整**：詳細的技術文檔
4. **開源友好**：MIT 授權

---

## 📝 使用建議

### 🚀 快速開始
1. 安裝 Visual Studio 2022
2. 克隆專案代碼
3. 使用 CMake 建置
4. 運行檢測引擎

### 🔍 開發建議
1. 熟悉 Windows API
2. 了解 C++23 特性
3. 掌握多線程程式設計
4. 學習記憶體安全概念

### 📈 擴展方向
1. 支援更多攻擊類型
2. 整合機器學習
3. 雲端威脅情報
4. 跨平台支援
