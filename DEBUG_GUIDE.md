# Real Memory Detection Engine - 調試指南

## 概述
本指南提供完整的崩潰調試解決方案，包括崩潰捕獲、符號解析、dump 分析和調試工具。

## 快速開始

### 1. 設置符號路徑
```bash
# 運行符號設置腳本
setup_symbols.bat
```

### 2. 編譯帶調試符號的版本
```bash
# Debug 版本（推薦用於調試）
cmake --build build --config Debug

# Release 版本（帶調試符號）
cmake --build build --config Release
```

### 3. 測試崩潰處理器
```bash
# 運行崩潰測試程式
build\src\crash_test.exe
```

## 崩潰捕獲方法

### 方法 1: 內建崩潰處理器（推薦）
程式已內建 `CrashHandler`，會自動：
- 捕獲所有異常
- 生成詳細的調用棧
- 創建 MiniDump 文件
- 顯示錯誤對話框

### 方法 2: 使用 Procdump
```bash
# 下載 Procdump
# https://docs.microsoft.com/en-us/sysinternals/downloads/procdump

# 運行監控
monitor_with_procdump.bat
```

### 方法 3: 手動生成 Dump
```cpp
// 在程式碼中手動生成 dump
RealMemoryDetection::GenerateCrashDump("manual.dmp");
```

## Dump 分析

### 使用 WinDbg 分析
```bash
# 分析特定的 dump 文件
analyze_dump.bat dumps\crash_20231201_143022.dmp
```

### 手動分析步驟
1. 打開 WinDbg
2. 載入 dump 文件：`File -> Open Crash Dump`
3. 執行分析：`!analyze -v`
4. 查看調用棧：`k`
5. 查看詳細調用棧：`kL`

### 常用 WinDbg 命令
```
!analyze -v          # 自動分析崩潰原因
k                    # 顯示調用棧
kL                   # 顯示詳細調用棧
!peb                 # 顯示進程環境塊
!teb                 # 顯示線程環境塊
lm                   # 列出載入的模組
!sym noisy           # 啟用符號載入詳細信息
```

## 常見問題解決

### 1. 權限問題
```bash
# 以管理員權限運行
run_as_admin.bat
# 或
run_as_admin.ps1
```

### 2. 符號載入失敗
```bash
# 檢查符號路徑
echo %_NT_SYMBOL_PATH%

# 重新設置符號路徑
setup_symbols.bat
```

### 3. Dump 文件過大
修改 `crash_handler.cpp` 中的 dump 選項：
```cpp
// 減少 dump 大小
MiniDumpNormal | MiniDumpWithThreadInfo  // 基本信息
// 或
MiniDumpNormal  // 最小 dump
```

### 4. 調用棧不完整
確保：
- 使用 Debug 版本編譯
- 符號路徑正確設置
- 程式沒有被優化（使用 `/Od` 編譯選項）

## 調試技巧

### 1. 添加調試輸出
```cpp
#include "../include/crash_handler.hpp"

// 在關鍵位置添加調用棧輸出
std::cout << "當前調用棧:" << std::endl;
std::cout << RealMemoryDetection::CrashHandler::GetCallStack() << std::endl;
```

### 2. 條件崩潰
```cpp
// 在特定條件下觸發崩潰
if (some_condition) {
    RealMemoryDetection::GenerateCrashDump("conditional_crash.dmp");
    // 或觸發異常
    int* ptr = nullptr;
    *ptr = 42;
}
```

### 3. 性能監控
```cpp
// 監控記憶體使用
#include "../include/utils/performance_monitor.hpp"
RealMemoryDetection::PerformanceMonitor::log_memory_usage();
```

## 文件結構
```
dumps/                    # Dump 文件目錄
├── crash_YYYYMMDD_HHMMSS.dmp
├── manual_test.dmp
└── conditional_crash.dmp

logs/                    # 日誌文件目錄
├── detection_engine.log
└── crash_handler.log

scripts/                 # 調試腳本
├── setup_symbols.bat
├── monitor_with_procdump.bat
├── analyze_dump.bat
├── run_as_admin.bat
└── run_as_admin.ps1
```

## 進階調試

### 1. 使用 Visual Studio 調試器
- 在 Visual Studio 中打開專案
- 設置斷點
- 使用 "Attach to Process" 附加到運行中的程式

### 2. 使用 WinDbg 實時調試
```bash
# 附加到運行中的進程
windbg -p <process_id>

# 或啟動新進程進行調試
windbg -g build\src\real_detection_engine.exe
```

### 3. 使用 ETW 追蹤
```bash
# 啟用 ETW 追蹤
xperf -on PROC_THREAD+LOADER+CSWITCH
# 運行程式
# 停止追蹤
xperf -d trace.etl
```

## 聯繫支持
如果遇到無法解決的問題，請提供：
1. Dump 文件
2. 調用棧信息
3. 錯誤訊息
4. 系統環境信息
5. 重現步驟
