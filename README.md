# 實時內存攻擊檢測引擎 (Real-Time Memory Attack Detection Engine)

## 專案概述

這是一個基於Windows API的實時內存攻擊檢測引擎，專為檢測和防護各種內存攻擊而設計。項目包含攻擊模擬器和檢測引擎兩個核心組件，能夠模擬並檢測ROP、緩衝區溢出、堆損壞、Shellcode注入、Use-After-Free等多種攻擊類型。

## 核心特性

- **多種攻擊類型檢測**: ROP、緩衝區溢出、堆損壞、Shellcode注入、Use-After-Free
- **實時進程監控**: 動態掃描系統進程，智能優先級排序
- **內存區域掃描**: 深度掃描進程內存區域，檢測攻擊模式
- **攻擊模擬器**: 內建攻擊模擬器，用於測試檢測引擎效果
- **自適應檢測閾值**: 根據進程類型調整檢測敏感度
- **白名單機制**: 支援系統進程白名單，避免誤報
- **詳細日誌記錄**: 完整的攻擊檢測和系統狀態日誌

## 項目組件

### 1. 檢測引擎 (real_detection_engine.exe)
- 實時監控系統進程
- 掃描內存區域檢測攻擊模式
- 智能進程優先級排序
- 多線程檢測架構

### 2. 攻擊模擬器 (attack_simulator.exe)
- 模擬ROP攻擊
- 模擬緩衝區溢出攻擊
- 模擬堆損壞攻擊
- 模擬Shellcode注入攻擊
- 模擬Use-After-Free攻擊

### 3. 內存監控器 (memory_monitor.exe)
- 基礎內存監控功能
- 進程信息收集

## 性能指標

- **檢測延遲**: 實時檢測，毫秒級響應
- **進程掃描**: 支援掃描前200個進程
- **內存掃描**: 深度掃描可執行內存區域
- **平台支援**: Windows 10/11
- **目標應用**: 安全研究、滲透測試、系統監控

## 項目結構

```
RealTimeMemoryAttackDetectEngine/
├── src/                    # 核心源碼
│   ├── detection_engine.cpp      # 檢測引擎實現
│   ├── attack_simulator.cpp      # 攻擊模擬器
│   ├── memory_monitor.cpp        # 內存監控器
│   ├── real_memory_detection_engine.cpp  # 核心檢測邏輯
│   └── logger.cpp                # 日誌系統
├── include/              # 頭檔案
│   ├── real_memory_detection_engine.hpp
│   ├── real_memory_detection_monitor.hpp
│   └── utils/
├── examples/            # 使用範例
├── docs/               # 文檔
└── build/              # 建置檔案
```

## 快速開始

### 建置要求

- Windows 10/11
- Visual Studio 2022 或更高版本
- CMake 3.20+
- C++23 標準支援

### 建置步驟

#### 方法一：使用CMake
```bash
# 創建建置目錄
mkdir build
cd build

# 配置項目
cmake .. -G "Visual Studio 17 2022" -A x64

# 編譯項目
cmake --build . --config Release
```

#### 方法二：使用Visual Studio
1. 打開 `RealTimeMemoryAttackDetectEngine.sln`
2. 選擇 Release 配置
3. 建置解決方案

### 運行測試

1. **啟動檢測引擎**:
   ```bash
   cd build/src/Release
   ./real_detection_engine.exe
   ```

2. **運行攻擊模擬器**:
   ```bash
   cd build/src/Release
   ./attack_simulator.exe
   ```

3. **查看日誌**:
   - 檢測引擎日誌: `detection_engine.log`
   - 攻擊模擬器日誌: `attack_simulator.log`

## 使用說明

### 檢測引擎功能
- 自動掃描系統進程（前200個）
- 智能進程優先級排序
- 深度掃描攻擊模擬器進程
- 實時內存區域檢測
- 詳細日誌記錄

### 攻擊模擬器功能
- 選擇攻擊類型（1-5）
- 自動分配可執行內存
- 注入攻擊代碼
- 驗證內存內容
- 統計攻擊次數

## 配置選項

### 檢測引擎配置
- `max_processes_to_scan`: 最大掃描進程數（預設200）
- `scan_interval`: 掃描間隔（毫秒）
- `memory_scan_depth`: 內存掃描深度
- `whitelist_processes`: 白名單進程列表

### 攻擊模擬器配置
- 可執行內存分配大小
- 攻擊代碼注入模式
- 內存驗證選項

## 日誌分析

### 檢測引擎日誌
- 進程掃描結果
- 內存區域檢測
- 攻擊檢測警報
- 系統狀態信息

### 攻擊模擬器日誌
- 攻擊執行過程
- 內存分配信息
- 攻擊統計數據

## 故障排除

### 常見問題
1. **檢測引擎未檢測到攻擊**
   - 檢查攻擊模擬器是否在進程列表中
   - 確認進程優先級排序
   - 查看日誌文件

2. **編譯錯誤**
   - 確認Visual Studio版本
   - 檢查C++23標準支援
   - 驗證CMake配置

3. **權限問題**
   - 以管理員身份運行
   - 檢查Windows Defender設置

## 開發計劃

- [ ] 支援更多攻擊類型
- [ ] 改進進程優先級算法
- [ ] 添加圖形化界面
- [ ] 支援Linux平台
- [ ] 性能優化

## 授權

MIT License

## 貢獻

歡迎提交Issue和Pull Request！

## 免責聲明

本項目僅用於安全研究和教育目的。使用者應遵守當地法律法規，不得用於非法活動。 