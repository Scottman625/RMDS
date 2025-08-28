# 實時內存攻擊檢測引擎 (Real-Time Memory Attack Detection Engine)

## 專案概述

這是一個基於Windows API的實時內存攻擊檢測引擎，專為檢測和防護各種內存攻擊而設計。項目包含攻擊模擬器和檢測引擎兩個核心組件，能夠模擬並檢測ROP、緩衝區溢出、堆損壞、Shellcode注入、Use-After-Free等多種攻擊類型。

## 核心特性

- **多種攻擊類型檢測**: ROP、JOP、緩衝區溢出、堆損壞、Shellcode注入、Use-After-Free
- **實時進程監控**: 動態掃描系統進程，智能優先級排序
- **內存區域掃描**: 深度掃描進程內存區域，檢測攻擊模式
- **攻擊模擬器**: 內建攻擊模擬器，用於測試檢測引擎效果
- **自適應檢測閾值**: 根據進程類型調整檢測敏感度
- **白名單機制**: 支援系統進程白名單，避免誤報
- **詳細日誌記錄**: 完整的攻擊檢測和系統狀態日誌
- **反取證技術**: 支援記憶體指紋混淆和動態環境混淆
- **分散式多線程**: 使用多線程架構進行並行檢測

## 項目組件

### 1. 檢測引擎 (real_detection_engine.exe)
- 實時監控系統進程（支援掃描前200個進程）
- 掃描內存區域檢測攻擊模式
- 智能進程優先級排序
- 多線程檢測架構
- 支援反取證模式（ENTROPY=7.2）

### 2. 攻擊模擬器 (attack_simulator.exe)
- 模擬分散式ROP攻擊（Scattered ROP）
- 模擬緩衝區溢出攻擊
- 模擬堆損壞攻擊
- 模擬Shellcode注入攻擊
- 模擬Use-After-Free攻擊
- 支援JIT即時編譯技術

### 3. 內存監控器 (memory_monitor.exe)
- 基礎內存監控功能
- 進程信息收集
- 記憶體區域完整性檢查

### 4. Agent 工作流系統 (agent_system/)
- **Orchestrator Agent** - 工作流編排與任務調度
- **Threat Intel Agent** - 威脅情報收集與分析
- **Feature Designer Agent** - 記憶體特徵工程
- **Attack Simulator Agent** - 攻擊場景回放與驗證
- 事件驅動架構，支援自動化威脅響應
- 智能特徵生成與優化
- 實時監控與 KPI 追蹤

## 性能指標

- **檢測延遲**: 實時檢測，毫秒級響應
- **進程掃描**: 支援掃描前200個進程
- **內存掃描**: 深度掃描可執行內存區域
- **平台支援**: Windows 10/11
- **目標應用**: 安全研究、滲透測試、系統監控

## 項目結構

```
RMDS/
├── src/                    # 核心源碼
│   ├── detection_engine.cpp      # 檢測引擎實現
│   ├── attack_simulator.cpp      # 攻擊模擬器
│   ├── memory_monitor.cpp        # 內存監控器
│   ├── memory_monitor_main.cpp   # 內存監控器主程序
│   ├── logger.cpp                # 日誌系統
│   ├── memory_detection_utils.cpp # 工具函數
│   ├── memory_detection_veh.cpp  # 向量化異常處理
│   ├── performance_monitor.cpp   # 性能監控
│   └── process_lists.cpp         # 進程列表管理
├── include/              # 頭檔案
│   ├── memory_detection_monitor.hpp
│   ├── memory_detection_types.hpp
│   ├── memory_detection_utils.hpp
│   ├── memory_detection_veh.hpp
│   ├── detection_engine.hpp
│   └── utils/
│       ├── logger.hpp
│       └── performance_monitor.hpp
├── agent_system/         # Agent 工作流系統
│   ├── agents/           # Agent 實作
│   │   ├── base_agent.py
│   │   ├── orchestrator.py
│   │   ├── threat_intel.py
│   │   ├── feature_designer.py
│   │   └── attack_simulator.py
│   ├── events/           # 事件系統
│   │   └── event_bus.py
│   ├── main.py           # 主程序
│   ├── test_system.py    # 測試腳本
│   ├── run_agent_system.py # 啟動腳本
│   ├── start_agents.bat  # Windows 批處理
│   ├── requirements.txt  # Python 依賴
│   └── README.md         # Agent 系統文檔
├── docs/               # 文檔
├── build/              # 建置檔案
├── run.bat            # 快速啟動腳本
└── CMakeLists.txt     # CMake配置
```

## 快速開始

### 建置要求

- Windows 10/11
- Visual Studio 2022 或更高版本
- CMake 3.20+
- C++23 標準支援
- Python 3.8+ (用於 Agent 系統)

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

#### 方法一：使用快速啟動腳本
```bash
# 以管理員權限運行
run.bat
```

#### 方法二：手動運行
1. **啟動檢測引擎**:
   ```bash
   cd build/src/Release
   ./real_detection_engine.exe /stealth /antidetect /entropy=7.2
   ```

2. **運行攻擊模擬器**:
   ```bash
   cd build/src/Release
   ./attack_simulator.exe /dynamic /jitc
   ```

3. **查看日誌**:
   - 檢測引擎日誌: `logs/detection_engine.log`
   - 攻擊模擬器日誌: `logs/simple_attack_simulator.log`
   - 內存監控器日誌: `logs/memory_monitor.log`

### Agent 工作流系統

#### 快速啟動
```bash
# 進入 Agent 系統目錄
cd agent_system

# 初始設置
python run_agent_system.py --setup

# 運行演示模式
python run_agent_system.py --demo

# 運行系統測試
python run_agent_system.py --test

# 正常啟動
python run_agent_system.py
```

#### 或使用批處理腳本
```bash
# Windows 批處理啟動
start_agents.bat --demo    # 演示模式
start_agents.bat --test    # 測試模式
start_agents.bat --setup   # 初始設置
start_agents.bat           # 正常模式
```

## 使用說明

### 檢測引擎功能
- 自動掃描系統進程（前200個）
- 智能進程優先級排序
- 深度掃描攻擊模擬器進程
- 實時內存區域檢測
- 詳細日誌記錄
- 支援反取證模式

### 攻擊模擬器功能
- 選擇攻擊類型（1-5）
- 自動分配可執行內存
- 注入攻擊代碼
- 驗證內存內容
- 統計攻擊次數
- 支援分散式ROP攻擊

### 快速啟動腳本功能
- 系統防護策略調整
- 進程注入保護
- 動態環境混淆
- 虛擬執行環境建立
- 自動清理程序（60分鐘後）

## 配置選項

### 檢測引擎配置
- `max_processes_to_scan`: 最大掃描進程數（預設200）
- `scan_interval`: 掃描間隔（毫秒）
- `memory_scan_depth`: 內存掃描深度
- `whitelist_processes`: 白名單進程列表
- `/stealth`: 啟用隱身模式
- `/antidetect`: 啟用反檢測模式
- `/entropy=7.2`: 設定熵值混淆

### 攻擊模擬器配置
- 可執行內存分配大小
- 攻擊代碼注入模式
- 內存驗證選項
- `/dynamic`: 啟用動態模式
- `/jitc`: 啟用JIT編譯

## 日誌分析

### 檢測引擎日誌
- 進程掃描結果
- 內存區域檢測
- 攻擊檢測警報
- 系統狀態信息
- ROP攻擊檢測記錄

### 攻擊模擬器日誌
- 攻擊執行過程
- 內存分配信息
- 攻擊統計數據
- 分散式ROP區域信息

## 技術特性

### 反取證技術
- **記憶體指紋混淆**: 使用熵值混淆技術
- **動態環境混淆**: 隨機目錄和虛擬執行環境
- **進程注入保護**: 系統層級繞過技術
- **JIT即時編譯**: 動態代碼生成

### 檢測技術
- **分散式ROP檢測**: 檢測分散在多個記憶體區域的ROP鏈
- **現代Shellcode檢測**: 支援多種現代攻擊框架特徵
- **自適應閾值**: 根據進程類型調整檢測敏感度
- **多線程架構**: 並行處理提高檢測效率

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

4. **日誌文件創建失敗**
   - 確保logs目錄存在
   - 檢查寫入權限

## 開發計劃

- [x] 支援分散式ROP攻擊檢測
- [x] 實現現代Shellcode檢測
- [x] 添加反取證技術
- [x] 統一日誌系統
- [x] **Agent 工作流系統** - 自動化威脅響應與特徵工程
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