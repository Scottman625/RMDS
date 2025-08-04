# 自適應記憶體攻擊檢測系統

## 概述

本系統實現了一個通用的記憶體攻擊檢測引擎，具有自適應閾值功能。檢測引擎會根據進程類型和風險等級自動調整檢測敏感度，以平衡檢測準確性和誤報率。

## 進程分類

### 1. 系統進程 (SYSTEM_PROCESS)
- **識別標準**: 基於進程名稱
- **包含進程**: svchost.exe, lsass.exe, winlogon.exe, services.exe, wininit.exe, csrss.exe, smss.exe, ntoskrnl.exe, explorer.exe, taskmgr.exe, cmd.exe, powershell.exe
- **檢測策略**: 使用較高閾值，減少誤報
- **掃描頻率**: 每10個系統進程掃描一次

### 2. 用戶進程 (USER_PROCESS)
- **識別標準**: 不屬於其他類別的進程
- **檢測策略**: 使用中等閾值
- **掃描頻率**: 每5個用戶進程掃描一次

### 3. 高風險進程 (HIGH_RISK_PROCESS)
- **識別標準**: 基於進程名稱
- **包含進程**: chrome.exe, firefox.exe, iexplore.exe, msedge.exe, java.exe, javaw.exe, python.exe, node.exe, powershell.exe, cmd.exe, explorer.exe
- **檢測策略**: 使用較低閾值，更容易檢測攻擊
- **掃描策略**: 立即進行深度掃描

### 4. 攻擊模擬器 (ATTACK_SIMULATOR)
- **識別標準**: 進程名稱包含 "attack_simulator" 或 "simple_attack_simulator"
- **檢測策略**: 使用最低閾值，確保檢測
- **掃描策略**: 立即進行深度掃描

## 自適應閾值配置

### ROP/JOP 檢測閾值

| 進程類別 | 可疑模式閾值 | RET指令閾值 |
|---------|-------------|------------|
| 系統進程 | 8 | 12 |
| 用戶進程 | 5 | 8 |
| 高風險進程 | 2 | 3 |
| 攻擊模擬器 | 3 | 5 |

### 堆積破壞檢測閾值

| 進程類別 | 破壞模式閾值 |
|---------|-------------|
| 系統進程 | 3 |
| 用戶進程 | 2 |
| 高風險進程 | 1 |
| 攻擊模擬器 | 1 |

### Shellcode 檢測閾值

| 進程類別 | Shellcode模式閾值 |
|---------|------------------|
| 系統進程 | 2 |
| 用戶進程 | 1 |
| 高風險進程 | 1 |
| 攻擊模擬器 | 1 |

## 檢測模式

### 1. 通用掃描
- 掃描所有可訪問的進程
- 根據進程類別應用不同的檢測策略
- 動態調整掃描頻率

### 2. 深度掃描
- 對高風險進程和攻擊模擬器進行深度掃描
- 檢查所有已提交的記憶體區域
- 使用自適應閾值進行檢測

### 3. 自適應檢測
- 根據進程類別自動選擇合適的閾值
- 在檢測輸出中顯示進程類別和閾值信息
- 提供詳細的檢測統計信息

## 使用方法

### 啟動檢測引擎
```batch
test_adaptive_detection.bat
```

### 手動啟動
1. 以管理員權限運行 `real_detection_engine.exe`
2. 啟動 `attack_simulator.exe`
3. 在攻擊模擬器中選擇攻擊類型

## 輸出示例

```
*** FOUND ATTACK SIMULATOR: PID 1234 ***
*** Process Name: attack_simulator.exe ***
*** REPORTING ROP ATTACK in process 1234 (attack_simulator.exe) ***
*** Category: SIMULATOR ***
*** Thresholds: suspicious=3, ret=5 ***
*** Found: suspicious=4, ret=6 ***
```

```
*** HIGH RISK PROCESS: PID 5678 (chrome.exe) ***
*** REPORTING HEAP CORRUPTION in process 5678 (chrome.exe) ***
*** Category: HIGH_RISK ***
*** Corruption threshold: 1, found: 2 ***
```

## 優勢

1. **通用性**: 不僅檢測攻擊模擬器，還檢測所有類型的進程
2. **自適應性**: 根據進程風險等級自動調整檢測敏感度
3. **準確性**: 對系統進程使用較高閾值，減少誤報
4. **效率**: 對不同類型的進程使用不同的掃描頻率
5. **可配置性**: 閾值可以根據需要調整

## 配置調整

如需調整閾值，請修改 `src/detection_engine.cpp` 中的 `AdaptiveThresholds` 結構：

```cpp
struct AdaptiveThresholds {
    // 系統進程閾值（較高，避免誤報）
    int system_rop_suspicious_patterns = 8;
    int system_rop_ret_count = 12;
    // ... 其他閾值
};
```

## 注意事項

1. 檢測引擎需要管理員權限才能訪問其他進程
2. 系統進程的較高閾值可能會降低對真實攻擊的檢測率
3. 高風險進程列表可以根據實際需求調整
4. 建議在生產環境中根據實際情況調整閾值 