# 改進的記憶體攻擊檢測系統

## 問題分析

您之前遇到的檢測結果顯示了對 `ssh-agent.exe` 的誤報：

```
*** REPORTING ROP ATTACK in process 5552 (ssh-agent.exe) ***
*** Category: USER ***
*** Thresholds: suspicious=5, ret=8 ***
*** Found: suspicious=0, ret=25 ***
```

這表明檢測系統存在以下問題：
1. **進程分類不準確**: ssh-agent 被錯誤分類為用戶進程
2. **閾值設置過低**: 對系統工具的檢測閾值不夠嚴格
3. **模式識別不夠精確**: 無法區分正常的函數返回和真正的攻擊

## 改進措施

### 1. 擴展系統進程列表

將更多系統工具歸類為系統進程：
```cpp
std::vector<std::string> system_processes_ = {
    "svchost.exe", "lsass.exe", "winlogon.exe", "services.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "ntoskrnl.exe",
    "explorer.exe", "taskmgr.exe", "cmd.exe", "powershell.exe",
    "ssh-agent.exe", "ssh.exe", "git.exe", "wsl.exe", "bash.exe",
    "conhost.exe", "dwm.exe", "ctfmon.exe", "spoolsv.exe"
};
```

### 2. 提高系統進程閾值

大幅提高系統進程的檢測閾值以避免誤報：

| 檢測類型 | 原閾值 | 新閾值 |
|---------|--------|--------|
| ROP可疑模式 | 8 | 12 |
| ROP RET指令 | 12 | 20 |
| 堆積破壞 | 3 | 5 |
| Shellcode | 2 | 5 |

### 3. 改進ROP檢測邏輯

添加更精確的ROP檢測機制：

```cpp
// 檢測連續的ret指令
int consecutive_ret = 0;
int max_consecutive_ret = 0;

// 擴展可疑模式檢測
if (i > 0 && buffer[i-1] == 0x58) { // pop eax
    suspicious_patterns++;
}
if (i > 0 && buffer[i-1] == 0x5E) { // pop esi
    suspicious_patterns++;
}
if (i > 0 && buffer[i-1] == 0x5F) { // pop edi
    suspicious_patterns++;
}

// 改進檢測條件
bool is_suspicious_rop = (suspicious_patterns >= suspicious_threshold || 
                         (ret_count >= ret_threshold && max_consecutive_ret >= 3));
```

### 4. 更精確的進程分類

```cpp
ProcessCategory classify_process(const std::string& process_name) {
    // 1. 檢查是否為攻擊模擬器
    // 2. 檢查是否為高風險進程
    // 3. 檢查是否為系統進程（擴展列表）
    // 4. 默認為用戶進程
}
```

## 預期效果

### 1. 減少誤報
- ssh-agent.exe 現在被歸類為系統進程
- 使用更嚴格的閾值（suspicious=12, ret=20）
- 需要連續的ret指令才會觸發檢測

### 2. 更精確的檢測
- 區分正常的函數返回和真正的ROP攻擊
- 考慮連續ret指令的模式
- 擴展可疑指令的檢測範圍

### 3. 更好的進程分類
- 系統工具被正確歸類
- 高風險進程使用較低閾值
- 攻擊模擬器使用最低閾值

## 測試建議

1. **重新運行檢測引擎**，觀察是否還有對 ssh-agent.exe 的誤報
2. **啟動攻擊模擬器**，確認仍能正確檢測攻擊
3. **觀察不同進程類別的檢測行為**：
   - 系統進程：應該很少或沒有誤報
   - 高風險進程：適中的檢測敏感度
   - 攻擊模擬器：高敏感度檢測

## 配置調整

如果仍有誤報，可以進一步調整：

```cpp
// 進一步提高系統進程閾值
int system_rop_suspicious_patterns = 15;
int system_rop_ret_count = 25;

// 或者添加白名單
std::vector<std::string> whitelist_processes_ = {
    "ssh-agent.exe", "ssh.exe", "git.exe"
};
```

## 監控建議

1. **觀察檢測日誌**，特別注意進程分類是否正確
2. **檢查閾值設置**，確保不同進程類別使用合適的閾值
3. **驗證攻擊檢測**，確保真正的攻擊仍能被檢測到
4. **調整參數**，根據實際運行情況微調閾值

這些改進應該能顯著減少對正常系統進程的誤報，同時保持對真正攻擊的檢測能力。 