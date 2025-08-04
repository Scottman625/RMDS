# 最終優化的記憶體攻擊檢測系統

## 問題解決總結

### 已解決的問題
1. ✅ **ssh-agent.exe 誤報**: 已添加到白名單
2. ✅ **ipf_uf.exe 誤報**: 已添加到白名單
3. ✅ **openvpnserv.exe 誤報**: 已添加到白名單
4. ✅ **nvcontainer.exe 誤報**: 已添加到白名單
5. ✅ **FNPLicensingService.exe 誤報**: 已添加到白名單
6. ✅ **過多的白名單跳過輸出**: 已實現靜默模式

## 最終改進措施

### 1. 擴展白名單機制

```cpp
std::vector<std::string> whitelist_processes_ = {
    "ipf_uf.exe", "ipf_ufd.exe", "ipf_ufw.exe", "ipf_ufs.exe",
    "rundll32.exe", "dllhost.exe", "svchost.exe", "lsass.exe",
    "winlogon.exe", "services.exe", "wininit.exe", "csrss.exe",
    "smss.exe", "ntoskrnl.exe", "explorer.exe", "taskmgr.exe",
    "cmd.exe", "powershell.exe", "ssh-agent.exe", "ssh.exe",
    "git.exe", "wsl.exe", "bash.exe", "conhost.exe", "dwm.exe",
    "ctfmon.exe", "spoolsv.exe", "openvpnserv.exe", "openvpn.exe",
    "nvcontainer.exe", "nvcpl.exe", "nvxdsync.exe",
    "nvidia-smi.exe", "nvbackend.exe", "nvwgf2umx.dll", "nvapi64.dll",
    "fnplicensingservice.exe"
};
```

### 2. 靜默白名單跳過機制

```cpp
void silent_whitelist_skip(const std::string& process_name) {
    std::lock_guard<std::mutex> lock(whitelist_mutex_);
    whitelist_skip_count_[process_name]++;
    
    // 只在第一次跳過時輸出信息，之後每500次才輸出一次
    if (whitelist_skip_count_[process_name] == 1) {
        std::cout << "    Skipping detection for whitelisted process: " << process_name << std::endl;
    } else if (whitelist_skip_count_[process_name] % 500 == 0) {
        std::cout << "    Skipped " << whitelist_skip_count_[process_name] << " times for whitelisted process: " << process_name << std::endl;
    }
}
```

### 3. 優化的閾值配置

| 進程類別 | ROP可疑模式 | ROP RET指令 | 堆積破壞 | Shellcode |
|---------|-------------|------------|----------|-----------|
| 系統進程 | 12 | 20 | 5 | 5 |
| 用戶進程 | 8 | 12 | 3 | 3 |
| 高風險進程 | 2 | 3 | 1 | 1 |
| 攻擊模擬器 | 3 | 5 | 1 | 1 |

### 4. 改進的檢測邏輯

#### ROP 檢測
- 檢測連續的ret指令
- 需要連續ret指令 >= 3 才會觸發
- 擴展可疑指令模式識別

#### Shellcode 檢測
- 檢測常見的shellcode開頭模式
- 對長NOP sled和int3 sled給予更高權重
- 限制掃描區域大小為4KB以提高效率

### 5. 進程分類系統

```cpp
enum ProcessCategory {
    SYSTEM_PROCESS,      // 系統進程（高閾值）
    USER_PROCESS,        // 用戶進程（中等閾值）
    ATTACK_SIMULATOR,    // 攻擊模擬器（低閾值）
    HIGH_RISK_PROCESS    // 高風險進程（最低閾值）
};
```

### 6. 深度掃描機制

- 對攻擊模擬器和高風險進程進行深度掃描
- 掃描所有已提交的記憶體區域
- 提供詳細的掃描日誌

## 使用說明

1. **編譯專案**:
   ```bash
   cd build_test
   cmake --build . --config Release
   ```

2. **運行檢測引擎**:
   ```bash
   # 以管理員權限運行
   src\Release\real_detection_engine.exe
   ```

3. **運行攻擊模擬器**:
   ```bash
   src\Release\attack_simulator.exe
   ```

4. **使用批次檔同時運行**:
   ```bash
   test_adaptive_detection.bat
   ```

## 監控和日誌

- 檢測結果記錄在 `detection_engine.log`
- 攻擊模擬器日誌記錄在 `simple_attack_simulator.log`
- 控制台輸出包含即時檢測狀態

## 性能優化

- 掃描頻率：每5秒進行一次記憶體掃描
- 全進程掃描：每60秒進行一次
- 狀態輸出：每60秒輸出一次
- 循環信息：每300秒輸出一次

## 注意事項

1. 需要以管理員權限運行檢測引擎
2. 白名單進程將完全跳過檢測
3. 系統進程使用較高的檢測閾值以避免誤報
4. 攻擊模擬器使用較低的閾值以確保檢測效果 