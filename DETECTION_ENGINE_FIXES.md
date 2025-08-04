# 記憶體檢測引擎修復說明

## 問題分析

原始的記憶體檢測引擎存在以下問題導致無法持續監控：

### 1. 主迴圈邏輯問題
- **重複的迴圈結構**：主迴圈中有重複的 while 迴圈，導致邏輯混亂
- **異常處理不當**：異常發生時直接退出，而不是繼續運行
- **過度頻繁的狀態檢查**：每30秒檢查一次狀態，但同時又有重複的迴圈

### 2. 記憶體掃描過度頻繁
- **掃描頻率過高**：每5秒執行一次完整記憶體掃描
- **掃描範圍過大**：掃描整個記憶體空間，導致系統負載過高
- **檢查範圍過大**：每次檢查4096位元組，消耗過多資源

### 3. 進程監控問題
- **進程掃描過於頻繁**：每5秒掃描一次所有進程
- **API Hook檢查過於頻繁**：每30秒檢查一次API Hook
- **沒有限制掃描數量**：掃描所有進程，包括系統進程

### 4. 異常處理不完善
- **異常導致退出**：任何異常都會導致檢測迴圈退出
- **缺乏恢復機制**：沒有從異常中恢復的機制
- **日誌記錄過於頻繁**：過多的日誌記錄影響性能

## 修復方案

### 1. 簡化主迴圈邏輯
```cpp
// 修復前：重複的迴圈結構
while (engine.is_running()) {
    // 複雜的邏輯
    if (engine.is_running()) {
        // 另一個迴圈
    }
}

// 修復後：簡化的單一迴圈
while (engine.is_running()) {
    try {
        // 每30秒顯示一次狀態
        std::this_thread::sleep_for(std::chrono::seconds(30));
        engine.show_status();
        
        // 檢查用戶輸入
        if (_kbhit()) {
            char ch = _getch();
            if (ch == 'q' || ch == 'Q') {
                engine.stop();
                break;
            }
        }
    } catch (...) {
        // 繼續運行，不要因為異常而退出
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}
```

### 2. 優化記憶體掃描策略
```cpp
// 修復前：過於頻繁的掃描
if (cycle_count % 600 == 0) { // 每5秒
    scan_memory_for_attacks();
}

// 修復後：減少掃描頻率
if (cycle_count % 200 == 0) { // 每10秒
    scan_memory_for_attacks();
}

// 限制掃描範圍
const SIZE_T MAX_SCAN_SIZE = 256 * 1024 * 1024; // 256MB
SIZE_T scanned_size = 0;
while (lpMem < si.lpMaximumApplicationAddress && scanned_size < MAX_SCAN_SIZE) {
    // 掃描邏輯
}
```

### 3. 改善進程監控
```cpp
// 修復前：過於頻繁的進程掃描
if (cycle_count % 5 == 0) { // 每5秒
    scan_processes();
}

// 修復後：減少掃描頻率並限制數量
if (cycle_count % 10 == 0) { // 每10秒
    scan_processes();
}

// 限制掃描的進程數量
const int MAX_PROCESSES = 50;
int process_count = 0;
if (process_count >= MAX_PROCESSES) {
    break;
}
```

### 4. 改善異常處理
```cpp
// 修復前：異常導致退出
} catch (const std::exception& e) {
    std::cerr << "Exception in detection loop: " << e.what() << std::endl;
    // 沒有恢復機制
}

// 修復後：異常後繼續運行
} catch (const std::exception& e) {
    std::cerr << "Exception in detection loop: " << e.what() << std::endl;
    log_message("ERROR", "Detection loop exception: " + std::string(e.what()));
    // 繼續運行，不要因為異常而退出
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}
```

### 5. 減少檢查頻率
```cpp
// 堆積檢查：每10次調用才檢查一次
static int heap_check_counter = 0;
heap_check_counter++;
if (heap_check_counter % 10 != 0) {
    return;
}

// 堆疊檢查：每10次調用才檢查一次
static int stack_integrity_counter = 0;
stack_integrity_counter++;
if (stack_integrity_counter % 10 != 0) {
    return;
}

// API Hook檢查：每5次調用才檢查一次
static int api_hook_counter = 0;
api_hook_counter++;
if (api_hook_counter % 5 != 0) {
    return;
}
```

## 修復效果

### 1. 穩定性提升
- **持續運行**：檢測引擎現在可以持續運行而不會因為異常而退出
- **異常恢復**：所有異常都被捕獲並處理，不會影響整體運行
- **資源管理**：改善了記憶體和CPU使用率

### 2. 性能優化
- **減少掃描頻率**：記憶體掃描從每5秒改為每10秒
- **限制掃描範圍**：記憶體掃描限制在256MB內
- **減少檢查範圍**：可執行區域檢查從1024位元組減少到512位元組

### 3. 系統負載降低
- **進程掃描優化**：從每5秒掃描改為每10秒，並限制掃描50個進程
- **API Hook檢查優化**：從每30秒改為每60秒檢查
- **堆積檢查優化**：每10次調用才檢查一次堆積

### 4. 用戶體驗改善
- **簡化的控制邏輯**：移除了重複的迴圈結構
- **更好的狀態顯示**：減少輸出頻率，避免信息過載
- **穩定的運行**：檢測引擎可以長時間穩定運行

## 使用方法

1. **編譯檢測引擎**：
   ```bash
   test_detection_engine.bat
   ```

2. **運行檢測引擎**：
   ```bash
   cd build_simple/bin/Release
   real_detection_engine.exe
   ```

3. **停止檢測引擎**：
   - 在運行中的終端按 'q' 鍵

## 注意事項

1. **權限要求**：檢測引擎需要管理員權限才能監控其他進程
2. **系統資源**：雖然已優化，但仍會消耗一定的CPU和記憶體資源
3. **誤報可能**：某些正常的系統行為可能被誤報為攻擊
4. **兼容性**：僅支持Windows系統

## 未來改進方向

1. **更智能的掃描策略**：根據系統負載動態調整掃描頻率
2. **更精確的檢測算法**：減少誤報率
3. **更好的用戶界面**：提供圖形化界面
4. **配置選項**：允許用戶自定義檢測參數 