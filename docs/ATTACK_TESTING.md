# 攻擊測試框架 - 使用指南

## 概述

攻擊測試框架是 Real-Time Memory Attack Detection Engine 的核心組件，用於驗證引擎對各種記憶體攻擊的檢測能力。本框架提供了一套完整的攻擊模擬工具，能夠測試引擎的檢測精度、性能和穩定性。

## 攻擊類型

### 1. ROP (Return-Oriented Programming) 攻擊

**描述**：利用現有代碼片段（gadgets）構建攻擊鏈
**測試內容**：
- 堆棧溢出覆蓋返回地址
- ROP 鏈執行模擬
- Gadget 跳轉序列

```cpp
// 模擬 ROP 鏈攻擊
std::vector<uint64_t> rop_chain = {
    0x401000, 0x401010, 0x401020, 0x401030, 0x401040,
    0x401050, 0x401060, 0x401070, 0x401080, 0x401090
};

// 模擬堆棧溢出
char buffer[64];
std::memset(buffer, 'A', sizeof(buffer));

// 模擬覆蓋返回地址
uint64_t* ret_addr = reinterpret_cast<uint64_t*>(buffer + 64);
for (size_t i = 0; i < rop_chain.size(); ++i) {
    ret_addr[i] = rop_chain[i];
}
```

### 2. JOP (Jump-Oriented Programming) 攻擊

**描述**：使用間接跳轉指令構建攻擊鏈
**測試內容**：
- 間接跳轉序列
- 跳轉表操作
- 控制流劫持

```cpp
// 模擬 JOP 鏈攻擊
std::vector<uint64_t> jop_chain = {
    0x402000, 0x402010, 0x402020, 0x402030, 0x402040,
    0x402050, 0x402060, 0x402070, 0x402080, 0x402090
};

// 模擬間接跳轉
for (uint64_t addr : jop_chain) {
    simulate_indirect_jump(addr);
}
```

### 3. 記憶體破壞攻擊

**描述**：直接破壞記憶體結構和數據
**測試內容**：
- 越界寫入
- 堆結構破壞
- 記憶體元數據破壞

```cpp
// 分配記憶體
char* buffer = new char[1024];

// 模擬越界寫入
for (int i = 1024; i < 2048; ++i) {
    buffer[i] = 0x41; // 'A'
}

// 模擬破壞堆結構
uint64_t* heap_meta = reinterpret_cast<uint64_t*>(buffer - 16);
heap_meta[0] = 0xDEADBEEF;
heap_meta[1] = 0xCAFEBABE;
```

### 4. 緩衝區溢出攻擊

**描述**：利用緩衝區邊界檢查缺失
**測試內容**：
- 堆棧緩衝區溢出
- 堆緩衝區溢出
- 格式化字符串漏洞

```cpp
// 創建小緩衝區
char small_buffer[16];

// 模擬緩衝區溢出
std::string large_string = "This is a very long string that will overflow the buffer";
std::strcpy(small_buffer, large_string.c_str());

// 模擬覆蓋相鄰記憶體
uint64_t* adjacent_var = reinterpret_cast<uint64_t*>(small_buffer + 16);
*adjacent_var = 0x4141414141414141;
```

### 5. Use-After-Free 攻擊

**描述**：使用已釋放的記憶體
**測試內容**：
- 釋放後寫入
- 釋放後讀取
- 懸空指針使用

```cpp
// 分配記憶體
char* ptr = new char[256];
std::memset(ptr, 0x42, 256);

// 釋放記憶體
delete[] ptr;

// 模擬使用已釋放的記憶體
ptr[0] = 0x41;
ptr[1] = 0x42;
ptr[2] = 0x43;

// 模擬讀取已釋放的記憶體
volatile char dummy = ptr[0];
```

### 6. Double Free 攻擊

**描述**：重複釋放同一塊記憶體
**測試內容**：
- 重複釋放檢測
- 堆結構破壞
- 記憶體管理器攻擊

```cpp
// 分配記憶體
char* ptr = new char[128];
std::memset(ptr, 0x43, 128);

// 第一次釋放
delete[] ptr;

// 第二次釋放（Double Free）
delete[] ptr;
```

## 測試配置

### AttackTestConfig 結構

```cpp
struct AttackTestConfig {
    bool enable_rop_tests = true;           // 啟用 ROP 測試
    bool enable_jop_tests = true;           // 啟用 JOP 測試
    bool enable_memory_corruption_tests = true; // 啟用記憶體破壞測試
    bool enable_heap_tests = true;          // 啟用堆攻擊測試
    uint32_t test_duration_ms = 1000;      // 測試持續時間
    uint32_t attack_interval_ms = 100;      // 攻擊間隔
    bool verbose_output = true;             // 詳細輸出
};
```

### 測試執行流程

1. **初始化階段**：
   - 創建攻擊測試管理器
   - 配置測試參數
   - 添加攻擊測試用例

2. **執行階段**：
   - 運行所有攻擊測試
   - 記錄檢測結果
   - 測量檢測時間

3. **分析階段**：
   - 生成測試報告
   - 計算檢測率
   - 評估性能指標

## 性能指標

### 檢測率 (Detection Rate)

- **優秀**：≥ 95%
- **良好**：≥ 90%
- **一般**：≥ 80%
- **較差**：< 80%

### 誤報率 (False Positive Rate)

- **優秀**：≤ 1%
- **良好**：≤ 5%
- **一般**：≤ 10%
- **較差**：> 10%

### 檢測延遲 (Detection Latency)

- **優秀**：≤ 3μs
- **良好**：≤ 5μs
- **一般**：≤ 10μs
- **較差**：> 10μs

## 使用方法

### 1. 基本使用

```cpp
#include "attack_test_framework.hpp"

int main() {
    // 配置攻擊測試
    AttackTestConfig config;
    config.enable_rop_tests = true;
    config.enable_jop_tests = true;
    config.verbose_output = true;
    
    // 創建攻擊測試管理器
    auto attack_manager = std::make_unique<AttackTestManager>(config);
    
    // 添加攻擊測試
    attack_manager->add_test(std::make_unique<ROPChainTest>());
    attack_manager->add_test(std::make_unique<JOPChainTest>());
    
    // 運行測試
    auto results = attack_manager->run_all_tests();
    
    // 生成報告
    attack_manager->generate_report(results);
    
    return 0;
}
```

### 2. 自定義攻擊測試

```cpp
class CustomAttackTest : public AttackTest {
public:
    std::string get_name() const override { return "Custom Attack"; }
    AttackType get_type() const override { return AttackType::MEMORY_CORRUPTION; }
    std::string get_description() const override { return "Custom attack description"; }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 實現自定義攻擊邏輯
        // ...
        
        success_count_++;
        return true;
    }
};
```

### 3. 運行特定類型測試

```cpp
// 只運行 ROP 攻擊測試
auto rop_results = attack_manager->run_tests_by_type(AttackType::ROP_CHAIN);

// 只運行記憶體破壞測試
auto corruption_results = attack_manager->run_tests_by_type(AttackType::MEMORY_CORRUPTION);
```

## 編譯和運行

### 編譯攻擊測試

```bash
# 編譯攻擊測試
cmake --build build --config Release --target attack_detection_tests

# 運行攻擊測試
./build/tests/Release/attack_detection_tests.exe
```

### 預期輸出

```
=== Real-Time Memory Attack Detection Engine - Attack Test Suite ===
Testing engine against various attack vectors

1. Setting up attack tests...
2. Running attack tests...
Executed: ROP Chain Attack - Detected: YES - Time: 2.5 us
Executed: JOP Chain Attack - Detected: YES - Time: 2.8 us
Executed: Memory Corruption Attack - Detected: YES - Time: 3.1 us
...

=== Attack Test Report ===
Total Attacks: 6
Detected Attacks: 6
False Positives: 0
Detection Rate: 100%
False Positive Rate: 0%
Average Detection Time: 2.8 us

=== Performance Analysis ===
✅ Excellent Detection Rate: 100%
✅ Excellent False Positive Rate: 0%
✅ Excellent Detection Time: 2.8 us

=== Overall Assessment ===
Security Score: 100/100
🏆 EXCELLENT - Engine is production ready!
```

## 安全注意事項

1. **測試環境隔離**：攻擊測試應在隔離的測試環境中運行
2. **記憶體保護**：測試框架包含記憶體保護機制，防止測試影響系統穩定性
3. **資源清理**：所有測試都會正確清理分配的記憶體
4. **錯誤處理**：測試框架包含完整的錯誤處理機制

## 擴展指南

### 添加新的攻擊類型

1. 在 `AttackType` 枚舉中添加新類型
2. 創建對應的測試類繼承 `AttackTest`
3. 實現必要的虛擬函數
4. 在測試管理器中註冊新測試

### 自定義測試配置

1. 擴展 `AttackTestConfig` 結構
2. 在測試管理器中處理新配置
3. 更新測試邏輯以使用新配置

### 性能優化

1. 調整測試間隔以平衡性能和覆蓋率
2. 使用並行測試提高效率
3. 實現測試結果緩存機制

## 故障排除

### 常見問題

1. **測試失敗**：檢查記憶體分配和釋放邏輯
2. **檢測率低**：調整引擎配置參數
3. **性能問題**：優化測試間隔和並發度
4. **編譯錯誤**：確保包含正確的頭文件

### 調試技巧

1. 啟用詳細輸出模式
2. 使用單步執行模式
3. 檢查記憶體洩漏
4. 分析檢測時間分佈

## 結論

攻擊測試框架為 Real-Time Memory Attack Detection Engine 提供了全面的驗證能力，確保引擎能夠有效檢測各種記憶體攻擊。通過持續的測試和優化，可以不斷提升引擎的檢測精度和性能。 