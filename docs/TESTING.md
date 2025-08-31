# RMDS 單元測試系統

## 概述

RMDS (Real-time Memory Detection System) 包含完整的單元測試系統，用於驗證系統的各個組件功能。

## 測試架構

### 1. CMake 測試配置

項目使用 CMake 的 `enable_testing()` 和 `add_test()` 來配置測試：

```cmake
# 在根目錄 CMakeLists.txt 中
enable_testing()

# 在 tests/CMakeLists.txt 中
add_executable(test_suite basic_test.cpp)
add_test(NAME test_suite COMMAND test_suite)
```

### 2. 測試文件結構

```
tests/
├── CMakeLists.txt          # 測試構建配置
├── basic_test.cpp          # 基本功能測試
├── simple_test.cpp         # 簡單測試
└── test_memory_detection.cpp # 記憶體檢測測試
```

### 3. 測試框架

使用自定義的測試框架，提供：
- 測試執行和結果收集
- 詳細的測試報告
- 錯誤處理和異常捕獲

## 運行測試

### 方法 1: 使用 Python 測試腳本

```bash
python run_tests.py
```

這個腳本會：
- 動態生成測試代碼
- 編譯並執行測試
- 提供詳細的測試報告

### 方法 2: 使用 CMake 和 CTest

```bash
# 構建項目
cmake -B build -S .
cmake --build build

# 運行測試
cd build
ctest --verbose
```

### 方法 3: 直接運行測試可執行文件

```bash
# 構建測試
cmake --build build --target test_suite

# 運行測試
./build/tests/test_suite.exe
```

## 測試類型

### 1. 基本功能測試

測試核心 C++ 功能：
- 字符串操作
- 向量操作
- 數學運算
- 內存操作
- 算法操作

### 2. 檢測ID生成測試

測試檢測ID生成功能：
- ID 唯一性驗證
- ID 格式驗證
- 時間戳生成

### 3. 記憶體檢測測試

測試記憶體檢測引擎：
- 事件處理
- 檢測邏輯
- 性能監控

## 測試結果

### 成功示例

```
=== RMDS 單元測試系統 ===
=== 運行基本測試 ===
=== Basic Test ===
PASS: All basic tests passed!
✅ 測試通過

=== 運行檢測ID測試 ===
=== Detection ID Test ===
Generated ID 1: detection_1_1735641234567
Generated ID 2: detection_2_1735641234568
Generated ID 3: detection_3_1735641234569
✅ PASS: All tests passed!
✅ 檢測ID測試通過

=== 測試總結 ===
總測試數: 2
通過: 2
失敗: 0
成功率: 100.0%

🎉 所有測試通過！
```

### 失敗示例

```
❌ FAIL: String length test
❌ 測試失敗

=== 測試總結 ===
總測試數: 2
通過: 1
失敗: 1
成功率: 50.0%

💥 部分測試失敗！
```

## 添加新測試

### 1. 創建測試文件

```cpp
#include <iostream>
#include <string>

bool test_new_functionality() {
    // 測試邏輯
    std::string test_str = "test";
    if (test_str.length() != 4) {
        return false;
    }
    return true;
}

int main() {
    std::cout << "=== New Functionality Test ===" << std::endl;
    
    if (test_new_functionality()) {
        std::cout << "✅ PASS: All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "❌ FAIL: Tests failed!" << std::endl;
        return 1;
    }
}
```

### 2. 更新 CMakeLists.txt

```cmake
add_executable(new_test new_test.cpp)
add_test(NAME new_test COMMAND new_test)
```

### 3. 更新 Python 測試腳本

在 `run_tests.py` 中添加新的測試函數。

## 測試最佳實踐

### 1. 測試設計原則

- **單一職責**: 每個測試只測試一個功能
- **獨立性**: 測試之間不應相互依賴
- **可重複性**: 測試應該可以重複執行
- **清晰性**: 測試名稱和錯誤信息應該清晰明確

### 2. 測試覆蓋率

- 核心功能: 100% 覆蓋
- 邊界條件: 必須測試
- 錯誤處理: 必須測試
- 性能測試: 關鍵路徑

### 3. 測試維護

- 定期運行測試
- 及時修復失敗的測試
- 更新測試文檔
- 添加新功能的測試

## 故障排除

### 常見問題

1. **編譯錯誤**
   - 檢查 C++ 標準版本
   - 確認所有依賴庫已安裝
   - 檢查編譯器設置

2. **測試失敗**
   - 檢查測試邏輯
   - 確認輸入數據正確
   - 檢查環境依賴

3. **編碼問題**
   - 使用 UTF-8 編碼
   - 避免特殊字符
   - 檢查文件編碼設置

### 調試技巧

1. **詳細輸出**
   ```bash
   ctest --verbose --output-on-failure
   ```

2. **單個測試**
   ```bash
   ./build/tests/test_suite.exe
   ```

3. **編譯調試**
   ```bash
   cmake --build build --verbose
   ```

## 持續集成

### GitHub Actions 配置

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
    - uses: actions/checkout@v2
    - name: Configure CMake
      run: cmake -B build -S .
    - name: Build
      run: cmake --build build
    - name: Test
      run: ctest --test-dir build --output-on-failure
```

## 總結

RMDS 的測試系統提供了：

- ✅ 完整的測試框架
- ✅ 自動化測試執行
- ✅ 詳細的測試報告
- ✅ 易於擴展的架構
- ✅ 持續集成支持

通過這個測試系統，我們可以確保 RMDS 的穩定性和可靠性。
