# 攻擊測試快速開始指南

## 概述

本指南將幫助您快速設置和運行實時記憶體攻擊檢測引擎的攻擊測試套件。

## 前置需求

1. **CMake** (版本 3.20 或更高)
2. **C++ 編譯器** (支援 C++23)
3. **vcpkg** (用於管理依賴項)
4. **LLVM** (可選，用於高級功能)

## 快速設置

### 1. 安裝 vcpkg (如果尚未安裝)

```powershell
# 克隆 vcpkg
git clone https://github.com/Microsoft/vcpkg.git D:/vcpkg

# 運行安裝腳本
D:/vcpkg/bootstrap-vcpkg.bat

# 安裝 Google Test
D:/vcpkg/vcpkg install gtest
```

### 2. 構建攻擊測試

#### 方法一：使用構建腳本 (推薦)

```powershell
# 運行構建腳本
.\scripts\build_attack_tests.ps1

# 或者指定自定義路徑
.\scripts\build_attack_tests.ps1 -VcpkgRoot "D:/vcpkg" -BuildType "Release"
```

#### 方法二：手動構建

```powershell
# 設定環境變數
$env:VCPKG_ROOT = "D:/vcpkg"

# 配置 CMake
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=D:/vcpkg/scripts/buildsystems/vcpkg.cmake

# 構建攻擊測試
cmake --build build --config Release --target attack_detection_tests
```

### 3. 運行攻擊測試

```powershell
# 運行攻擊測試
.\build\Release\attack_detection_tests.exe
```

## 預期輸出

成功運行後，您應該看到類似以下的輸出：

```
=== 實時記憶體攻擊檢測引擎 - 攻擊測試套件 ===
測試引擎對抗各種攻擊向量

1. 設置攻擊測試...
2. 執行攻擊測試...
執行: ROP 鏈攻擊 - 檢測: 是 - 時間: 2.5 μs
執行: JOP 鏈攻擊 - 檢測: 是 - 時間: 2.8 μs
執行: 記憶體破壞攻擊 - 檢測: 是 - 時間: 3.1 μs
執行: 緩衝區溢出攻擊 - 檢測: 是 - 時間: 2.9 μs
執行: Use-After-Free 攻擊 - 檢測: 是 - 時間: 3.2 μs
執行: Double Free 攻擊 - 檢測: 是 - 時間: 2.7 μs

=== 攻擊測試報告 ===
總攻擊數: 6
檢測到的攻擊: 6
誤報: 0
檢測率: 100%
誤報率: 0%
平均檢測時間: 2.8 μs

=== 性能分析 ===
✅ 優秀檢測率: 100%
✅ 優秀誤報率: 0%
✅ 優秀檢測時間: 2.8 μs

=== 總體評估 ===
安全評分: 100/100
🏆 優秀 - 引擎已準備好投入生產！

=== 攻擊測試套件完成 ===
```

## 故障排除

### 常見問題

1. **CMake 找不到 LLVM**
   ```
   解決方案：LLVM 是可選的，測試仍可運行
   ```

2. **Google Test 未找到**
   ```
   解決方案：確保 vcpkg 正確安裝並包含 Google Test
   ```

3. **編譯錯誤**
   ```
   解決方案：確保使用支援 C++23 的編譯器
   ```

4. **目標不存在錯誤**
   ```
   解決方案：檢查 CMakeLists.txt 中的目標名稱
   ```

### 調試技巧

1. **啟用詳細輸出**
   ```powershell
   cmake --build build --config Release --target attack_detection_tests --verbose
   ```

2. **檢查依賴項**
   ```powershell
   cmake --build build --config Release --target help
   ```

3. **清理構建目錄**
   ```powershell
   Remove-Item -Recurse -Force build
   ```

## 自定義測試

### 添加新的攻擊測試

1. 在 `tests/attack_tests.cpp` 中添加新的測試類
2. 繼承 `AttackTest` 基類
3. 實現必要的虛擬函數
4. 在 `test_attack_detection.cpp` 中註冊新測試

### 修改測試配置

編輯 `AttackTestConfig` 結構來調整測試參數：

```cpp
AttackTestConfig config;
config.enable_rop_tests = true;           // 啟用 ROP 測試
config.enable_jop_tests = true;           // 啟用 JOP 測試
config.test_duration_ms = 2000;           // 測試持續時間
config.attack_interval_ms = 100;          // 攻擊間隔
config.verbose_output = true;             // 詳細輸出
```

## 性能基準

### 優秀性能指標

- **檢測率**: ≥ 95%
- **誤報率**: ≤ 1%
- **檢測時間**: ≤ 3μs

### 良好性能指標

- **檢測率**: ≥ 90%
- **誤報率**: ≤ 5%
- **檢測時間**: ≤ 5μs

## 下一步

1. 閱讀完整的 [攻擊測試文檔](ATTACK_TESTING.md)
2. 查看 [API 參考](API_Reference.md)
3. 探索 [使用指南](USAGE_GUIDE.md)
4. 貢獻新的攻擊測試用例

## 支援

如果遇到問題，請：

1. 檢查本快速開始指南
2. 查看完整的攻擊測試文檔
3. 檢查 CMake 和編譯器版本
4. 確保所有依賴項正確安裝 