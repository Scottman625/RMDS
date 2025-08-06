# 安全軟體白名單設定指南

## 問題描述
檢測引擎 `real_detection_engine.exe` 被安全軟體誤判為惡意軟體，導致無法執行。

## 解決方案

### 方案 1：Windows Defender 白名單設定
1. 開啟 Windows Defender 設定
2. 進入「病毒與威脅防護」→「管理設定」
3. 在「排除項目」中新增資料夾：`D:\code\CyberSecirity\RealTimeMemoryAttackDetectEngine\build\src\Release\`
4. 重新啟動檢測引擎

### 方案 2：其他安全軟體白名單
- **Norton/Symantec**: 設定 → 掃描與風險 → 排除項目
- **McAfee**: 設定 → 即時掃描 → 排除項目
- **Kaspersky**: 設定 → 進階威脅防護 → 排除項目

### 方案 3：命令列執行（繞過安全軟體）
```powershell
# 使用 PowerShell 執行，可能繞過部分安全軟體
powershell -ExecutionPolicy Bypass -Command "& '.\build\src\Release\real_detection_engine.exe'"

# 或使用 cmd
cmd /c "build\src\Release\real_detection_engine.exe"
```

### 方案 4：重新簽名（進階）
如果上述方法無效，可以考慮：
1. 使用開發者憑證重新簽名
2. 修改程式碼減少觸發安全軟體的行為
3. 使用虛擬機器進行測試

## 驗證方法
執行以下命令確認檢測引擎功能：
```powershell
.\build\src\Release\attack_simulator.exe
.\build\src\Release\real_detection_engine.exe
```

## 注意事項
- 此專案為安全研究用途，包含記憶體掃描和程序操作
- 建議在隔離環境中測試
- 如持續被阻擋，可考慮使用虛擬機器 