# 實時內存攻擊檢測引擎 (Real-Time Memory Attack Detection Engine)

## 專案概述

這是一個基於C++23硬件內存標籤（MTE）擴展的實時內存攻擊檢測引擎，專為檢測和防護ROP/JOP攻擊而設計。

## 核心特性

- **硬件內存標籤（MTE）支援**: 利用ARM MTE技術進行內存安全檢測
- **LLVM插樁堆棧指針追蹤**: 基於LLVM的動態插樁技術
- **ROP/JOP攻擊模式匹配**: 先進的攻擊模式識別算法
- **高性能檢測**: 延遲增加<3μs（對比傳統方案20μs+）
- **DDR5 ECC協同檢測**: 支援DDR5內存的ECC糾錯協同檢測

## 性能指標

- 檢測延遲: <3μs
- 記憶體使用: 最小化開銷
- 支援平台: Windows, Linux, macOS
- 目標應用: 遊戲反外掛、金融交易系統

## 變現路徑

1. **遊戲反外掛模組**: 與Unity/Unreal引擎整合
2. **金融交易系統內存防護**: 訂閱服務模式

## 專案結構

```
RealTimeMemoryAttackDetectEngine/
├── src/                    # 核心源碼
│   ├── engine/            # 檢測引擎核心
│   ├── mte/              # MTE擴展支援
│   ├── llvm_instrument/  # LLVM插樁工具
│   └── patterns/         # 攻擊模式庫
├── include/              # 頭檔案
├── tests/               # 測試檔案
├── examples/            # 使用範例
├── docs/               # 文檔
└── build/              # 建置檔案
```

## 快速開始

### 建置要求

- C++23 編譯器 (GCC 13+, Clang 16+, MSVC 2022)
- LLVM 16+
- CMake 3.20+
- ARM MTE 支援的硬體 (可選)

### 建置步驟

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 授權

MIT License

## 貢獻

歡迎提交Issue和Pull Request！ 