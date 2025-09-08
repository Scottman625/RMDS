#pragma once
#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>

namespace RealMemoryDetection {

class CrashHandler {
public:
    static void Initialize();
    static void Cleanup();
    
    // 設置 dump 文件路徑
    static void SetDumpPath(const std::string& path);
    
    // 手動生成 dump
    static bool GenerateMiniDump(const std::string& filename = "");
    
    // 獲取當前調用棧
    static std::string GetCallStack();
    
    // 獲取異常信息
    static std::string GetExceptionInfo(DWORD exceptionCode, PVOID exceptionAddress);

private:
    static LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo);
    static void WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS exceptionInfo);
    
    static std::string dump_path_;
    static PVOID vectored_handler_;
    static bool initialized_;
    
    // 符號信息結構
    struct SymbolInfo {
        SYMBOL_INFO symbol_info;
        char name_buffer[256];
    };
};

// 全局崩潰處理器實例
extern CrashHandler g_crash_handler;

// 便捷函數
inline void InitializeCrashHandler() { CrashHandler::Initialize(); }
inline void CleanupCrashHandler() { CrashHandler::Cleanup(); }
inline bool GenerateCrashDump(const std::string& filename = "") { return CrashHandler::GenerateMiniDump(filename); }

} // namespace RealMemoryDetection
