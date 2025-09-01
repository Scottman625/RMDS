#include "../include/crash_handler.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <filesystem>

#ifdef _MSC_VER
#pragma comment(lib, "dbghelp.lib")
#endif

namespace RealMemoryDetection {

// 靜態成員初始化
std::string CrashHandler::dump_path_ = "dumps";
PVOID CrashHandler::vectored_handler_ = nullptr;
bool CrashHandler::initialized_ = false;

void CrashHandler::Initialize() {
    if (initialized_) return;
    
    // 創建 dump 目錄
    std::filesystem::create_directories(dump_path_);
    
    // 初始化 DbgHelp
    SymInitialize(GetCurrentProcess(), nullptr, TRUE);
    
    // 設置符號搜索路徑
    SymSetSearchPath(GetCurrentProcess(), "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
    
    // 安裝 Vectored Exception Handler
    vectored_handler_ = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    
    // 設置未處理異常過濾器
    SetUnhandledExceptionFilter(reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(UnhandledExceptionFilter));
    
    initialized_ = true;
    
    std::cout << "[CrashHandler] 崩潰處理器已初始化" << std::endl;
    std::cout << "[CrashHandler] Dump 路徑: " << dump_path_ << std::endl;
}

void CrashHandler::Cleanup() {
    if (!initialized_) return;
    
    if (vectored_handler_) {
        RemoveVectoredExceptionHandler(vectored_handler_);
        vectored_handler_ = nullptr;
    }
    
    SymCleanup(GetCurrentProcess());
    initialized_ = false;
    
    std::cout << "[CrashHandler] 崩潰處理器已清理" << std::endl;
}

void CrashHandler::SetDumpPath(const std::string& path) {
    dump_path_ = path;
    std::filesystem::create_directories(dump_path_);
}

LONG WINAPI CrashHandler::VectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo) {
    std::cout << "\n[CRASH] 檢測到異常！" << std::endl;
    
    DWORD exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID exceptionAddress = exceptionInfo->ExceptionRecord->ExceptionAddress;
    
    std::cout << GetExceptionInfo(exceptionCode, exceptionAddress) << std::endl;
    std::cout << "調用棧:" << std::endl;
    std::cout << GetCallStack() << std::endl;
    
    // 生成 dump 文件
    GenerateMiniDump();
    
    // 返回 EXCEPTION_CONTINUE_SEARCH 讓其他處理器處理
    return EXCEPTION_CONTINUE_SEARCH;
}

void WINAPI CrashHandler::UnhandledExceptionFilter(PEXCEPTION_POINTERS exceptionInfo) {
    std::cout << "\n[FATAL CRASH] 未處理的異常！" << std::endl;
    
    DWORD exceptionCode = exceptionInfo->ExceptionRecord->ExceptionCode;
    PVOID exceptionAddress = exceptionInfo->ExceptionRecord->ExceptionAddress;
    
    std::cout << GetExceptionInfo(exceptionCode, exceptionAddress) << std::endl;
    std::cout << "調用棧:" << std::endl;
    std::cout << GetCallStack() << std::endl;
    
    // 生成 dump 文件
    GenerateMiniDump();
    
    // 顯示錯誤對話框
    std::stringstream ss;
    ss << "程式發生嚴重錯誤！\n\n";
    ss << "異常代碼: 0x" << std::hex << exceptionCode << std::dec << "\n";
    ss << "異常地址: 0x" << std::hex << reinterpret_cast<uintptr_t>(exceptionAddress) << std::dec << "\n\n";
    ss << "Dump 文件已保存到: " << dump_path_ << "\n\n";
    ss << "請將 dump 文件提供給開發者進行分析。";
    
    MessageBoxA(nullptr, ss.str().c_str(), "Real Memory Detection Engine - 嚴重錯誤", 
                MB_OK | MB_ICONERROR | MB_TOPMOST);
    
    ExitProcess(1);
}

std::string CrashHandler::GetExceptionInfo(DWORD exceptionCode, PVOID exceptionAddress) {
    std::stringstream ss;
    
    ss << "異常代碼: 0x" << std::hex << exceptionCode << std::dec << " (";
    
    switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:
            ss << "ACCESS_VIOLATION";
            break;
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            ss << "ARRAY_BOUNDS_EXCEEDED";
            break;
        case EXCEPTION_BREAKPOINT:
            ss << "BREAKPOINT";
            break;
        case EXCEPTION_DATATYPE_MISALIGNMENT:
            ss << "DATATYPE_MISALIGNMENT";
            break;
        case EXCEPTION_FLT_DENORMAL_OPERAND:
            ss << "FLT_DENORMAL_OPERAND";
            break;
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
            ss << "FLT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_FLT_INEXACT_RESULT:
            ss << "FLT_INEXACT_RESULT";
            break;
        case EXCEPTION_FLT_INVALID_OPERATION:
            ss << "FLT_INVALID_OPERATION";
            break;
        case EXCEPTION_FLT_OVERFLOW:
            ss << "FLT_OVERFLOW";
            break;
        case EXCEPTION_FLT_STACK_CHECK:
            ss << "FLT_STACK_CHECK";
            break;
        case EXCEPTION_FLT_UNDERFLOW:
            ss << "FLT_UNDERFLOW";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION:
            ss << "ILLEGAL_INSTRUCTION";
            break;
        case EXCEPTION_IN_PAGE_ERROR:
            ss << "IN_PAGE_ERROR";
            break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
            ss << "INT_DIVIDE_BY_ZERO";
            break;
        case EXCEPTION_INT_OVERFLOW:
            ss << "INT_OVERFLOW";
            break;
        case EXCEPTION_INVALID_DISPOSITION:
            ss << "INVALID_DISPOSITION";
            break;
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            ss << "NONCONTINUABLE_EXCEPTION";
            break;
        case EXCEPTION_PRIV_INSTRUCTION:
            ss << "PRIV_INSTRUCTION";
            break;
        case EXCEPTION_SINGLE_STEP:
            ss << "SINGLE_STEP";
            break;
        case EXCEPTION_STACK_OVERFLOW:
            ss << "STACK_OVERFLOW";
            break;
        default:
            ss << "UNKNOWN";
            break;
    }
    
    ss << ")\n";
    ss << "異常地址: 0x" << std::hex << reinterpret_cast<uintptr_t>(exceptionAddress) << std::dec;
    
    return ss.str();
}

std::string CrashHandler::GetCallStack() {
    std::stringstream ss;
    
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();
    
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);
    
    STACKFRAME64 frame;
    ZeroMemory(&frame, sizeof(frame));
    
#ifdef _WIN64
    frame.AddrPC.Offset = context.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;
#else
    frame.AddrPC.Offset = context.Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = context.Esp;
    frame.AddrStack.Mode = AddrModeFlat;
#endif
    
    SymbolInfo symbol_info;
    ZeroMemory(&symbol_info, sizeof(symbol_info));
    symbol_info.symbol_info.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol_info.symbol_info.MaxNameLen = sizeof(symbol_info.name_buffer) - 1;
    
    DWORD displacement;
    IMAGEHLP_LINE64 line;
    ZeroMemory(&line, sizeof(line));
    line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    
    int frame_count = 0;
    const int max_frames = 50;
    
    while (StackWalk64(
#ifdef _WIN64
        IMAGE_FILE_MACHINE_AMD64,
#else
        IMAGE_FILE_MACHINE_I386,
#endif
        process, thread, &frame, &context, nullptr, 
        SymFunctionTableAccess64, SymGetModuleBase64, nullptr) && frame_count < max_frames) {
        
        ss << "  #" << frame_count << " ";
        
        if (SymFromAddr(process, frame.AddrPC.Offset, nullptr, &symbol_info.symbol_info)) {
            ss << symbol_info.symbol_info.Name;
        } else {
            ss << "0x" << std::hex << frame.AddrPC.Offset << std::dec;
        }
        
        if (SymGetLineFromAddr64(process, frame.AddrPC.Offset, &displacement, &line)) {
            ss << " (" << line.FileName << ":" << line.LineNumber << ")";
        }
        
        ss << "\n";
        frame_count++;
    }
    
    return ss.str();
}

bool CrashHandler::GenerateMiniDump(const std::string& filename) {
    if (!initialized_) return false;
    
    std::string dump_filename;
    if (filename.empty()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << dump_path_ << "/crash_" << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S") << ".dmp";
        dump_filename = ss.str();
    } else {
        dump_filename = dump_path_ + "/" + filename;
    }
    
    HANDLE file = CreateFileA(dump_filename.c_str(), GENERIC_WRITE, 0, nullptr, 
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        std::cerr << "[CrashHandler] 無法創建 dump 文件: " << dump_filename << std::endl;
        return false;
    }
    
    MINIDUMP_EXCEPTION_INFORMATION exception_info;
    exception_info.ThreadId = GetCurrentThreadId();
    exception_info.ExceptionPointers = nullptr;
    exception_info.ClientPointers = FALSE;
    
    bool success = MiniDumpWriteDump(
        GetCurrentProcess(),
        GetCurrentProcessId(),
        file,
        static_cast<MINIDUMP_TYPE>(MiniDumpNormal | MiniDumpWithFullMemory | MiniDumpWithDataSegs | 
        MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo),
        &exception_info,
        nullptr,
        nullptr
    );
    
    CloseHandle(file);
    
    if (success) {
        std::cout << "[CrashHandler] Dump 文件已保存: " << dump_filename << std::endl;
    } else {
        std::cerr << "[CrashHandler] 生成 dump 文件失敗: " << GetLastError() << std::endl;
    }
    
    return success;
}

// 全局實例
CrashHandler g_crash_handler;

} // namespace RealMemoryDetection
