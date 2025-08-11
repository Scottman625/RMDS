#include "../include/memory_detection_utils.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <Psapi.h>
#include <TlHelp32.h>

namespace RealMemoryDetection {

// 檢測工具類實現
std::string DetectionUtils::attack_type_to_string(AttackType type) {
    switch (type) {
        case AttackType::ROP_CHAIN:
            return "ROP Chain";
        case AttackType::JOP_CHAIN:
            return "JOP Chain";
        case AttackType::BUFFER_OVERFLOW:
            return "Buffer Overflow";
        case AttackType::HEAP_CORRUPTION:
            return "Heap Corruption";
        case AttackType::STACK_OVERFLOW:
            return "Stack Overflow";
        case AttackType::USE_AFTER_FREE:
            return "Use-After-Free";
        case AttackType::SHELLCODE_INJECTION:
            return "Shellcode Injection";
        case AttackType::API_HOOK:
            return "API Hook";
        case AttackType::MEMORY_CORRUPTION:
            return "Memory Corruption";
        default:
            return "Unknown";
    }
}

std::string DetectionUtils::get_process_name(DWORD process_id) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
    if (!hProcess) {
        return "Unknown";
    }

    char process_name[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, process_name, &size)) {
        CloseHandle(hProcess);
        return std::string(process_name);
    }

    CloseHandle(hProcess);
    return "Unknown";
}

std::string DetectionUtils::format_address(uint64_t address) {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << address;
    return ss.str();
}

bool DetectionUtils::is_rop_jop_gadget(BYTE* code, SIZE_T size) {
    if (!code || size < 1) {
        return false;
    }

    // 檢查常見的ROP/JOP gadgets
    for (SIZE_T i = 0; i < size - 1; i++) {
        // ret指令 (0xC3)
        if (code[i] == 0xC3) {
            return true;
        }
        // pop rsp; ret (0x5C 0xC3)
        if (i < size - 2 && code[i] == 0x5C && code[i + 1] == 0xC3) {
            return true;
        }
        // jmp rax (0xFF 0xE0)
        if (i < size - 2 && code[i] == 0xFF && code[i + 1] == 0xE0) {
            return true;
        }
    }

    return false;
}

bool DetectionUtils::is_shellcode_signature(BYTE* data, SIZE_T size) {
    if (!data || size < 4) {
        return false;
    }

    // 檢查常見的shellcode特徵
    for (SIZE_T i = 0; i < size - 3; i++) {
        // 檢查Windows API調用特徵
        if (data[i] == 0x68 && data[i + 1] == 0x00 && data[i + 2] == 0x00 && data[i + 3] == 0x00) {
            return true;
        }
        // 檢查系統調用特徵
        if (data[i] == 0xCD && data[i + 1] == 0x80) {
            return true;
        }
    }

    return false;
}

bool DetectionUtils::is_api_hooked(LPVOID function_address) {
    if (!function_address) {
        return false;
    }

    // 檢查函數開頭是否被修改
    BYTE* code = (BYTE*)function_address;
    
    // 檢查是否為跳轉指令
    if (code[0] == 0xE9 || code[0] == 0xFF) {
        return true;
    }

    return false;
}

std::string DetectionUtils::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    
    return ss.str();
}

} // namespace RealMemoryDetection 