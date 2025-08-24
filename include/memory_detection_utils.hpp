#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <fstream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include "memory_detection_types.hpp"

namespace RealMemoryDetection {

// 檢測工具類
class DetectionUtils {
public:
    // 將攻擊類型轉換為字符串
    static std::string attack_type_to_string(AttackType type);
    
    // 獲取進程名稱
    static std::string get_process_name(DWORD process_id);
    
    // 格式化地址
    static std::string format_address(uint64_t address);
    
    // 檢測ROP/JOP gadgets
    static bool is_rop_jop_gadget(BYTE* code, SIZE_T size);
    
    // 檢測shellcode簽名
    static bool is_shellcode_signature(BYTE* data, SIZE_T size);
    
    // 檢測API hook
    static bool is_api_hooked(LPVOID function_address);
    
    // 檢查記憶體保護
    static bool is_executable_memory(LPVOID address, SIZE_T size);
    
    // 檢查記憶體是否可讀
    static bool is_readable_memory(LPVOID address, SIZE_T size);
    
    // 檢查記憶體是否有效
    static bool is_valid_address(LPVOID address);
    
    // 獲取記憶體保護屬性
    static DWORD get_memory_protection(LPVOID address);
    
    // 獲取時間戳
    static std::string get_timestamp();
    
    // 計算校驗和
    static uint32_t calculate_checksum(BYTE* data, SIZE_T size);
    
    // 格式化記憶體大小
    static std::string format_memory_size(SIZE_T size);
    
    // 檢查堆是否損壞
    static bool is_heap_corrupted();
    
    // 檢查堆疊是否損壞
    static bool is_stack_corrupted();
};

class Logger {
private:
    std::ofstream log_file_;
    std::mutex log_mutex_;
    int log_level_;

public:
    explicit Logger(const std::string& log_file = "logs/detection_engine.log", int level = 1);
    ~Logger();
    
    void log(const std::string& level, const std::string& message);
    void set_log_level(int level);
    
    // 便捷日誌方法
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void debug(const std::string& message);
};

} // namespace RealMemoryDetection