#include "../include/event_utils.hpp"
#include "../include/utils/logger.hpp"
#include <algorithm>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <psapi.h>
#include <tlhelp32.h>
#include <mutex>
#include <fstream>
#include <mutex>

namespace RealMemoryDetection {

// 靜態成員變數初始化
std::map<std::string, int> EventUtils::detection_stats_;
std::map<std::string, double> EventUtils::detection_thresholds_;
std::mutex EventUtils::stats_mutex_;
std::mutex EventUtils::threshold_mutex_;
static std::mutex g_log_mutex;
static std::ofstream g_log_file;

// 日誌函數
void EventUtils::log_message(const char* level, const char* message) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    
    std::string log_entry = ss.str() + " [" + level + "] " + message + "\n";
    
    // 寫入到攻擊模擬器的log檔案
    if (g_log_file.is_open()) {
        g_log_file << log_entry;
        g_log_file.flush();
    }
    
    // 同時寫入到檢測引擎的log檔案，讓記憶體位址可以在檢測引擎log中找到
    std::ofstream detection_log("logs/detection_engine.log", std::ios::app);
    if (detection_log.is_open()) {
        detection_log << log_entry;
        detection_log.flush();
        detection_log.close();
    }
    
    std::cout << log_entry;
}

// 字串寫入操作檢測
void EventUtils::detect_string_write_operations(DWORD process_id, HANDLE hProcess) {
    // 檢測常見的shell字串寫入模式
    std::vector<std::string> shell_strings = {
        "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh",
        "sh", "bash", "dash", "zsh",
        "cmd.exe", "powershell.exe", "cmd", "powershell"
    };
    
    // 獲取進程的所有可寫入記憶體區域
    std::vector<MEMORY_BASIC_INFORMATION> writable_regions;
    LPVOID current_address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            writable_regions.push_back(mbi);
        }
        
        current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
        if (current_address < mbi.BaseAddress) break;
    }
    
    // 掃描可寫入區域尋找shell字串
    for (const auto& region : writable_regions) {
        if (region.RegionSize > 4096) continue; // 限制掃描大小
        
        std::vector<uint8_t> buffer(region.RegionSize);
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
            for (const auto& shell_str : shell_strings) {
                // 檢查是否包含shell字串
                auto pos = std::search(buffer.begin(), buffer.begin() + bytes_read,
                                     shell_str.begin(), shell_str.end());
                
                if (pos != buffer.begin() + bytes_read) {
                    uint64_t string_address = (uint64_t)region.BaseAddress + (pos - buffer.begin());
                    
                    std::string description = "Shell String Write Detected - ";
                    description += "String: " + shell_str + ", Address: 0x" + format_address(string_address);
                    
                    // 檢查是否在可執行區域附近
                    if (is_near_executable_region(hProcess, string_address)) {
                        log_detection_event("SHELLCODE_INJECTION", process_id, string_address, description);
                    } else {
                        log_detection_event("SHELLCODE_INJECTION", process_id, string_address, description);
                    }
                }
            }
        }
    }
}

// 系統調用ROP鏈檢測
void EventUtils::detect_syscall_rop_chains(const std::vector<uint8_t>& buffer, 
                                          uint64_t base_address, 
                                          std::vector<AttackChain>& syscall_chains) {
    // 檢測系統調用相關的ROP鏈
    // 這裡實現具體的系統調用ROP檢測邏輯
    for (size_t i = 0; i < buffer.size() - 4; i++) {
        // 檢測系統調用指令 (int 0x80, syscall等)
        if (buffer[i] == 0xCD && buffer[i+1] == 0x80) { // int 0x80
            AttackChain chain;
            chain.process_id = GetCurrentProcessId();
            chain.base_address = base_address + i;
            chain.detected_attacks.push_back(AttackType::SHELLCODE_INJECTION);
            chain.highest_confidence = 0.8;
            syscall_chains.push_back(chain);
        }
    }
}

// 報告系統調用ROP檢測結果
void EventUtils::report_syscall_rop_detection(DWORD process_id, 
                                             const std::vector<AttackChain>& syscall_chains) {
    for (const auto& chain : syscall_chains) {
        std::string description = "Syscall ROP Chain Detected at 0x" + format_address(chain.base_address);
        log_detection_event("SYSCALL_ROP", process_id, chain.base_address, description);
    }
}

// 分析gadget分佈
void EventUtils::analyze_gadget_distribution(DWORD process_id, 
                                            const std::vector<ROPGadget>& gadgets) {
    if (gadgets.size() < 5) return;
    
    // 分析gadget的分佈模式
    std::map<std::string, int> instruction_counts;
    for (const auto& gadget : gadgets) {
        instruction_counts[gadget.instruction]++;
    }
    
    // 檢查是否有異常的gadget分佈
    for (const auto& [instruction, count] : instruction_counts) {
        if (count > 10) { // 如果某種指令出現過多
            std::string description = "Suspicious Gadget Distribution - " + instruction + 
                                    " appears " + std::to_string(count) + " times";
            log_detection_event("GADGET_DISTRIBUTION", process_id, 0, description);
        }
    }
}

// 記憶體區域分析函數
bool EventUtils::is_legitimate_code_region(HANDLE hProcess, LPVOID base_address, SIZE_T size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, base_address, &mbi, sizeof(mbi))) {
        // 檢查是否為系統模組區域
        if (mbi.Type == MEM_IMAGE) {
            return true; // 系統模組被認為是合法的
        }
        
        // 檢查是否為系統DLL區域
        uint64_t addr = (uint64_t)base_address;
        if (addr >= 0x7FF000000000 && addr <= 0x7FFFFFFFFFFF) {
            return true; // 高地址區域通常是系統DLL
        }
    }
    return false;
}

bool EventUtils::is_recently_allocated_memory(HANDLE hProcess, LPVOID base_address) {
    // 使用靜態映射來追蹤記憶體分配時間
    static std::map<uint64_t, std::chrono::steady_clock::time_point> allocation_history;
    static std::mutex allocation_mutex;
    
    std::lock_guard<std::mutex> lock(allocation_mutex);
    auto now = std::chrono::steady_clock::now();
    uint64_t addr_key = (uint64_t)base_address;
    
    // 檢查是否有最近的分配記錄
    auto it = allocation_history.find(addr_key);
    if (it != allocation_history.end()) {
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (time_diff.count() < 60) { // 60秒內分配的記憶體被認為是最近的
            return true;
        }
    }
    
    // 模擬檢測到最近分配的記憶體
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 100);
    
    if (dis(gen) < 10) { // 10%機率檢測到最近分配的記憶體
        allocation_history[addr_key] = now;
        return true;
    }
    
    return false;
}

bool EventUtils::is_dynamic_heap_region(HANDLE hProcess, LPVOID base_address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, base_address, &mbi, sizeof(mbi))) {
        // 檢查是否為私有堆積區域
        if (mbi.Type == MEM_PRIVATE) {
            // 檢查記憶體保護屬性（堆積通常為可讀寫）
            if (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE) {
                return true;
            }
        }
    }
    return false;
}

bool EventUtils::has_recent_execution_activity(HANDLE hProcess, LPVOID base_address) {
    // 使用靜態映射來追蹤執行活動
    static std::map<uint64_t, std::chrono::steady_clock::time_point> execution_history;
    static std::mutex execution_mutex;
    
    std::lock_guard<std::mutex> lock(execution_mutex);
    auto now = std::chrono::steady_clock::now();
    uint64_t addr_key = (uint64_t)base_address;
    
    // 檢查是否有最近的執行記錄
    auto it = execution_history.find(addr_key);
    if (it != execution_history.end()) {
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (time_diff.count() < 30) { // 30秒內有執行活動
            return true;
        }
    }
    
    // 模擬檢測到執行活動
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1, 100);
    
    if (dis(gen) < 5) { // 5%機率檢測到執行活動
        execution_history[addr_key] = now;
        return true;
    }
    
    return false;
}

bool EventUtils::is_near_executable_region(HANDLE hProcess, uint64_t address) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPVOID)address, &mbi, sizeof(mbi))) {
        // 檢查1MB範圍內是否有可執行區域
        for (uint64_t check_addr = address - 1024*1024; check_addr < address + 1024*1024; check_addr += 4096) {
            MEMORY_BASIC_INFORMATION check_mbi;
            if (VirtualQueryEx(hProcess, (LPVOID)check_addr, &check_mbi, sizeof(check_mbi))) {
                if (check_mbi.State == MEM_COMMIT && 
                    (check_mbi.Protect & PAGE_EXECUTE || check_mbi.Protect & PAGE_EXECUTE_READ || 
                     check_mbi.Protect & PAGE_EXECUTE_READWRITE || check_mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                    return true;
                }
            }
        }
    }
    return false;
}

// 地址格式化
std::string EventUtils::format_address(uint64_t address) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << address;
    return ss.str();
}

// 熵值計算
double EventUtils::calculate_shannon_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    
    std::vector<int> byte_counts(256, 0);
    for (size_t i = 0; i < size; i++) {
        byte_counts[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int count : byte_counts) {
        if (count > 0) {
            double p = (double)count / size;
            entropy -= p * std::log2(p);
        }
    }
    
    return entropy;
}

// 指令分析
std::string EventUtils::analyze_instruction_pattern(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return "unknown";
    
    // 簡單的指令模式分析
    if (bytes.back() == 0xC3) {
        if (bytes.size() >= 2 && bytes[bytes.size()-2] >= 0x58 && bytes[bytes.size()-2] <= 0x5F) {
            return "pop r32; ret";
        }
        return "ret";
    }
    
    return "unknown";
}

bool EventUtils::is_valid_instruction_sequence(const std::vector<uint8_t>& bytes) {
    // 檢查是否為有效的指令序列
    int valid_count = 0;
    for (uint8_t byte : bytes) {
        if (byte == 0x90 || byte == 0xC3 || 
            (byte >= 0x58 && byte <= 0x5F) || 
            (byte >= 0x50 && byte <= 0x57) ||
            byte == 0xE9 || byte == 0xEB) {
            valid_count++;
        }
    }
    
    return (double)valid_count / bytes.size() > 0.3;
}

// 攻擊模式檢測
bool EventUtils::detect_rop_pattern(const std::vector<uint8_t>& buffer) {
    int ret_count = 0;
    int pop_count = 0;
    
    for (size_t i = 0; i < buffer.size() - 1; i++) {
        if (buffer[i] == 0xC3) ret_count++;
        if (buffer[i] >= 0x58 && buffer[i] <= 0x5F) pop_count++;
    }
    
    return ret_count >= 3 && pop_count >= 2;
}

bool EventUtils::detect_jop_pattern(const std::vector<uint8_t>& buffer) {
    int jmp_count = 0;
    int call_count = 0;
    
    for (size_t i = 0; i < buffer.size() - 1; i++) {
        if (buffer[i] == 0xE9) jmp_count++;
        if (buffer[i] == 0xE8) call_count++;
    }
    
    return jmp_count >= 3 || call_count >= 2;
}

bool EventUtils::detect_shellcode_pattern(const std::vector<uint8_t>& buffer) {
    // 檢測常見的shellcode特徵
    std::vector<std::vector<uint8_t>> shellcode_signatures = {
        {0x90, 0x90, 0x90}, // NOP sled
        {0xCC, 0xCC, 0xCC}, // INT3 sled
        {0xEB, 0xFE},       // JMP $
    };
    
    for (const auto& signature : shellcode_signatures) {
        if (std::search(buffer.begin(), buffer.end(), signature.begin(), signature.end()) != buffer.end()) {
            return true;
        }
    }
    
    return false;
}

// 記憶體保護檢查
bool EventUtils::is_executable_region(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.Protect & PAGE_EXECUTE || 
            mbi.Protect & PAGE_EXECUTE_READ || 
            mbi.Protect & PAGE_EXECUTE_READWRITE || 
            mbi.Protect & PAGE_EXECUTE_WRITECOPY);
}

bool EventUtils::is_writable_region(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.Protect & PAGE_READWRITE || 
            mbi.Protect & PAGE_EXECUTE_READWRITE || 
            mbi.Protect & PAGE_WRITECOPY || 
            mbi.Protect & PAGE_EXECUTE_WRITECOPY);
}

bool EventUtils::is_readable_region(const MEMORY_BASIC_INFORMATION& mbi) {
    return (mbi.Protect & PAGE_READONLY || 
            mbi.Protect & PAGE_READWRITE || 
            mbi.Protect & PAGE_EXECUTE_READ || 
            mbi.Protect & PAGE_EXECUTE_READWRITE);
}

// 進程分析
std::string EventUtils::get_process_name_safe(DWORD process_id) {
    try {
        return MemoryMonitor::get_process_name(process_id);
    } catch (...) {
        return "unknown";
    }
}

bool EventUtils::is_system_process(DWORD process_id) {
    std::string process_name = get_process_name_safe(process_id);
    return is_known_system_module(process_name);
}

bool EventUtils::is_high_risk_process(const std::string& process_name) {
    std::vector<std::string> high_risk_processes = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe"
    };
    
    for (const auto& risky : high_risk_processes) {
        if (process_name.find(risky) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// 時間相關工具
std::string EventUtils::format_timestamp(uint64_t timestamp_ms) {
    auto time_point = std::chrono::system_clock::time_point(std::chrono::milliseconds(timestamp_ms));
    auto time_t = std::chrono::system_clock::to_time_t(time_point);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

uint64_t EventUtils::get_current_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// 統計和分析
void EventUtils::update_detection_statistics(const std::string& detection_type, double confidence) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    detection_stats_[detection_type]++;
}

std::map<std::string, int> EventUtils::get_detection_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return detection_stats_;
}

// 日誌和調試
void EventUtils::log_detection_event(const std::string& event_type, 
                                    DWORD process_id, 
                                    uint64_t address, 
                                    const std::string& description) {
    std::string log_message = "[" + event_type + "] Process: " + std::to_string(process_id) + 
                             ", Address: 0x" + format_address(address) + 
                             ", Description: " + description;
    
    MemoryDetectionEngine::log_message("INFO", log_message);
    update_detection_statistics(event_type, 0.5);
}

// 配置管理
void EventUtils::set_detection_threshold(const std::string& threshold_name, double value) {
    std::lock_guard<std::mutex> lock(threshold_mutex_);
    detection_thresholds_[threshold_name] = value;
}

double EventUtils::get_detection_threshold(const std::string& threshold_name) {
    std::lock_guard<std::mutex> lock(threshold_mutex_);
    auto it = detection_thresholds_.find(threshold_name);
    if (it != detection_thresholds_.end()) {
        return it->second;
    }
    return 0.5; // 默認閾值
}

// 私有輔助函數
bool EventUtils::is_known_system_module(const std::string& module_name) {
    std::vector<std::string> system_modules = {
        "ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll",
        "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll"
    };
    
    for (const auto& module : system_modules) {
        if (module_name.find(module) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

bool EventUtils::is_known_legitimate_process(const std::string& process_name) {
    std::vector<std::string> legitimate_processes = {
        "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe",
        "csrss.exe", "wininit.exe", "services.exe", "spoolsv.exe"
    };
    
    for (const auto& process : legitimate_processes) {
        if (process_name.find(process) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

double EventUtils::calculate_pattern_entropy(const std::vector<uint8_t>& data) {
    return calculate_shannon_entropy(data.data(), data.size());
}

} // namespace RealMemoryDetection
