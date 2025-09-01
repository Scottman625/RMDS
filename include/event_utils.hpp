#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <random>
#include "memory_detection_types.hpp"
#include "memory_detection_monitor.hpp"

namespace RealMemoryDetection {

// 事件工具函數類別
class EventUtils {
public:
    static void log_message(const char* level, const char* message);
    // 字串寫入操作檢測
    static void detect_string_write_operations(DWORD process_id, HANDLE hProcess);
    
    // 系統調用ROP鏈檢測
    static void detect_syscall_rop_chains(const std::vector<uint8_t>& buffer, 
                                         uint64_t base_address, 
                                         std::vector<AttackChain>& syscall_chains);
    
    // 報告系統調用ROP檢測結果
    static void report_syscall_rop_detection(DWORD process_id, 
                                            const std::vector<AttackChain>& syscall_chains);
    
    // 分析gadget分佈
    static void analyze_gadget_distribution(DWORD process_id, 
                                           const std::vector<ROPGadget>& gadgets);
    
    // 記憶體區域分析
    static bool is_legitimate_code_region(HANDLE hProcess, LPVOID base_address, SIZE_T region_size);
    static bool is_recently_allocated_memory(HANDLE hProcess, LPVOID base_address);
    static bool is_dynamic_heap_region(HANDLE hProcess, LPVOID base_address);
    static bool has_recent_execution_activity(HANDLE hProcess, LPVOID base_address);
    static bool is_near_executable_region(HANDLE hProcess, uint64_t address);
    
    // 地址格式化
    static std::string format_address(uint64_t address);
    
    // 熵值計算
    static double calculate_shannon_entropy(const uint8_t* data, size_t size);
    
    // 指令分析
    static std::string analyze_instruction_pattern(const std::vector<uint8_t>& bytes);
    static bool is_valid_instruction_sequence(const std::vector<uint8_t>& bytes);
    
    // 攻擊模式檢測
    static bool detect_rop_pattern(const std::vector<uint8_t>& buffer);
    static bool detect_jop_pattern(const std::vector<uint8_t>& buffer);
    static bool detect_shellcode_pattern(const std::vector<uint8_t>& buffer);
    
    // 記憶體保護檢查
    static bool is_executable_region(const MEMORY_BASIC_INFORMATION& mbi);
    static bool is_writable_region(const MEMORY_BASIC_INFORMATION& mbi);
    static bool is_readable_region(const MEMORY_BASIC_INFORMATION& mbi);
    
    // 進程分析
    static std::string get_process_name_safe(DWORD process_id);
    static bool is_system_process(DWORD process_id);
    static bool is_high_risk_process(const std::string& process_name);
    
    // 時間相關工具
    static std::string format_timestamp(uint64_t timestamp_ms);
    static uint64_t get_current_timestamp_ms();
    static uint64_t now_ms() { return get_current_timestamp_ms(); } // 別名函數
    
    // 統計和分析
    static void update_detection_statistics(const std::string& detection_type, double confidence);
    static std::map<std::string, int> get_detection_statistics();
    
    // 日誌和調試
    static void log_detection_event(const std::string& event_type, 
                                   DWORD process_id, 
                                   uint64_t address, 
                                   const std::string& description);
    
    // 配置管理
    static void set_detection_threshold(const std::string& threshold_name, double value);
    static double get_detection_threshold(const std::string& threshold_name);

private:
    // 靜態成員變數用於統計和配置
    static std::map<std::string, int> detection_stats_;
    static std::map<std::string, double> detection_thresholds_;
    static std::mutex stats_mutex_;
    static std::mutex threshold_mutex_;
    
    // 內部輔助函數
    static bool is_known_system_module(const std::string& module_name);
    static bool is_known_legitimate_process(const std::string& process_name);
    static double calculate_pattern_entropy(const std::vector<uint8_t>& data);
};

} // namespace RealMemoryDetection
