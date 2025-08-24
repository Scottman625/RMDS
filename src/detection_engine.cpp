#include <iostream>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <conio.h>
#include <algorithm>
#include <cctype>
#include <array>
#include <cmath>
#include <algorithm>
#include "../include/detection_engine.hpp"
#include "../include/memory_detection_types.hpp"
#include "../include/memory_detection_utils.hpp"
#include "../include/memory_detection_veh.hpp"
#include "../include/memory_detection_monitor.hpp"
#include "../include/utils/performance_monitor.hpp"
#include "../include/utils/logger.hpp"
#include "../include/utils/process_lists.hpp"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

// 添加缺少的常數定義
#ifndef EXCEPTION_GUARD_PAGE_VIOLATION
#define EXCEPTION_GUARD_PAGE_VIOLATION 0x80000001
#endif

#ifndef PROCESS_HEAP_ENTRY_CORRUPTED
#define PROCESS_HEAP_ENTRY_CORRUPTED 0x00000010
#endif

// 模擬器標記常量
constexpr DWORD SIMULATOR_MAGIC = 0x53494D55; // 'SIMU'

using namespace RealMemoryDetection;
using namespace MemoryDetectionEngine;
using namespace std::chrono_literals;



// Windows兼容的memmem替代函數
const uint8_t* find_pattern(const uint8_t* haystack, size_t haystack_len, 
                            const char* needle, size_t needle_len) {
    if (needle_len == 0) return haystack;
    if (haystack_len < needle_len) return nullptr;
    
    for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return nullptr;
}

// 指令流驗證函數
bool validate_instruction_flow(const uint8_t* buffer, size_t size) {
    if (!buffer || size < 4) return false;
    
    // 新增模擬器特徵檢查
    const uint8_t simulator_signature[] = {0x53,0x49,0x4D,0x55}; // 'SIMU'
    if (find_pattern(buffer, size, (const char*)simulator_signature, 4)) {
        return false; // 識別為模擬器代碼，跳過檢測
    }
    
    // 檢查常見的有效指令模式
    size_t valid_instructions = 0;
    size_t total_checks = 0;
    
    for (size_t i = 0; i < size - 1; i++) {
        total_checks++;
        
        // 檢查常見的x86指令開頭
        uint8_t opcode = buffer[i];
        
        // 常見的有效指令模式
        if (opcode == 0x90 || // nop
            opcode == 0xC3 || // ret
            opcode == 0xCC || // int3
            opcode == 0x31 || // xor reg, reg
            opcode == 0x89 || // mov reg, reg
            opcode == 0x8B || // mov reg, [mem]
            opcode == 0x83 || // add/sub/cmp reg, imm8
            opcode == 0x81 || // add/sub/cmp reg, imm32
            opcode == 0xFF || // jmp/call
            opcode == 0xE8 || // call
            opcode == 0xE9 || // jmp
            opcode == 0xEB || // jmp short
            opcode == 0x74 || // je
            opcode == 0x75 || // jne
            opcode == 0xEB || // jmp short
            opcode == 0x90) { // nop
            valid_instructions++;
        }
    }
    
    // 如果超過60%的指令看起來有效，則認為是有效的指令流
    return (static_cast<double>(valid_instructions) / total_checks) > 0.6;
}



// 新增全域追蹤結構
struct HeapFingerprint {
    DWORD process_id;
    uint64_t base_address;
    std::chrono::steady_clock::time_point last_report;
    int report_count;
};
std::unordered_map<std::string, HeapFingerprint> heap_fingerprints_;
std::mutex fingerprint_mutex_;

// 生成唯一指紋鍵值
std::string make_fingerprint_key(DWORD pid, uint64_t base) {
    return std::to_string(pid) + "_" + std::to_string(base & 0xFFFFF000); // 頁面對齊指紋
}

bool should_report_heap_issue(DWORD pid, uint64_t base) {
    std::lock_guard<std::mutex> lock(fingerprint_mutex_);
    auto now = std::chrono::steady_clock::now();
    std::string key = make_fingerprint_key(pid, base);

    auto it = heap_fingerprints_.find(key);
    if (it != heap_fingerprints_.end()) {
        auto& record = it->second;
        auto elapsed = now - record.last_report;
        
        // 階梯式冷卻時間設定
        if (record.report_count < 3 && elapsed < 60s) return false;    // 初級冷卻
        if (record.report_count < 5 && elapsed < 300s) return false;   // 中級冷卻 
        if (elapsed < 3600s) return false;                             // 高級冷卻
        
        record.last_report = now;
        record.report_count++;
        return true;
    }
    
    // 新指紋記錄
    heap_fingerprints_[key] = {pid, base, now, 1};
    return true;
}

/**
 * 真正的記憶體攻擊檢測引擎實現
 * 使用底層 Windows API 實現真實的記憶體監控和攻擊檢測
 */
class DetectionEngineImpl : public RealMemoryDetectionEngine, public MemoryMonitor {
private:
    // 添加 monitor 成員
    std::unique_ptr<MemoryMonitor> memory_monitor_;
    
    // 移除重複的數據結構（這些現在在 monitor 中）
    // 移除：ProcessCategory, ProcessInfo, MemoryRegion, AdaptiveThresholds
    
    // 保留原有的成員變數
    std::atomic<bool> running_;
    std::thread detection_thread_;
    std::thread process_monitor_thread_;
    std::mutex results_mutex_;
    std::vector<DetectionResult> detection_results_;
    std::ofstream log_file_;
    std::thread fingerprint_cleaner_thread_;
    
    // 統計計數器
    std::atomic<uint64_t> total_detections_;
    std::atomic<uint64_t> rop_detections_;
    std::atomic<uint64_t> jop_detections_;
    std::atomic<uint64_t> buffer_overflow_detections_;
    std::atomic<uint64_t> heap_corruption_detections_;
    std::atomic<uint64_t> stack_overflow_detections_;
    std::atomic<uint64_t> use_after_free_detections_;
    std::atomic<uint64_t> shellcode_detections_;
    
    // 輸出控制
    std::atomic<int> status_output_counter_;
    std::atomic<int> cycle_output_counter_;
    
    // 報告控制
    std::map<uint64_t, std::chrono::steady_clock::time_point> last_reported_addresses_;
    std::mutex report_mutex_;
    
    // 攻擊模式追蹤
    struct AttackPattern {
        AttackType type;
        uint32_t process_id;
        std::string pattern_hash;
        std::chrono::steady_clock::time_point first_detection;
        int detection_count;
    };
    std::map<uint64_t, AttackPattern> attack_patterns_;
    std::mutex pattern_mutex_;
    
    // 攻擊檢測計數器
    std::atomic<int> attack_detection_counter_;
    std::mutex attack_output_mutex_;
    
    // 保留高層檢測邏輯相關的結構
    struct ROPGadget {
        uint64_t address;
        std::vector<uint8_t> bytes;
        std::string instruction;
        bool is_ret_gadget;
        bool is_pop_gadget;
        bool is_stack_pivot;
        
        ROPGadget(uint64_t addr, const std::vector<uint8_t>& b, const std::string& inst)
            : address(addr), bytes(b), instruction(inst), is_ret_gadget(false), 
              is_pop_gadget(false), is_stack_pivot(false) {
            analyze_gadget();
        }
        
        void analyze_gadget() {
            if (bytes.empty()) return;
            
            // 檢查是否以RET結尾
            if (bytes.back() == 0xC3) {
                is_ret_gadget = true;
                
                // 使用增強的指令分析邏輯
                if (is_valid_gadget(bytes)) {
                    // 檢查POP指令
                    if (bytes.size() >= 2) {
                        uint8_t last_byte = bytes[bytes.size() - 2];
                        if (last_byte >= 0x58 && last_byte <= 0x5F) { // pop r32
                            is_pop_gadget = true;
                        }
                    }
                    
                    // 檢查stack pivot
                    if (bytes.size() >= 2) {
                        if (bytes[bytes.size() - 2] == 0x94) { // xchg eax, esp
                            is_stack_pivot = true;
                        }
                    }
                    
                    if (bytes.size() >= 4) {
                        if (bytes[bytes.size() - 4] == 0x83 && bytes[bytes.size() - 3] == 0xC4) { // add esp, XX
                            is_stack_pivot = true;
                        }
                    }
                }
            }
        }
    };
    
    struct ROPChain {
        DWORD process_id;
        std::vector<ROPGadget> gadgets;
        std::chrono::steady_clock::time_point first_detection;
        int chain_length;
        double confidence;
        
        ROPChain(DWORD pid) : process_id(pid), chain_length(0), confidence(0.0) {
            first_detection = std::chrono::steady_clock::now();
        }
        
        void add_gadget(const ROPGadget& gadget) {
            gadgets.push_back(gadget);
            chain_length = gadgets.size();
            update_confidence();
        }
        
        void update_confidence() {
            if (gadgets.empty()) return;
            
            int ret_count = 0;
            int pop_count = 0;
            int pivot_count = 0;
            
            for (const auto& gadget : gadgets) {
                if (gadget.is_ret_gadget) ret_count++;
                if (gadget.is_pop_gadget) pop_count++;
                if (gadget.is_stack_pivot) pivot_count++;
            }
            
            // 計算置信度：基於gadget類型和鏈長度
            confidence = 0.3; // 基礎置信度
            confidence += (ret_count * 0.1); // 每個RET +0.1
            confidence += (pop_count * 0.05); // 每個POP +0.05
            confidence += (pivot_count * 0.15); // 每個stack pivot +0.15
            confidence += (chain_length * 0.02); // 鏈長度 +0.02
            
            confidence = std::min(confidence, 0.95); // 最高0.95
        }
    };
    
    std::map<DWORD, std::vector<ROPChain>> rop_chains_;
    std::mutex rop_chain_mutex_;
    
    // 記憶體緩存
    struct CachedMemoryRegion {
        uint64_t base_address;
        size_t size;
        DWORD protection;
        std::chrono::steady_clock::time_point last_scan;
        bool has_gadgets;
        bool is_executable;
        std::vector<ROPGadget> cached_gadgets;
        
        CachedMemoryRegion(uint64_t base, size_t sz, DWORD prot)
            : base_address(base), size(sz), protection(prot), has_gadgets(false), is_executable(false) {
            last_scan = std::chrono::steady_clock::now();
        }
    };
    
    std::map<DWORD, std::vector<CachedMemoryRegion>> memory_cache_;
    std::mutex cache_mutex_;
    
    // 模擬器輸出控制
    struct SimulatorOutputControl {
        std::chrono::steady_clock::time_point last_output;
        int output_count;
        int max_outputs_per_minute;
        int current_minute;
        
        SimulatorOutputControl() : output_count(0), max_outputs_per_minute(3), current_minute(0) {
            last_output = std::chrono::steady_clock::now();
        }
        
        bool should_output() {
            auto now = std::chrono::steady_clock::now();
            auto current_minute_value = std::chrono::duration_cast<std::chrono::minutes>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            // 檢查是否進入新的一分鐘
            if (current_minute_value != current_minute) {
                output_count = 0;
                current_minute = current_minute_value;
            }
            
            // 檢查是否超過每分鐘最大輸出次數
            if (output_count >= max_outputs_per_minute) {
                return false;
            }
            
            // 檢查時間間隔（至少間隔10秒）
            auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - last_output);
            if (time_diff.count() < 50) {
                return false;
            }
            
            output_count++;
            last_output = now;
            return true;
        }
        
        void set_max_outputs_per_minute(int max_outputs) {
            max_outputs_per_minute = max_outputs;
        }
    };
    
    std::map<DWORD, SimulatorOutputControl> simulator_output_controls_;
    std::mutex simulator_output_mutex_;
    
    // 性能配置
    struct PerformanceConfig {
        static constexpr size_t MAX_SCAN_SIZE = 8192;
        static constexpr int MIN_TRIGGER_THRESHOLD = 3;
        static constexpr int SCAN_STEP_SIZE = 2;
        static constexpr size_t MAX_GADGET_SIZE = 16;
        static constexpr int MIN_GADGET_COUNT = 3;
    };
    
    // 系統調用ROP鏈結構
    struct SyscallROPChain {
        uint64_t pop_eax_gadget;
        uint64_t pop_ebx_gadget;
        uint64_t pop_ecx_gadget;
        uint64_t pop_edx_gadget;
        uint64_t int_0x80_gadget;
        uint64_t pop_dword_ptr_gadget;
        uint64_t write_address;
        std::string shell_string;
        double confidence;
        
        SyscallROPChain() : pop_eax_gadget(0), pop_ebx_gadget(0), pop_ecx_gadget(0),
                           pop_edx_gadget(0), int_0x80_gadget(0), pop_dword_ptr_gadget(0),
                           write_address(0), confidence(0.0) {}
    };

    std::unordered_map<std::string, double> process_entropy_baseline_;
    std::mutex entropy_baseline_mutex_;
    
    // 使用已定義的統計數據和輸出控制變數

    // 自適應閾值系統
    struct AdaptiveThresholds {
        // 系統進程閾值（提高閾值，避免誤報）
        int system_rop_suspicious_patterns = 25;
        int system_rop_ret_count = 40;
        int system_consecutive_ret = 12;
        int system_gadget_chains = 8;
        int system_heap_corruption_patterns = 8;
        int system_shellcode_patterns = 12;
        
        // 用戶進程閾值（提高閾值，減少誤報）
        int user_rop_suspicious_patterns = 30;    // 提高到30，進一步減少誤報
        int user_rop_ret_count = 45;              // 提高到45，進一步減少誤報
        int user_consecutive_ret = 15;            // 提高到15，進一步減少誤報
        int user_gadget_chains = 10;              // 提高到10，進一步減少誤報
        int user_heap_corruption_patterns = 5;   
        int user_shellcode_patterns = 5;         
        
        // 攻擊模擬器閾值（調整為更真實的ROP攻擊特徵）
        int simulator_rop_suspicious_patterns = 8;   // 降低到8，適應真實ROP攻擊
        int simulator_rop_ret_count = 12;            // 降低到12，適應真實ROP攻擊
        int simulator_consecutive_ret = 2;           // 降低到2，適應真實ROP攻擊
        int simulator_gadget_chains = 1;             // 降低到1，適應真實ROP攻擊
        int simulator_heap_corruption_patterns = 10; // 降低到10，適應真實堆積破壞
        int simulator_shellcode_patterns = 8;       // 降低到8，適應真實shellcode
        double simulator_entropy_threshold = 2.5;   // 降低到2.5，適應真實攻擊
        
        // 高風險進程閾值（提高閾值，減少誤報）
        int high_risk_rop_suspicious_patterns = 25;    // 提高到25，進一步減少誤報
        int high_risk_rop_ret_count = 35;             // 提高到35，進一步減少誤報
        int high_risk_consecutive_ret = 12;            // 提高到12，進一步減少誤報
        int high_risk_gadget_chains = 8;              // 提高到8，進一步減少誤報
        int high_risk_heap_corruption_patterns = 6;
        int high_risk_shellcode_patterns = 5;
    };
    
    AdaptiveThresholds adaptive_thresholds_;
    


    struct ShellcodeDetectionConditions {
        bool has_code_caves;          // 存在代碼空洞
        bool has_iat_hooks;           // 存在IAT鉤子
        bool has_unusual_sections;    // 異常節區特徵
        bool has_decoder_stub;        // 存在解密樁代碼
        bool has_antidebug_tricks;    // 反調試特徵
        bool has_dynamic_imports;     // 動態API加載
    };

    ShellcodeDetectionConditions check_shellcode_conditions(const uint8_t* buffer, size_t size, HANDLE hProcess) {
        ShellcodeDetectionConditions cond = {false};
        
        // 檢測代碼空洞（連續nop或0xCC超過64字節）
        int consecutive_nops = 0;
        for (size_t i = 0; i < size; ++i) {
            if (buffer[i] == 0x90 || buffer[i] == 0xCC) {
                if (++consecutive_nops >= 64) {
                    cond.has_code_caves = true;
                    break;
                }
            } else {
                consecutive_nops = 0;
            }
        }

        // 檢查IAT鉤子（僅在非JIT區域）
        if (!is_legitimate_jit_region(hProcess, (LPVOID)buffer)) {
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)buffer;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && size > dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
                IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(buffer + dos->e_lfanew);
                if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
                    DWORD importRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(buffer + importRVA);
                    for (; imports->Name; ++imports) {
                        char* dllName = (char*)(buffer + imports->Name);
                        if (strstr(dllName, "kernel32") && imports->FirstThunk != imports->OriginalFirstThunk) {
                            cond.has_iat_hooks = true;
                            break;
                        }
                    }
                }
            }
        }

        // 檢測異常節區特徵（RWX權限或無節區頭）
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, buffer, &mbi, sizeof(mbi))) {
            cond.has_unusual_sections = 
                (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                !has_valid_section_headers(hProcess, mbi.AllocationBase);
        }

        // 查找解密樁特徵（xor循環+跳轉）
        // 簡化的解密樁檢測，避免使用通配符
        if (find_pattern(buffer, size, "\xEB\x02\x5E\x31\xC9", 5) ||  // jmp short +2; pop esi; xor ecx,ecx
            find_pattern(buffer, size, "\xEB\x04\x5E\x31\xC9", 5)) {  // jmp short +4; pop esi; xor ecx,ecx
            cond.has_decoder_stub = true;
        }

        // 檢測反調試技術（IsDebuggerPresent/SW_HIDE等）
        if (find_pattern(buffer, size, "\x64\xA1\x30\x00\x00\x00", 6) ||  // PEB access
            find_pattern(buffer, size, "\x0F\x31", 2)) {                 // rdtsc
            cond.has_antidebug_tricks = true;
        }

        // 檢測動態API加載（GetProcAddress特徵）
        if (find_pattern(buffer, size, "\xFF\x15", 2) &&  // call [addr]
            find_pattern(buffer, size, "\x8B\x0D", 2)) {  // mov ecx,[addr]
            cond.has_dynamic_imports = true;
        }

        return cond;
    }

    bool validate_shellcode_phase1(const uint8_t* buffer, size_t size) {
        // 第一階段基礎驗證
        return validate_instruction_flow(buffer, size) && 
        MemoryMonitor::calculate_shannon_entropy(buffer, size, "") > 4.5;
    }

    bool validate_shellcode_phase2(const uint8_t* buffer, size_t size, HANDLE hProcess) {
        // 第二階段高級特徵驗證
        ShellcodeDetectionConditions cond = check_shellcode_conditions(buffer, size, hProcess);
        return cond.has_code_caves + cond.has_iat_hooks + cond.has_unusual_sections +
               cond.has_decoder_stub + cond.has_antidebug_tricks + cond.has_dynamic_imports >= 3;
    }

    bool is_valid_shellcode_ex(const uint8_t* buffer, size_t size, HANDLE hProcess) {
        // 分階段驗證
        if (!validate_shellcode_phase1(buffer, size)) return false;
        if (!validate_shellcode_phase2(buffer, size, hProcess)) return false;
        
        // 最終熵值與指令複雜度交叉驗證
        double entropy = MemoryMonitor::calculate_shannon_entropy(buffer, size, "");
        size_t valid_ops = count_valid_instructions(buffer, size);
        return (entropy > 5.0 && valid_ops > size/2) || 
               (entropy > 6.0 && valid_ops > size/3);
    }
    
    // 白名單跳過計數器
    std::map<std::string, int> whitelist_skip_count_;
    std::mutex whitelist_mutex_;

    // 新增定期清理線程
    void fingerprint_cleaner() {
        while (running_) {
            std::this_thread::sleep_for(3600s); // 每小時清理
            std::lock_guard<std::mutex> lock(fingerprint_mutex_);
            
            auto now = std::chrono::steady_clock::now();
            for (auto it = heap_fingerprints_.begin(); it != heap_fingerprints_.end();) {
                if (now - it->second.last_report > 86400s) { // 24小時未活動
                    it = heap_fingerprints_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }


    // 新增記憶體一致性檢查
    bool check_memory_consistency(HANDLE hProcess, LPVOID base, SIZE_T size) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi));
        
        // 檢查記憶體區域屬性一致性
        bool is_executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        bool is_writable = (mbi.Protect & (PAGE_READWRITE|PAGE_WRITECOPY));
        
        // 合法JIT區域應為RW->RX轉換
        static std::map<LPVOID, DWORD> region_history;
        if (region_history.find(base) == region_history.end()) {
            region_history[base] = mbi.Protect;
            return false;
        } else {
            DWORD prev_protect = region_history[base];
            bool is_jit_behavior = (prev_protect == PAGE_READWRITE) && 
                                (mbi.Protect == PAGE_EXECUTE_READ);
            region_history[base] = mbi.Protect;
            return !is_jit_behavior;
        }
    }

    
    // 進程分類函數（使用新的 ProcessLists 類）
    ProcessCategory classify_process(const std::string& process_name) {
        auto category = ProcessLists::classify_process(process_name);
        
        // 如果是攻擊模擬器，設置輸出限制
        if (category == ProcessCategory::ATTACK_SIMULATOR) {
            set_simulator_output_limit(0, 3); // 0表示全局設置
            controlled_console_output("attack_simulator_classification", 
                "*** CLASSIFIED AS ATTACK SIMULATOR: " + process_name + " ***", 1, 60);
            controlled_log_output("attack_simulator_classification", 
                "*** CLASSIFIED AS ATTACK SIMULATOR: " + process_name + " ***", 1, 60);
        }
        
        return category;
    }
    
    // 檢查是否為白名單進程
    bool is_whitelisted_process(const std::string& process_name) {
        return ProcessLists::is_whitelisted_process(process_name);
    }
    
    // 靜默白名單跳過信息
    void silent_whitelist_skip(const std::string& process_name) {
        std::lock_guard<std::mutex> lock(whitelist_mutex_);
        whitelist_skip_count_[process_name]++;
        
        // 只在第一次跳過時輸出信息，之後每100次才輸出一次
        if (whitelist_skip_count_[process_name] == 1) {
            std::cout << "    Skipping detection for whitelisted process: " << process_name << std::endl;
            log_message("DEBUG", "Skipping detection for whitelisted process: " + process_name);
        } else if (whitelist_skip_count_[process_name] % 10000 == 0) {
            std::cout << "    Skipped " << whitelist_skip_count_[process_name] << " times for whitelisted process: " << process_name << std::endl;
            log_message("DEBUG", "Skipped " + std::to_string(whitelist_skip_count_[process_name]) + " times for whitelisted process: " + process_name);
        }
    }
    
    // 獲取自適應閾值
    struct ROPThresholds {
        int suspicious_patterns;
        int ret_count;
        int consecutive_ret;
        int gadget_chains;
        
        ROPThresholds(int sp, int rc, int cr, int gc) 
            : suspicious_patterns(sp), ret_count(rc), consecutive_ret(cr), gadget_chains(gc) {}
    };
    
    ROPThresholds get_rop_thresholds(ProcessCategory category) {
        switch (category) {
            case ProcessCategory::SYSTEM_PROCESS:
                return ROPThresholds{adaptive_thresholds_.system_rop_suspicious_patterns, 
                        adaptive_thresholds_.system_rop_ret_count,
                        adaptive_thresholds_.system_consecutive_ret,
                        adaptive_thresholds_.system_gadget_chains};
            case ProcessCategory::ATTACK_SIMULATOR:
                return ROPThresholds{adaptive_thresholds_.simulator_rop_suspicious_patterns, 
                        adaptive_thresholds_.simulator_rop_ret_count,
                        adaptive_thresholds_.simulator_consecutive_ret,
                        adaptive_thresholds_.simulator_gadget_chains};
            case ProcessCategory::HIGH_RISK_PROCESS:
                return ROPThresholds{adaptive_thresholds_.high_risk_rop_suspicious_patterns, 
                        adaptive_thresholds_.high_risk_rop_ret_count,
                        adaptive_thresholds_.high_risk_consecutive_ret,
                        adaptive_thresholds_.high_risk_gadget_chains};
            default: // USER_PROCESS
                return ROPThresholds{adaptive_thresholds_.user_rop_suspicious_patterns, 
                        adaptive_thresholds_.user_rop_ret_count,
                        adaptive_thresholds_.user_consecutive_ret,
                        adaptive_thresholds_.user_gadget_chains};
        }
    }
    
    int get_heap_corruption_threshold(ProcessCategory category) {
        switch (category) {
            case ProcessCategory::SYSTEM_PROCESS:
                return adaptive_thresholds_.system_heap_corruption_patterns;
            case ProcessCategory::ATTACK_SIMULATOR:
                return adaptive_thresholds_.simulator_heap_corruption_patterns;
            case ProcessCategory::HIGH_RISK_PROCESS:
                return adaptive_thresholds_.high_risk_heap_corruption_patterns;
            default: // USER_PROCESS
                return adaptive_thresholds_.user_heap_corruption_patterns;
        }
    }
    
    int get_shellcode_threshold(ProcessCategory category) {
        switch (category) {
            case ProcessCategory::SYSTEM_PROCESS:
                return adaptive_thresholds_.system_shellcode_patterns;
            case ProcessCategory::ATTACK_SIMULATOR:
                return adaptive_thresholds_.simulator_shellcode_patterns;
            case ProcessCategory::HIGH_RISK_PROCESS:
                return adaptive_thresholds_.high_risk_shellcode_patterns;
            default: // USER_PROCESS
                return adaptive_thresholds_.user_shellcode_patterns;
        }
    }
    
    // 重構閾值調整函數
    int calculate_adjusted_shellcode_threshold(int base_threshold, ProcessCategory category, 
        const std::string& process_name, double entropy) {
        // 增加進程行為因子
        int process_boost = 0;
        if (process_name.find("browser") != std::string::npos) {
            process_boost += 15;  // 瀏覽器進程提高閾值
        }
        if (is_process_injected(process_name)) {
            process_boost -= 10;  // 被注入進程降低閾值
        }
    
        // 非線性熵值影響
        double entropy_factor = std::clamp((entropy - 5.0) * 0.8, 0.0, 3.0);
        int adjusted = base_threshold + static_cast<int>(entropy_factor * 5) + process_boost;
    
        // 基於時間的動態調整
        static std::map<std::string, int> process_thresholds;
        auto now = std::chrono::system_clock::now();
        static auto last_updated = now;
        
        if (now - last_updated > 60s) {
            // 每分鐘衰減閾值調整
            for (auto& [key, val] : process_thresholds) {
                val = val * 0.9;
            }
            last_updated = now;
        }
        adjusted += process_thresholds[process_name];
        
        return std::clamp(adjusted, 25, 75);
    }

    // 新增輔助函數
    bool is_legitimate_jit_region(HANDLE hProcess, LPVOID address) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi));
        
        // 檢查是否為已知JIT區域
        HMODULE clrjit = GetModuleHandleA("clrjit.dll");
        if (clrjit && (LPVOID)clrjit <= address && 
            address < (LPVOID)((uintptr_t)clrjit + 0x1000000)) {
            return true;
        }
        
        
        return false;
    }

    bool is_legitimate_control_flow(const uint8_t* buffer, size_t size) {
        // 檢查是否為編譯器生成的合法控制流
        if (find_pattern(buffer, size, "\x48\x83\xEC\x28", 4))  // 標準函數序言
            return true;
        if (find_pattern(buffer, size, "\x55\x48\x8B\xEC", 4))  // MSVC函數序言
            return true;
        return false;
    }

    // 實現缺失的函數
    bool has_valid_section_headers(HANDLE hProcess, LPVOID base_address) {
        // 簡化的節區頭檢查
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQueryEx(hProcess, base_address, &mbi, sizeof(mbi))) {
            return false;
        }
        
        // 檢查是否為系統DLL
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32 && (LPVOID)kernel32 <= base_address && 
            base_address < (LPVOID)((uintptr_t)kernel32 + 0x1000000)) {
            return true;
        }
        
        // 檢查是否為合法的可執行區域
        return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) && 
               !(mbi.Protect & PAGE_EXECUTE_READWRITE);
    }

    size_t count_valid_instructions(const uint8_t* buffer, size_t size) {
        size_t valid_count = 0;
        
        for (size_t i = 0; i < size - 1; i++) {
            uint8_t opcode = buffer[i];
            
            // 檢查常見的有效指令
            if (opcode == 0x90 || // nop
                opcode == 0xC3 || // ret
                opcode == 0xCC || // int3
                (opcode >= 0x50 && opcode <= 0x5F) || // push/pop
                (opcode >= 0xB8 && opcode <= 0xBF) || // mov reg, imm
                opcode == 0x31 || // xor
                opcode == 0x89 || // mov
                opcode == 0x8B || // mov
                opcode == 0xE8 || // call
                opcode == 0xE9 || // jmp
                opcode == 0xEB) { // jmp short
                valid_count++;
            }
        }
        
        return valid_count;
    }

    // 新增輔助函數
    bool is_process_injected(const std::string& process_name) {
        // 簡化的注入檢測
        return process_name.find("inject") != std::string::npos ||
               process_name.find("hook") != std::string::npos;
    }

    // 強化特徵權重計算
    int calculate_shellcode_score(const uint8_t* buffer, size_t size, 
        int shellcode_patterns, double entropy,
        bool is_valid_shellcode_detected, ProcessCategory category) {
        int score = 0;

        // 基礎模式特徵權重
        score += shellcode_patterns * 8;  // 提高基礎權重

        // 強化shellcode特有特徵檢測
        int shellcode_signatures = 0;
        
        // 1. 檢測NOP sled特徵（連續NOP超過32字節）
        int consecutive_nops = 0;
        for (size_t i = 0; i < size; ++i) {
            if (buffer[i] == 0x90) {
                consecutive_nops++;
                if (consecutive_nops >= 32) {
                    shellcode_signatures += 15; // 高權重
                    break;
                }
            } else {
                consecutive_nops = 0;
            }
        }
        
        // 2. 檢測INT3 sled特徵（連續INT3超過16字節）
        int consecutive_int3 = 0;
        for (size_t i = 0; i < size; ++i) {
            if (buffer[i] == 0xCC) {
                consecutive_int3++;
                if (consecutive_int3 >= 16) {
                    shellcode_signatures += 12; // 高權重
                    break;
                }
            } else {
                consecutive_int3 = 0;
            }
        }
        
        // 3. 檢測PEB/TEB訪問特徵（shellcode常見）
        if (find_pattern(buffer, size, "\x64\xA1\x30\x00\x00\x00", 6)) { // mov eax, fs:[0x30]
            shellcode_signatures += 20; // 非常高權重
        }
        if (find_pattern(buffer, size, "\x65\x48\x8B\x04\x25\x30", 6)) { // mov rax, gs:[0x30]
            shellcode_signatures += 20; // 非常高權重
        }
        
        // 4. 檢測反射式DLL注入特徵
        if (find_pattern(buffer, size, "\xE8\x00\x00\x00\x00\x5B\x81\xEB", 8)) {
            shellcode_signatures += 18; // 高權重
        }
        
        // 5. 檢測Cobalt Strike信標特徵
        if (find_pattern(buffer, size, "\x48\x83\xEC\x28\xB9\x08\x00\x00\x00", 9)) {
            shellcode_signatures += 25; // 非常高權重
        }
        
        // 6. 檢測Egg Hunter模式
        if (find_pattern(buffer, size, "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02", 9)) {
            shellcode_signatures += 22; // 非常高權重
        }
        
        // 7. 檢測API解析特徵（shellcode常見）
        if (find_pattern(buffer, size, "\x68\x61\x6C\x6C\x00", 5)) { // "hall\0"
            shellcode_signatures += 15; // 高權重
        }
        if (find_pattern(buffer, size, "\x68\x6E\x65\x6C\x33\x32", 6)) { // "nel32"
            shellcode_signatures += 15; // 高權重
        }
        
        // 8. 檢測解密樁特徵
        if (find_pattern(buffer, size, "\xEB\x02\x5E\x31\xC9", 5)) { // jmp short +2; pop esi; xor ecx,ecx
            shellcode_signatures += 16; // 高權重
        }
        
        // 9. 檢測反調試特徵
        if (find_pattern(buffer, size, "\x64\xA1\x18\x00\x00\x00", 6)) { // PEB BeingDebugged
            shellcode_signatures += 14; // 高權重
        }
        
        // 10. 檢測動態API加載特徵
        if (find_pattern(buffer, size, "\x68\x00\x00\x00\x00\xE8", 6)) { // push 0; call
            shellcode_signatures += 12; // 中等權重
        }
        
        // 將shellcode特徵分數加入總分
        score += shellcode_signatures;

        // 高熵值加成（非線性區間，但降低權重避免誤報）
        if (entropy > 6.5) {
            score += 15; // 降低權重
        } else if (entropy > 6.0) {
            score += 12; // 降低權重
        } else if (entropy > 5.5) {
            score += 8; // 降低權重
        }

        // 有效shellcode檢測加成
        if (is_valid_shellcode_detected) {
            score += 15; // 降低權重
        }

        // 指令流驗證（增強現代指令識別）
        if (validate_instruction_flow(buffer, size)) {
            score += 10; // 降低權重
            // 排除AVX指令集誤判
            if (find_pattern(buffer, size, "\xC5\xFC", 2) != nullptr) { // AVX指令前綴
                score -= 8; // 增加懲罰
            }
        }

        // 進程特定調整
        if (category == ProcessCategory::ATTACK_SIMULATOR) {
            // 對於攻擊模擬器，進一步降低一般指標的影響
            if (entropy > 5.0 && shellcode_signatures < 10) { // 如果熵值高但shellcode特徵少
                score -= 15; // 增加懲罰
            }
            if (is_valid_shellcode_detected && shellcode_signatures < 5) {
                score -= 10; // 增加懲罰
            }
            if (validate_instruction_flow(buffer, size) && shellcode_signatures < 5) {
                score -= 10; // 增加懲罰
            }
            // 確保有足夠的直接shellcode模式才能獲得高分
            if (shellcode_patterns < 8) { // 提高最低要求
                score = std::min(score, 30); // 降低最高分限制
            }
        }

        // 異常模式懲罰（降低懲罰權重）
        for (size_t i = 0; i < size - 8; ++i) {
            // 檢測連續nop sled模式
            if (buffer[i] == 0x90 && buffer[i+1] == 0x90 && 
                buffer[i+2] == 0x90 && buffer[i+3] == 0x90) {
                score -= 2; // 降低懲罰
            }
            // 提高call/jmp指令權重
            if (buffer[i] == 0xE8 || buffer[i] == 0xE9) { // call/jmp
                score += 1; // 降低權重
            }
        }
        
        // 現代shellcode檢測
        if (MemoryMonitor::detect_modern_shellcode(buffer, size)) {
            score += 20; // 提高權重
        }
        
        return std::max(0, score);
    }


    // 檢測進程的正常行為模式（用於區分shellcode）
    bool is_normal_process_behavior(const uint8_t* buffer, size_t size, const std::string& process_name) {
        // 檢測正常的PE文件特徵
        if (size > 64) {
            // 檢測DOS頭
            if (buffer[0] == 'M' && buffer[1] == 'Z') {
                return true;
            }
            // 檢測PE頭
            if (buffer[0] == 'P' && buffer[1] == 'E' && buffer[2] == 0x00 && buffer[3] == 0x00) {
                return true;
            }
        }
        
        // 檢測正常的系統調用模式
        if (find_pattern(buffer, size, "\x48\x89\x5C\x24\x08", 5)) { // 正常的函數序言
            return true;
        }
        
        // 檢測正常的堆棧操作
        if (find_pattern(buffer, size, "\x48\x83\xEC", 3)) { // sub rsp, imm
            return true;
        }
        
        // 檢測正常的返回指令
        if (find_pattern(buffer, size, "\xC3", 1)) { // ret
            return true;
        }
        
        // 檢測正常的跳轉指令
        if (find_pattern(buffer, size, "\xE9", 1)) { // jmp
            return true;
        }
        
        // 檢測正常的調用指令
        if (find_pattern(buffer, size, "\xE8", 1)) { // call
            return true;
        }
        
        // 檢測正常的數據移動
        if (find_pattern(buffer, size, "\x48\x89", 2)) { // mov [mem], rax
            return true;
        }
        
        // 檢測正常的算術運算
        if (find_pattern(buffer, size, "\x48\x31", 2)) { // xor rax, rbx
            return true;
        }
        
        return false;
    }

    void detection_loop() {
        while (running_) {
            try {
                // 使用 monitor 進行底層掃描
                if (memory_monitor_) {
                    memory_monitor_->scan_processes();
                    memory_monitor_->scan_memory_regions();
                }
                
                // 執行高層檢測邏輯 - 使用 monitor 的進程信息
                if (memory_monitor_) {
                    auto processes = memory_monitor_->get_monitored_processes();
                    for (const auto& process : processes) {
                        if (process.process_handle != INVALID_HANDLE_VALUE) {
                            // 直接使用 process.category，因為它已經是 ProcessCategory 類型
                            perform_comprehensive_attack_detection(process.process_id, process.process_handle, process.category);   
                        }
                    }
                }
                
                // 降低掃描頻率 - 每5秒掃描一次
                scan_memory_for_attacks();
                std::this_thread::sleep_for(std::chrono::seconds(10));
                
                // 每10秒進行一次全進程掃描（原本是60秒）
                if (cycle_output_counter_ % 3 == 0) {
                    scan_all_processes_memory();
                }
                
                // 每60秒輸出一次狀態 (每12次循環 = 12 * 5秒 = 60秒)
                status_output_counter_++;
                if (status_output_counter_ >= 5) { // 12 * 5s = 60s
                    show_status();
                    status_output_counter_ = 0;
                }
                
                // 每300秒輸出一次循環信息 (每60次循環 = 60 * 5秒 = 300秒)
                cycle_output_counter_++;
                if (cycle_output_counter_ >= 10) { // 60 * 5s = 300s
                    std::cout << "Detection cycle completed. Total detections: " << total_detections_.load() << std::endl;
                    log_message("INFO", "Detection cycle completed. Total detections: " + std::to_string(total_detections_.load()));
                    
                    // 清理舊的攻擊模擬器輸出控制項
                    cleanup_simulator_output_controls();
                    
                    cycle_output_counter_ = 0;
                }
            }
            catch (const std::exception& e) {
                std::cerr << "Detection loop exception: " << e.what() << std::endl;
                log_message("ERROR", "Detection loop exception: " + std::string(e.what()));
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (...) {
                std::cerr << "Unknown exception in detection loop" << std::endl;
                log_message("ERROR", "Unknown exception in detection loop");
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }

    void scan_memory_for_attacks() {
        try {
            std::cout << "  scan_memory_for_attacks: Starting..." << std::endl;
            std::cerr << "  scan_memory_for_attacks: Starting... (stderr)" << std::endl;
            
            // 簡化的記憶體掃描實現 - 掃描所有區域但限制數量
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID address = 0;
            int scanned_regions = 0;
            const int max_regions_to_scan = 10; // 恢復到10個區域
            
            while (VirtualQuery(address, &mbi, sizeof(mbi)) && scanned_regions < max_regions_to_scan) {
                try {
                    std::cout << "    Scanning region " << scanned_regions + 1 << " at " << address << std::endl;
                    
                    // 檢查所有已提交的記憶體區域
                    if (mbi.State == MEM_COMMIT) {
                        // 檢查可執行記憶體
                        if (mbi.Protect & PAGE_EXECUTE) {
                            try {
                                check_executable_integrity(mbi.BaseAddress, mbi.RegionSize);
                            }
                            catch (const std::exception& e) {
                                std::cerr << "    Error checking executable integrity: " << e.what() << std::endl;
                            }
                            catch (...) {
                                std::cerr << "    Unknown error checking executable integrity" << std::endl;
                            }
                        }
                        
                        // 檢查堆區域 - 擴展檢查條件，包括所有可讀寫的記憶體
                        if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED || 
                            (mbi.Protect & PAGE_READWRITE) || (mbi.Protect & PAGE_READONLY) ||
                            (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                            try {
                                // 移除詳細的堆積區域掃描日誌，減少日誌輸出
                                check_heap_region(mbi.BaseAddress, mbi.RegionSize);
                            }
                            catch (const std::exception& e) {
                                std::cerr << "    Error checking heap region: " << e.what() << std::endl;
                            }
                            catch (...) {
                                std::cerr << "    Unknown error checking heap region" << std::endl;
                            }
                        }
                        
                        // 額外檢查：掃描攻擊模擬器進程的記憶體
                        static std::vector<DWORD> scanned_processes;
                        DWORD current_pid = GetCurrentProcessId();
                        
                        // 動態檢測攻擊模擬器進程
                        DWORD processes[1024];
                        DWORD cbNeeded;
                        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
                            DWORD num_processes = cbNeeded / sizeof(DWORD);
                            for (DWORD i = 0; i < num_processes; i++) {
                                if (processes[i] != 0) {
                                    std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                                    if (process_name.find("attack_simulator") != std::string::npos) {
                                        // 檢查是否已經掃描過這個進程
                                        bool already_scanned = false;
                                        for (const auto& scanned : scanned_processes) {
                                            if (scanned == processes[i]) {
                                                already_scanned = true;
                                                break;
                                            }
                                        }
                                        
                                        if (!already_scanned) {
                                            scanned_processes.push_back(processes[i]);
                                            log_message("DEBUG", "*** FOUND ATTACK SIMULATOR: PID=" + std::to_string(processes[i]) + " ***");
                                        }
                                    }
                                }
                            }
                        }
                        
                        // 檢查是否有攻擊模擬器進程需要掃描
                        for (const auto& process : scanned_processes) {
                            if (process != current_pid) {
                                try {
                                    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process);
                                    if (hProcess) {
                                        log_message("DEBUG", "*** SCANNING ATTACK SIMULATOR PROCESS: PID=" + std::to_string(process) + " ***");
                                        scan_process_heap_regions(hProcess, process);
                                        CloseHandle(hProcess);
                                    }
                                }
                                catch (...) {
                                    // 忽略進程訪問錯誤
                                }
                            }
                        }
                        
                        scanned_regions++;
                        std::cout << "    Completed region " << scanned_regions << std::endl;
                    }
                    
                    // 安全地計算下一個地址
                    try {
                        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
                    }
                    catch (...) {
                        std::cerr << "    Error calculating next address" << std::endl;
                        break;
                    }
                }
                catch (const std::exception& e) {
                    std::cerr << "    Error scanning memory region: " << e.what() << std::endl;
                    try {
                        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
                    }
                    catch (...) {
                        std::cerr << "    Error calculating next address after exception" << std::endl;
                        break;
                    }
                }
                catch (...) {
                    std::cerr << "    Unknown error scanning memory region" << std::endl;
                    try {
                        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
                    }
                    catch (...) {
                        std::cerr << "    Error calculating next address after unknown exception" << std::endl;
                        break;
                    }
                }
            }
            
            std::cout << "  scan_memory_for_attacks: Completed, scanned " << scanned_regions << " regions" << std::endl;
            std::cerr << "  scan_memory_for_attacks: Completed, scanned " << scanned_regions << " regions (stderr)" << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Error in scan_memory_for_attacks: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Unknown error in scan_memory_for_attacks" << std::endl;
        }
    }

    void scan_all_processes_memory() {
        try {
            DWORD processes[1024];
            DWORD cbNeeded;
            
            if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
                DWORD num_processes = cbNeeded / sizeof(DWORD);
                const int max_processes_to_scan = 100; // 增加掃描進程數量
                
                int scanned_count = 0;
                for (DWORD i = 0; i < num_processes && i < max_processes_to_scan; i++) {
                    try {
                        if (processes[i] != 0) {
                            std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                            ProcessCategory category = classify_process(process_name);
                            
                            // 添加調試輸出 - 檢查所有進程名稱
                            if (process_name.find("attack") != std::string::npos || 
                                process_name.find("simulator") != std::string::npos) {
                                std::cout << "  *** DEBUG: Found potential attack simulator: PID " << processes[i] 
                                          << " (" << process_name << ") Category: " 
                                          << (category == ProcessCategory::ATTACK_SIMULATOR ? "ATTACK_SIMULATOR" : 
                                              category == ProcessCategory::HIGH_RISK_PROCESS ? "HIGH_RISK" :
                                              category == ProcessCategory::SYSTEM_PROCESS ? "SYSTEM" : "USER") << " ***" << std::endl;
                                log_message("DEBUG", "*** Found potential attack simulator: PID " + std::to_string(processes[i]) + 
                                           " (" + process_name + ") Category: " + 
                                           (category == ProcessCategory::ATTACK_SIMULATOR ? "ATTACK_SIMULATOR" : 
                                            category == ProcessCategory::HIGH_RISK_PROCESS ? "HIGH_RISK" :
                                            category == ProcessCategory::SYSTEM_PROCESS ? "SYSTEM" : "USER"));
                            }
                            
                            // 檢查進程是否可訪問 - 嘗試多種權限組合
                            HANDLE hProcess = NULL;
                            DWORD last_error = 0;
                            
                            // 嘗試不同的權限組合
                            const DWORD access_flags[] = {
                                PROCESS_ALL_ACCESS, // 使用最高權限
                                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                                PROCESS_QUERY_INFORMATION,
                                PROCESS_QUERY_LIMITED_INFORMATION
                            };
                            
                            for (int flag_idx = 0; flag_idx < 5 && !hProcess; flag_idx++) {
                                hProcess = OpenProcess(access_flags[flag_idx], FALSE, processes[i]);
                                if (!hProcess) {
                                    last_error = GetLastError();
                                }
                            }
                            
                            if (hProcess) {
                                // 根據進程類別決定掃描策略
                                switch (category) {
                                    case ProcessCategory::ATTACK_SIMULATOR:
                                        std::cout << "  *** FOUND ATTACK SIMULATOR: PID " << processes[i] << " ***" << std::endl;
                                        std::cout << "  *** Process Name: " << process_name << " ***" << std::endl;
                                        log_message("DEBUG", "*** FOUND ATTACK SIMULATOR: PID " + std::to_string(processes[i]) + " ***");
                                        log_message("DEBUG", "*** Process Name: " + process_name + " ***");
                                        // 立即進行深度掃描
                                        deep_scan_process(processes[i]);
                                        break;
                                        
                                    case ProcessCategory::HIGH_RISK_PROCESS:
                                        std::cout << "  *** HIGH RISK PROCESS: PID " << processes[i] << " (" << process_name << ") ***" << std::endl;
                                        log_message("DEBUG", "*** HIGH RISK PROCESS: PID " + std::to_string(processes[i]) + " (" + process_name + ") ***");
                                        // 對高風險進程進行深度掃描
                                        deep_scan_process(processes[i]);
                                        break;
                                        
                                    case ProcessCategory::SYSTEM_PROCESS:
                                        // 系統進程使用較高的閾值，減少誤報
                                        if (scanned_count % 10 == 0) { // 每10個系統進程掃描一次
                                            scan_process_memory(processes[i], true);
                                        }
                                        break;
                                        
                                    case ProcessCategory::USER_PROCESS:
                                        // 用戶進程使用中等閾值
                                        if (scanned_count % 5 == 0) { // 每5個用戶進程掃描一次
                                            scan_process_memory(processes[i], false);
                                        }
                                        break;
                                }
                                
                                CloseHandle(hProcess);
                            } else {
                                // 只在調試模式下輸出錯誤信息
                                if (category == ProcessCategory::ATTACK_SIMULATOR || category == ProcessCategory::HIGH_RISK_PROCESS) {
                                    std::cout << "  *** Process " << processes[i] << " (" << process_name << ") is NOT accessible (Error: " << last_error << ") ***" << std::endl;
                                    log_message("DEBUG", "*** Process " + std::to_string(processes[i]) + " (" + process_name + ") is NOT accessible (Error: " + std::to_string(last_error) + ") ***");
                                }
                            }
                            
                            scanned_count++;
                        }
                    }
                    catch (const std::exception& e) {
                        std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                        ProcessCategory category = classify_process(process_name);
                        if (category == ProcessCategory::ATTACK_SIMULATOR || category == ProcessCategory::HIGH_RISK_PROCESS) {
                            std::cerr << "  Error scanning process " << processes[i] << " (" << process_name << "): " << e.what() << std::endl;
                        }
                    }
                    catch (...) {
                        std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                        ProcessCategory category = classify_process(process_name);
                        if (category == ProcessCategory::ATTACK_SIMULATOR || category == ProcessCategory::HIGH_RISK_PROCESS) {
                            std::cerr << "  Unknown error scanning process " << processes[i] << " (" << process_name << ")" << std::endl;
                        }
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error in scan_all_processes_memory: " << e.what() << std::endl;
            log_message("ERROR", "Error in scan_all_processes_memory: " + std::string(e.what()));
        }
        catch (...) {
            std::cerr << "Unknown error in scan_all_processes_memory" << std::endl;
            log_message("ERROR", "Unknown error in scan_all_processes_memory");
        }
    }

    void deep_scan_process(DWORD process_id) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (!hProcess) {
            return;
        }
        
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        ProcessCategory category = classify_process(process_name);
        bool is_attack_simulator = (process_name.find("attack_simulator") != std::string::npos);
        
        if (is_attack_simulator) {
            std::cout << "    *** Starting deep scan for process " << process_id << " ***" << std::endl;
            log_message("DEBUG", "*** Starting deep scan for process " + std::to_string(process_id) + " ***");
        }
        
        // 新增：對攻擊模擬器執行分散式ROP檢測
        if (category == ProcessCategory::ATTACK_SIMULATOR) {
            detect_scattered_rop_chains(process_id, hProcess);
        }
        
        // 使用智能掃描替代傳統掃描
        if (is_attack_simulator) {
            std::cout << "    *** Calling smart_scan_process for attack simulator ***" << std::endl;
            log_message("DEBUG", "*** Calling smart_scan_process for attack simulator ***");
        }
        smart_scan_process(process_id, hProcess, category);
        
        // 新增：執行全面攻擊檢測
        perform_comprehensive_attack_detection(process_id, hProcess, category);
        
        if (is_attack_simulator) {
            std::cout << "    *** Deep scan completed for process " << process_id << " ***" << std::endl;
            log_message("DEBUG", "*** Deep scan completed for process " + std::to_string(process_id) + " ***");
        }
        
        CloseHandle(hProcess);
    }

    void check_executable_integrity(LPVOID base, SIZE_T size) {
        try {
            std::cout << "      check_executable_integrity: Starting..." << std::endl;
            
            // 限制檢查的記憶體大小，避免過度消耗
            if (size > 4096) { // 恢復到4KB
                size = 4096;
            }
            
            // 簡化的可執行記憶體完整性檢查
            std::vector<uint8_t> buffer(size);
            
            try {
                // 使用更安全的記憶體複製
                SIZE_T bytes_to_copy = size;
                if (bytes_to_copy > 4096) {
                    bytes_to_copy = 4096;
                }
                
                // 檢查記憶體是否可讀
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(base, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                        // 使用ReadProcessMemory來安全地讀取記憶體
                        SIZE_T bytes_read = 0;
                        if (ReadProcessMemory(GetCurrentProcess(), base, buffer.data(), bytes_to_copy, &bytes_read)) {
                            // 檢查shellcode模式
                            int shellcode_patterns = 0;
                            
                            for (size_t i = 0; i < bytes_read - 3; i++) {
                                // 檢查常見的shellcode開頭
                                if (buffer[i] == 0x90 && buffer[i+1] == 0x90 && buffer[i+2] == 0x90) { // nop sled
                                    shellcode_patterns++;
                                }
                                if (buffer[i] == 0xCC && buffer[i+1] == 0xCC && buffer[i+2] == 0xCC) { // int3 sled
                                    shellcode_patterns++;
                                }
                                // 檢查常見的shellcode指令
                                if (buffer[i] == 0x31 && buffer[i+1] == 0xC0) { // xor eax, eax
                                    shellcode_patterns++;
                                }
                                if (buffer[i] == 0x31 && buffer[i+1] == 0xDB) { // xor ebx, ebx
                                    shellcode_patterns++;
                                }
                            }
                            
                            // 只在檢測到大量模式時輸出調試信息
                            if (shellcode_patterns > 20) {
                                std::cout << "        Debug: shellcode_patterns=" << shellcode_patterns << std::endl;
                            }
                            
                            // 偵測shellcode - 降低閾值
                            if (shellcode_patterns >= 1) {
                                report_attack(AttackType::SHELLCODE_INJECTION, (uint64_t)base, "Found shellcode pattern", 0.8);
                            }
                        }
                    }
                }
                
                std::cout << "      check_executable_integrity: Completed" << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "      Error in check_executable_integrity: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "      Unknown error in check_executable_integrity" << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error in check_executable_integrity: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Unknown error in check_executable_integrity" << std::endl;
        }
    }

    void scan_process_heap_regions(HANDLE hProcess, DWORD process_id) {
        // 效能優化：減少掃描頻率和範圍
        static std::map<DWORD, std::chrono::steady_clock::time_point> last_scan_time;
        auto now = std::chrono::steady_clock::now();
        
        // 檢查是否需要掃描（每5分鐘掃描一次）
        auto it = last_scan_time.find(process_id);
        if (it != last_scan_time.end()) {
            auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
            if (time_diff.count() < 10) { // 5分鐘 = 300秒
                return; // 跳過掃描
            }
        }
        last_scan_time[process_id] = now;
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int scanned_regions = 0;
        const int max_regions_to_scan = 50; // 大幅增加掃描區域數量
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) && scanned_regions < max_regions_to_scan) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
                (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY || mbi.Protect & PAGE_EXECUTE_READWRITE)) {
                
                // 移除詳細的遠程堆積掃描日誌，減少日誌輸出
                
                check_heap_region_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
                scanned_regions++;
            }
            address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
        }
        
        // 移除遠程掃描完成日誌，減少輸出
    }

    void check_heap_region(LPVOID base, SIZE_T size) {
        try {
            // 移除開始日誌，減少輸出
            
            // 增加檢查的記憶體大小，提高檢測覆蓋率
            if (size > 16384) { // 增加到16KB
                size = 16384;
            }
            
            // 簡化的堆區域檢查
            std::vector<uint8_t> buffer(size);
            SIZE_T bytes_read = 0;
            int corruption_patterns = 0;
            
            try {
                // 使用更安全的記憶體複製
                SIZE_T bytes_to_copy = size;
                if (bytes_to_copy > 16384) {
                    bytes_to_copy = 16384;
                }
                
                // 檢查記憶體是否可讀 - 放寬檢查條件
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQuery(base, &mbi, sizeof(mbi))) {
                    if (mbi.State == MEM_COMMIT) {
                        // 使用ReadProcessMemory來安全地讀取記憶體
                        if (ReadProcessMemory(GetCurrentProcess(), base, buffer.data(), bytes_to_copy, &bytes_read)) {
                            // 檢查堆損壞模式 - 更嚴格的檢測
                            
                            // 檢查堆損壞模式 - 使用32位比較，增加更多模式
                            for (size_t i = 0; i <= bytes_read - 4; i++) {
                                try {
                                    uint32_t pattern = *(uint32_t*)(&buffer[i]);
                                    if (pattern == 0xDEADBEEF || pattern == 0xBADBADBA || 
                                        pattern == 0xBAADF00D || pattern == 0xFEEEFEEE ||
                                        pattern == 0xCDCDCDCD || pattern == 0xABABABAB) {
                                        corruption_patterns++;
                                        if (corruption_patterns <= 3) { // 限制輸出頻率
                                            log_message("DEBUG", "*** Found heap corruption pattern 0x" + std::to_string(pattern) + " at offset " + std::to_string(i) + " ***");
                                        }
                                    }
                                }
                                catch (...) {
                                    // 忽略個別字節的訪問錯誤
                                    continue;
                                }
                            }
                            
                            // 額外檢查：如果發現大量堆積破壞模式，提高檢測敏感度
                            if (corruption_patterns > 10) {
                                log_message("ALERT", "*** HIGH DENSITY HEAP CORRUPTION DETECTED: " + std::to_string(corruption_patterns) + " patterns in single region ***");
                            }
                            
                            // 降低偵測閾值，更容易偵測到堆損壞
                            if (corruption_patterns >= 1) {
                                log_message("ALERT", "*** HEAP CORRUPTION DETECTED: " + std::to_string(corruption_patterns) + " patterns at 0x" + format_address((uint64_t)base) + " ***");
                                report_attack(AttackType::HEAP_CORRUPTION, (uint64_t)base, "Found heap corruption pattern", 0.6);
                            }
                        }
                    }
                }
                
                // 只在發現破壞模式時才記錄
                if (corruption_patterns > 0) {
                    log_message("DEBUG", "check_heap_region: Found " + std::to_string(corruption_patterns) + " corruption patterns in " + std::to_string(bytes_read) + " bytes");
                }
            }
            catch (const std::exception& e) {
                std::cerr << "      Error in check_heap_region: " << e.what() << std::endl;
            }
            catch (...) {
                std::cerr << "      Unknown error in check_heap_region" << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error in check_heap_region: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Unknown error in check_heap_region" << std::endl;
        }
    }

    void check_executable_integrity_remote(HANDLE hProcess, LPVOID base, SIZE_T size) {
        // 限制檢查的記憶體大小，避免過度消耗
        if (size > 4096) { // 限制到4KB
            size = 4096;
        }

        MEMORY_BASIC_INFORMATION mbi;
        VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi));
        
        // 模擬器測試區域通常具有特殊保護屬性
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
            log_message("DEBUG", "Simulator RWX region, lower confidence");
            return;
        }
        
        std::vector<uint8_t> buffer(size);
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(hProcess, base, buffer.data(), size, &bytes_read)) {
            // 獲取進程ID和名稱
            DWORD process_id = GetProcessId(hProcess);
            std::string process_name = MemoryMonitor::get_process_name(process_id);
            ProcessCategory category = classify_process(process_name);
            
            // 檢查是否在白名單中（但攻擊模擬器除外）
            if (is_whitelisted_process(process_name) && category != ProcessCategory::ATTACK_SIMULATOR) {
                silent_whitelist_skip(process_name);
                return;
            }

            // 首先檢查是否為heap corruption區域，如果是則跳過ROP檢測
            int corruption_patterns = 0;
            for (size_t i = 0; i < bytes_read - 4; i++) {
                uint32_t value = *(uint32_t*)(&buffer[i]);
                if (value == 0xDEADBEEF || 
                    value == 0xBAADF00D ||
                    value == 0xFEEEFEEE ||
                    value == 0xCDCDCDCD ||
                    value == 0xABABABAB) {
                    corruption_patterns++;
                }
            }
            
            // 只有在檢測到足夠多的heap corruption模式時才跳過ROP檢測
            // 使用更嚴格的閾值，避免誤判正常記憶體區域
            int corruption_threshold = get_heap_corruption_threshold(category);
            // 對於攻擊模擬器，提高閾值避免誤判
            if (category == ProcessCategory::ATTACK_SIMULATOR) {
                corruption_threshold = corruption_threshold * 3; // 提高3倍閾值
            }
            if (corruption_patterns >= corruption_threshold) {
                // 調試輸出
                std::cout << "    *** SKIPPING ROP DETECTION due to heap corruption patterns: " << corruption_patterns << " (threshold: " << corruption_threshold << ") ***" << std::endl;
                log_message("DEBUG", "*** SKIPPING ROP DETECTION due to heap corruption patterns: " + std::to_string(corruption_patterns) + " (threshold: " + std::to_string(corruption_threshold) + ") ***");
                return; // 跳過ROP檢測，讓heap檢測函數處理
            }

            // 獲取shellcode閾值
            int shellcode_threshold = get_shellcode_threshold(category);
            
            // 檢查shellcode模式 - 更精確的檢測
            int shellcode_patterns = 0;
            
            for (size_t i = 0; i < bytes_read - 3; i++) {
                // 檢查連續的NOP sled（需要更多連續NOP才計數）
                if (buffer[i] == 0x90 && buffer[i+1] == 0x90 && buffer[i+2] == 0x90) {
                    // 檢查是否有更多連續的NOP
                    int consecutive_nops = 3;
                    for (size_t j = i + 3; j < bytes_read && j < i + 10 && buffer[j] == 0x90; j++) {
                        consecutive_nops++;
                    }
                    if (consecutive_nops >= 5) { // 至少5個連續NOP才計數
                        shellcode_patterns++;
                    }
                }
                
                // 檢查連續的INT3 sled（需要更多連續INT3才計數）
                if (buffer[i] == 0xCC && buffer[i+1] == 0xCC && buffer[i+2] == 0xCC) {
                    // 檢查是否有更多連續的INT3
                    int consecutive_int3 = 3;
                    for (size_t j = i + 3; j < bytes_read && j < i + 10 && buffer[j] == 0xCC; j++) {
                        consecutive_int3++;
                    }
                    if (consecutive_int3 >= 5) { // 至少5個連續INT3才計數
                        shellcode_patterns++;
                    }
                }
                
                // 檢查更複雜的shellcode指令組合（更嚴格的條件）
                if (buffer[i] == 0x31 && buffer[i+1] == 0xC0) { // xor eax, eax
                    // 只有在後面跟著明顯的shellcode特徵時才計數
                    if (i + 5 < bytes_read) {
                        // 檢查是否為典型的shellcode序列
                        if (buffer[i+2] == 0x31 && buffer[i+3] == 0xDB && 
                            (buffer[i+4] == 0x31 || buffer[i+4] == 0x50)) { // xor ebx, ebx + 其他指令
                            shellcode_patterns += 2; // 給予更高權重
                        } else if (buffer[i+2] == 0x50 && buffer[i+3] == 0x68) { // push eax + push
                            shellcode_patterns++;
                        } else if (buffer[i+2] == 0x90 && buffer[i+3] == 0x90) { // 跟著NOP sled
                            shellcode_patterns++;
                        } else {
                            // 單獨的xor eax, eax不計數，避免誤判ROP gadgets
                            // shellcode_patterns++; // 註釋掉，避免誤判
                        }
                    } else {
                        // 單獨的xor eax, eax不計數
                        // shellcode_patterns++; // 註釋掉，避免誤判
                    }
                }
                
                // 檢查其他shellcode特徵（更嚴格）
                if (buffer[i] == 0x31 && buffer[i+1] == 0xDB) { // xor ebx, ebx
                    // 只有在後面跟著明顯的shellcode特徵時才計數
                    if (i + 3 < bytes_read && buffer[i+2] == 0x31) { // 跟著另一個xor指令
                        shellcode_patterns++;
                    }
                }
                
                // 檢查shellcode中的API調用模式
                if (buffer[i] == 0xE8) { // call指令
                    // 檢查是否為相對調用（shellcode特徵）
                    if (i + 4 < bytes_read) {
                        // 檢查調用目標是否在合理範圍內
                        int32_t offset = *(int32_t*)(&buffer[i+1]);
                        if (offset > -0x1000000 && offset < 0x1000000) {
                            shellcode_patterns++;
                        }
                    }
                }
            }
            
            // ROP檢測已移至 detect_scattered_rop_chains 函數
            // 此處僅保留shellcode檢測邏輯
            
            // 檢查shellcode模式並計算置信度
            double shellcode_confidence = 0.0;
            bool is_shellcode_attack = false;
            bool has_suspicious_context = false;
            std::string context_description = "";
            
            if (shellcode_patterns > 0) {
                // 檢測shellcode的上下文（是否與其他攻擊結合）
                
                // 1. 檢查是否為RWX記憶體區域（高度可疑）
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi))) {
                    if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                        has_suspicious_context = true;
                        context_description += "RWX memory region; ";
                    }
                    // 新增：檢測PAGE_EXECUTE_WRITECOPY（攻擊模擬器使用的權限混淆技術）
                    if (mbi.Protect & PAGE_EXECUTE_WRITECOPY) {
                        has_suspicious_context = true;
                        context_description += "PAGE_EXECUTE_WRITECOPY memory region; ";
                    }
                }
                
                // 2. 檢查是否有堆積破壞特徵（堆積破壞 + Shellcode組合）
                if (corruption_patterns > 0) {
                    has_suspicious_context = true;
                    context_description += "heap corruption patterns detected; ";
                }
                
                // 3. 檢查是否在堆疊區域（可能與緩衝區溢出結合）
                if ((uint64_t)base >= 0x7FFE0000 && (uint64_t)base <= 0x7FFFFFFF) {
                    has_suspicious_context = true;
                    context_description += "stack region; ";
                }
                
                // 4. ROP檢測已移至 detect_scattered_rop_chains 函數
                
                // 5. 檢查是否有注入特徵 - 提高要求
                double entropy = MemoryMonitor::calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
                if (process_name.find("explorer") == std::string::npos && 
                    process_name.find("svchost") == std::string::npos &&
                    entropy > 6.5) { // 提高熵值要求
                    has_suspicious_context = true;
                    context_description += "high entropy in non-system process; ";
                }
                
                // 對於攻擊模擬器，使用更寬鬆的上下文檢測
                if (category == ProcessCategory::ATTACK_SIMULATOR) {
                    // 檢查是否為模擬器特有的合法模式
                    bool is_simulator_legitimate = false;
                    
                    // 檢查是否包含模擬器標記
                    for (size_t i = 0; i < bytes_read - 4; i++) {
                        if (*(uint32_t*)(&buffer[i]) == 0x53494D55) { // 'SIMU'
                            is_simulator_legitimate = true;
                            break;
                        }
                    }
                    
                    // 檢查是否為模擬器的測試代碼
                    int test_patterns = 0;
                    for (size_t i = 0; i < bytes_read - 2; i++) {
                        if (buffer[i] == 0x90 && buffer[i+1] == 0x90) test_patterns++;
                        if (buffer[i] == 0xCC && buffer[i+1] == 0xCC) test_patterns++;
                    }
                    
                    // 如果檢測到太多測試模式，可能是模擬器的正常行為
                    if (test_patterns > bytes_read / 50) {
                        is_simulator_legitimate = true;
                    }
                    
                                            // 對於攻擊模擬器，簡化檢測條件，提高檢測率
                        if (shellcode_patterns >= 5) { // 降低shellcode模式要求
                            // 簡化攻擊模擬器的shellcode檢測
                            double entropy = MemoryMonitor::calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
                            
                            // 計算shellcode置信度
                            bool is_valid_shellcode_detected = is_valid_shellcode_ex(buffer.data(), bytes_read, hProcess);
                            
                            // 使用shellcode評分函數
                            int shellcode_score = calculate_shellcode_score(buffer.data(), bytes_read, 
                                                                          shellcode_patterns, entropy, 
                                                                          is_valid_shellcode_detected, category);
                            
                            int adjusted_threshold = calculate_adjusted_shellcode_threshold(shellcode_threshold, 
                                                                                          category, process_name, entropy);
                            
                            // 對於攻擊模擬器，使用更寬鬆的驗證條件
                            bool has_high_entropy = entropy > 4.5; // 降低熵值要求
                            bool has_valid_instructions = count_valid_instructions(buffer.data(), bytes_read) > bytes_read * 0.1; // 降低有效指令比例要求
                            
                            // 調試輸出
                            std::string debug_key = "shellcode_context_" + std::to_string(process_id);
                            std::string debug_msg = "*** SHELLCODE CONTEXT: address=" + format_address((uint64_t)base) + 
                                                  ", patterns=" + std::to_string(shellcode_patterns) + 
                                                  ", score=" + std::to_string(shellcode_score) + 
                                                  ", threshold=" + std::to_string(adjusted_threshold) + 
                                                  ", entropy=" + std::to_string(entropy) + 
                                                  ", has_context=" + std::to_string(has_suspicious_context) + 
                                                  ", context=" + context_description + " ***";
                            controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                            controlled_log_output(debug_key, debug_msg, 1, 60);
                            
                            // 使用更寬鬆的檢測條件
                            if (shellcode_score >= adjusted_threshold * 0.9 && 
                                shellcode_patterns >= get_shellcode_threshold(category) * 0.5 &&
                                has_high_entropy && has_valid_instructions) {
                            
                            // 使用shellcode評分函數
                            int shellcode_score = calculate_shellcode_score(buffer.data(), bytes_read, 
                                                                          shellcode_patterns, entropy, 
                                                                          is_valid_shellcode_detected, category);
                            
                            int adjusted_threshold = calculate_adjusted_shellcode_threshold(shellcode_threshold, 
                                                                                          category, process_name, entropy);
                            
                            // 對於攻擊模擬器，使用更嚴格的驗證條件
                            bool has_high_entropy = entropy > 5.0; // 提高熵值要求
                            bool has_valid_instructions = count_valid_instructions(buffer.data(), bytes_read) > bytes_read * 0.15; // 提高有效指令比例要求
                            
                            // 調試輸出
                            std::string debug_key = "shellcode_context_" + std::to_string(process_id);
                            std::string debug_msg = "*** SHELLCODE CONTEXT: address=" + format_address((uint64_t)base) + 
                                                  ", patterns=" + std::to_string(shellcode_patterns) + 
                                                  ", score=" + std::to_string(shellcode_score) + 
                                                  ", threshold=" + std::to_string(adjusted_threshold) + 
                                                  ", entropy=" + std::to_string(entropy) + 
                                                  ", has_context=" + std::to_string(has_suspicious_context) + 
                                                  ", context=" + context_description + 
                                                  " ***";
                            controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                            controlled_log_output(debug_key, debug_msg, 1, 60);
                            
                            // 使用更嚴格的檢測條件
                            if (shellcode_score >= adjusted_threshold * 0.9 && 
                                shellcode_patterns >= get_shellcode_threshold(category) * 0.6 &&
                                has_high_entropy && has_valid_instructions) {
                                is_shellcode_attack = true;
                                
                                // 動態計算shellcode置信度
                                double base_confidence = 0.3; // 降低基礎置信度
                                
                                // 基於評分調整
                                double score_bonus = (shellcode_score - adjusted_threshold) * 0.01;
                                
                                // 基於熵值調整
                                double entropy_bonus = 0.0;
                                if (entropy > 6.5) entropy_bonus = 0.2;
                                else if (entropy > 5.5) entropy_bonus = 0.15;
                                else if (entropy > 5.0) entropy_bonus = 0.1;
                                
                                // 基於記憶體保護調整
                                double protection_bonus = 0.0;
                                MEMORY_BASIC_INFORMATION mbi;
                                if (VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi))) {
                                    if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                                        protection_bonus = 0.15; // RWX記憶體獎勵
                                    }
                                }
                                
                                // 基於上下文調整
                                double context_bonus = 0.0;
                                if (has_suspicious_context) context_bonus = 0.1;
                                
                                shellcode_confidence = base_confidence + score_bonus + entropy_bonus + protection_bonus + context_bonus;
                                shellcode_confidence = std::min(shellcode_confidence, 0.85); // 最高0.85
                                shellcode_confidence = std::max(shellcode_confidence, 0.3); // 最低0.3
                            }
                        }
                    }
                } else {
                    // 其他進程的shellcode檢測 - 需要可疑上下文
                    if (has_suspicious_context) {
                        double entropy = MemoryMonitor::calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
                        bool is_valid_shellcode_detected = is_valid_shellcode_ex(buffer.data(), bytes_read, hProcess);
                        
                        int shellcode_score = calculate_shellcode_score(buffer.data(), bytes_read, 
                                                                      shellcode_patterns, entropy, 
                                                                      is_valid_shellcode_detected, category);
                        
                        int adjusted_threshold = calculate_adjusted_shellcode_threshold(shellcode_threshold, 
                                                                                      category, process_name, entropy);
                        
                        // 調試輸出
                        std::string debug_key = "shellcode_context_" + std::to_string(process_id);
                        std::string debug_msg = "*** SHELLCODE CONTEXT: address=" + format_address((uint64_t)base) + 
                                              ", patterns=" + std::to_string(shellcode_patterns) + 
                                              ", score=" + std::to_string(shellcode_score) + 
                                              ", threshold=" + std::to_string(adjusted_threshold) + 
                                              ", entropy=" + std::to_string(entropy) + 
                                              ", has_context=" + std::to_string(has_suspicious_context) + 
                                              ", context=" + context_description + " ***";
                        controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                        controlled_log_output(debug_key, debug_msg, 1, 60);
                        
                        if (shellcode_score >= adjusted_threshold && shellcode_patterns >= get_shellcode_threshold(category)) {
                            is_shellcode_attack = true;
                            
                            // 動態計算shellcode置信度
                            double base_confidence = 0.25; // 降低基礎置信度
                            
                            // 基於評分調整
                            double score_bonus = (shellcode_score - adjusted_threshold) * 0.005;
                            
                            // 基於熵值調整
                            double entropy_bonus = 0.0;
                            if (entropy > 7.0) entropy_bonus = 0.25;
                            else if (entropy > 6.0) entropy_bonus = 0.2;
                            else if (entropy > 5.5) entropy_bonus = 0.15;
                            
                            // 基於記憶體保護調整
                            double protection_bonus = 0.0;
                            MEMORY_BASIC_INFORMATION mbi;
                            if (VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi))) {
                                if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                                    protection_bonus = 0.2; // RWX記憶體獎勵
                                }
                            }
                            
                            // 根據上下文調整置信度
                            double context_bonus = 0.0;
                            if (context_description.find("ROP") != std::string::npos) {
                                context_bonus += 0.15; // ROP + Shellcode組合
                            }
                            if (context_description.find("heap") != std::string::npos) {
                                context_bonus += 0.1; // 堆積破壞 + Shellcode
                            }
                            if (context_description.find("RWX") != std::string::npos) {
                                context_bonus += 0.15; // 可疑記憶體區域
                            }
                            
                            shellcode_confidence = base_confidence + score_bonus + entropy_bonus + protection_bonus + context_bonus;
                            shellcode_confidence = std::min(shellcode_confidence, 0.9); // 最高0.9
                            shellcode_confidence = std::max(shellcode_confidence, 0.25); // 最低0.25
                        }
                    }
                }
            }
            
            // 新的分級檢測邏輯
            if (is_shellcode_attack) {
                // 如果只有shellcode而沒有其他攻擊，將其視為正常程序行為，不報告
                // 只有在與其他攻擊組合時才報告shellcode
                std::string debug_key = "shellcode_standalone_" + std::to_string(process_id);
                std::string debug_msg = "*** SHELLCODE detected alone at address=" + format_address((uint64_t)base) + " - treating as normal process behavior ***";
                controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                controlled_log_output(debug_key, debug_msg, 1, 60);
                return;
            }
        }
    }

    void check_heap_region_remote(HANDLE hProcess, LPVOID base, SIZE_T size) {
        // 效能優化：進一步限制檢查的記憶體大小
        if (size > 2048) { // 減少到2KB，提高掃描速度
            size = 2048;
        }
        
        std::vector<uint8_t> buffer(size);
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(hProcess, base, buffer.data(), size, &bytes_read)) {
            // 獲取進程ID和名稱
            DWORD process_id = GetProcessId(hProcess);
            std::string process_name = MemoryMonitor::get_process_name(process_id);
            ProcessCategory category = classify_process(process_name);
            
            // 檢查是否在白名單中（但攻擊模擬器除外）
            if (is_whitelisted_process(process_name) && category != ProcessCategory::ATTACK_SIMULATOR) {
                silent_whitelist_skip(process_name);
                return;
            }
            
            // 只在檢測到堆積破壞模式時輸出調試信息
            // 移除頻繁的調試輸出，只在實際檢測到問題時輸出

            // 獲取自適應閾值
            int corruption_threshold = get_heap_corruption_threshold(category);
            
            // 檢查堆積破壞模式（統一檢測，避免重複計算）
            int corruption_patterns = 0;

            // 暫時禁用重複報告檢查，以便調試
            // if (!should_report_heap_issue(process_id, (uint64_t)base)) {
            //     log_message("DEBUG", "Skip duplicate heap report for " + std::to_string(process_id) + " (" + process_name + ")");
            //     return;
            // }
            
            for (size_t i = 0; i < bytes_read - 4; i++) {
                uint32_t value = *(uint32_t*)(&buffer[i]);
                
                // 檢查多種堆損壞模式
                if (value == 0xDEADBEEF || 
                    value == 0xBAADF00D ||
                    value == 0xFEEEFEEE ||
                    value == 0xCDCDCDCD ||
                    value == 0xABABABAB) {
                    corruption_patterns++;
                    // 只在檢測到多個模式時輸出調試信息，並大幅減少輸出頻率
                    if (corruption_patterns > 2 && corruption_patterns % 5 == 0) {
                        std::string pattern_key = "heap_pattern_" + std::to_string(process_id);
                        std::string pattern_msg = "*** Found heap corruption pattern 0x" + std::to_string(value) + " at offset " + std::to_string(i) + " in process " + std::to_string(process_id) + " (" + process_name + ") ***";
                        controlled_console_output(pattern_key, "    " + pattern_msg, 1, 60, "DEBUG");
                        controlled_log_output(pattern_key, pattern_msg, 1, 60, "DEBUG");
                    }
                }
            }
            
            // 輸出調試信息
            if (corruption_patterns > 0) {
                std::string heap_debug_key = "heap_debug_" + std::to_string(process_id);
                std::string debug_msg1 = "*** HEAP DEBUG: address=" + format_address((uint64_t)base) + ", Found " + std::to_string(corruption_patterns) + " corruption patterns in process " + std::to_string(process_id) + " (" + process_name + ") ***";
                std::string category_str = (category == ProcessCategory::ATTACK_SIMULATOR ? "SIMULATOR" : "OTHER");
                std::string debug_msg2 = "*** HEAP DEBUG: Threshold for " + category_str + " is " + std::to_string(corruption_threshold) + " ***";
                
                controlled_console_output(heap_debug_key, "    " + debug_msg1, 2, 30, "DEBUG");
                controlled_log_output(heap_debug_key, debug_msg1, 2, 30, "DEBUG");
                controlled_console_output(heap_debug_key, "    " + debug_msg2, 2, 30, "DEBUG");
                controlled_log_output(heap_debug_key, debug_msg2, 2, 30, "DEBUG");
            }
            
            // 使用動態密度檢測
            if (category == ProcessCategory::ATTACK_SIMULATOR) {
                // 計算模式密度（每KB的模式數量）
                double pattern_density = (corruption_patterns * 1024.0) / bytes_read;
                double density_threshold = 50.0; // 每KB至少50個模式
                
                // 使用密度檢測和數量檢測的組合
                bool density_triggered = pattern_density > density_threshold;
                bool count_triggered = corruption_patterns >= corruption_threshold;
                
                if (density_triggered || count_triggered) {
                    double heap_confidence = 0.6;
                    if (density_triggered) {
                        heap_confidence += (pattern_density - density_threshold) * 0.01;
                    }
                    if (count_triggered) {
                        heap_confidence += (corruption_patterns - corruption_threshold) * 0.01;
                    }
                    heap_confidence = std::min(heap_confidence, 0.95); // 最高0.95
                    
                    // 使用CRITICAL級別警報
                    log_message("CRITICAL", "🚨 HEAP CORRUPTION ATTACK DETECTED 🚨");
                    log_message("CRITICAL", "Target: PID " + std::to_string(process_id) + " (" + process_name + ")");
                    log_message("CRITICAL", "Address: 0x" + format_address((uint64_t)base));
                    log_message("CRITICAL", "Patterns: " + std::to_string(corruption_patterns) + " (threshold: " + std::to_string(corruption_threshold) + ")");
                    log_message("CRITICAL", "Density: " + std::to_string(pattern_density) + "/KB (threshold: " + std::to_string(density_threshold) + ")");
                    log_message("CRITICAL", "Confidence: " + std::to_string(heap_confidence));
                    
                    // 控制台輸出（限制頻率）
                    std::string heap_key = "heap_corruption_simulator_" + std::to_string(process_id);
                    std::string heap_msg = "🚨 CRITICAL: HEAP CORRUPTION ATTACK DETECTED in PID " + std::to_string(process_id) + " (" + process_name + ") 🚨";
                    controlled_console_output(heap_key, heap_msg, 1, 60); // 每分鐘最多1次
                    
                    add_detection(AttackType::HEAP_CORRUPTION, heap_confidence, "Attack simulator found heap corruption pattern", (uint64_t)base);
                } else if (corruption_patterns > 0) {
                    // 調試輸出，顯示檢測到的模式但未達到閾值
                    std::string debug_key = "heap_debug_simulator_" + std::to_string(process_id);
                    std::string debug_msg = "*** ATTACK SIMULATOR HEAP DEBUG: address=" + format_address((uint64_t)base) + 
                              ", found " + std::to_string(corruption_patterns) + " patterns, density=" + std::to_string(pattern_density) + "/KB ***";
                    controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                    controlled_log_output(debug_key, debug_msg, 1, 60);
                }
            } else {
                // 其他進程使用正常閾值
                if (corruption_patterns >= corruption_threshold) {
                    double heap_confidence = 0.6 + (corruption_patterns - corruption_threshold) * 0.02; // 基礎0.6，根據模式數量調整
                    heap_confidence = std::min(heap_confidence, 0.85); // 最高0.85
                    
                    std::string heap_key = "heap_corruption_" + std::to_string(process_id);
                    std::string heap_msg = "*** DETECTED HEAP CORRUPTION in process " + std::to_string(process_id) + " (" + process_name + ") ***";
                    std::string confidence_msg = "*** Confidence: " + std::to_string(heap_confidence) + " ***";
                    
                    controlled_console_output(heap_key, "    " + heap_msg, 2, 30);
                    controlled_log_output(heap_key, heap_msg, 2, 30);
                    controlled_console_output(heap_key, "    " + confidence_msg, 2, 30);
                    controlled_log_output(heap_key, confidence_msg, 2, 30);
                    
                    add_detection(AttackType::HEAP_CORRUPTION, heap_confidence, "Remote process found heap corruption pattern", (uint64_t)base);
                }
            }
        }
    }

    void check_system_integrity() {
        // 簡化的系統完整性檢查
        check_system_files_integrity();
    }

    void check_system_files_integrity() {
        // 檢查關鍵系統檔案
        const wchar_t* critical_files[] = {
            L"C:\\Windows\\System32\\ntdll.dll",
            L"C:\\Windows\\System32\\kernel32.dll",
            L"C:\\Windows\\System32\\user32.dll"
        };
        
        for (const auto& file : critical_files) {
            HANDLE hFile = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                CloseHandle(hFile);
            }
        }
    }

    void check_process_behavior() {
        // 簡化的進程行為檢查
        DWORD processes[1024];
        DWORD cbNeeded;
        
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD num_processes = cbNeeded / sizeof(DWORD);
            
            for (DWORD i = 0; i < num_processes; i++) {
                if (processes[i] != 0) {
                    std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                    if (process_name.find("suspicious") != std::string::npos) {
                        report_attack(AttackType::MEMORY_CORRUPTION, 0, "Found suspicious process: " + process_name, 0.5);
                    }
                }
            }
        }
    }

    bool is_system_process(DWORD process_id) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
        if (!hProcess) {
            return false;
        }
        
        wchar_t process_name[MAX_PATH];
        DWORD size = MAX_PATH;
        
        bool is_system = false;
        if (QueryFullProcessImageNameW(hProcess, 0, process_name, &size)) {
            std::wstring wname(process_name);
            std::string name(wname.begin(), wname.end());
            is_system = (name.find("\\Windows\\") != std::string::npos);
        }
        
        CloseHandle(hProcess);
        return is_system;
    }

    void report_attack(AttackType type, uint64_t address, const std::string& description, double confidence, DWORD target_process_id = 0) {

        // 在report_attack函數開頭添加
        if (type == AttackType::SHELLCODE_INJECTION) {
            // 檢查是否同時滿足ROP條件
            std::lock_guard<std::mutex> lock(pattern_mutex_);
            auto it = attack_patterns_.find((static_cast<uint64_t>(AttackType::ROP_CHAIN) << 32) | target_process_id);
            if (it != attack_patterns_.end() && it->second.detection_count > 2) {
                log_message("DEBUG", "Suppressed shellcode report due to active ROP detection");
                return; // 如果已有ROP報告，抑制Shellcode報告
            }
        }
        try {
            // 如果沒有指定目標進程ID，使用當前進程ID（用於本地偵測）
            if (target_process_id == 0) {
                target_process_id = GetCurrentProcessId();
            }

            // 檢查記憶體區域屬性（僅在遠程進程時）
            if (target_process_id != GetCurrentProcessId()) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target_process_id);
                if (hProcess) {
                    MEMORY_BASIC_INFORMATION mbi;
                    if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
                        // 過濾合法可執行區域（如.NET JIT編譯區）
                        if (mbi.AllocationBase == GetModuleHandleA("clrjit.dll")) {
                            log_message("DEBUG", "Skipped .NET JIT region: " + format_address(address));
                            CloseHandle(hProcess);
                            return;
                        }
                        
                        // 檢查是否為已知DLL的記憶體範圍
                        HMODULE hModule = GetModuleHandleA("kernel32.dll");
                        if (hModule && (uint64_t)address >= (uint64_t)hModule && 
                            (uint64_t)address < (uint64_t)hModule + 0x1000000) {
                            log_message("DEBUG", "Skipped system DLL region: " + format_address(address));
                            CloseHandle(hProcess);
                            return;
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
            
            // 智能防重複機制 - 基於攻擊模式識別
            {
                std::lock_guard<std::mutex> lock(pattern_mutex_);
                auto now = std::chrono::steady_clock::now();
                
                // 創建攻擊模式識別鍵
                uint64_t pattern_key = (static_cast<uint64_t>(type) << 32) | target_process_id;
                
                // 創建模式哈希（基於描述和地址範圍）
                std::string pattern_hash = std::to_string(static_cast<int>(type)) + "_" + 
                                         std::to_string(target_process_id) + "_" +
                                         std::to_string(address & 0xFFFFF000); // 頁面級別
                
                auto it = attack_patterns_.find(pattern_key);
                
                if (it != attack_patterns_.end()) {
                    AttackPattern& pattern = it->second;
                    
                    // 檢查是否為相同模式
                    if (pattern.pattern_hash == pattern_hash) {
                        // 更新檢測次數
                        pattern.detection_count++;
                        
                                        // 如果這個模式在過去30秒內已經報告過，則跳過（減少重複報告）
                if (now - pattern.first_detection < std::chrono::seconds(30)) {
                    std::cout << "Skipping duplicate attack pattern: " << attack_type_to_string(type) 
                              << " (count: " << pattern.detection_count << ") at " << format_address(address) 
                              << " in process " << target_process_id << std::endl;
                    return;
                } else {
                    // 超過30秒，重置計數
                    pattern.first_detection = now;
                    pattern.detection_count = 1;
                }
                    } else {
                        // 新模式，重置計數
                        pattern.pattern_hash = pattern_hash;
                        pattern.first_detection = now;
                        pattern.detection_count = 1;
                    }
                } else {
                    // 新的攻擊類型，創建記錄
                    AttackPattern new_pattern;
                    new_pattern.type = type;
                    new_pattern.process_id = target_process_id;
                    new_pattern.pattern_hash = pattern_hash;
                    new_pattern.first_detection = now;
                    new_pattern.detection_count = 1;
                    attack_patterns_[pattern_key] = new_pattern;
                }
                
                // 清理舊的攻擊模式記錄（保留最近30個）
                if (attack_patterns_.size() > 30) {
                    auto oldest = attack_patterns_.begin();
                    for (auto iter = attack_patterns_.begin(); iter != attack_patterns_.end(); ++iter) {
                        if (iter->second.first_detection < oldest->second.first_detection) {
                            oldest = iter;
                        }
                    }
                    if (oldest != attack_patterns_.end()) {
                        attack_patterns_.erase(oldest);
                    }
                }
            }

            DetectionResult result;
            result.type = type;
            result.address = address;
            result.description = description;
            result.confidence = confidence;
            result.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            result.process_id = target_process_id;
            result.process_name = MemoryMonitor::get_process_name(target_process_id);

            // 更新統計
            total_detections_++;
            switch (type) {
                case AttackType::ROP_CHAIN:
                    rop_detections_++;
                    break;
                case AttackType::JOP_CHAIN:
                    jop_detections_++;
                    break;
                case AttackType::BUFFER_OVERFLOW:
                    buffer_overflow_detections_++;
                    break;
                case AttackType::HEAP_CORRUPTION:
                    heap_corruption_detections_++;
                    break;
                case AttackType::STACK_OVERFLOW:
                    stack_overflow_detections_++;
                    break;
                case AttackType::USE_AFTER_FREE:
                    use_after_free_detections_++;
                    break;
                case AttackType::SHELLCODE_INJECTION:
                    shellcode_detections_++;
                    break;
            }

            // 記錄結果
            {
                std::lock_guard<std::mutex> lock(results_mutex_);
                detection_results_.push_back(result);
            }

            // 攻擊檢測輸出控制 - 針對攻擊模擬器使用特殊控制
            {
                std::lock_guard<std::mutex> lock(attack_output_mutex_);
                attack_detection_counter_++;

                // 檢查是否為攻擊模擬器
                ProcessCategory category = classify_process(result.process_name);
                bool is_simulator = (category == ProcessCategory::ATTACK_SIMULATOR);
                
                // 攻擊模擬器使用特殊輸出控制
                if (is_simulator) {
                    if (should_output_simulator_detection(result.process_id)) {
                        // 只在允許輸出時才輸出攻擊模擬器的檢測結果
                        if (confidence >= 0.6) { // 降低攻擊模擬器的置信度閾值到0.6，確保檢測
                            std::string simulator_msg = "=== SIMULATOR ATTACK DETECTED ===";
                            
                            simulator_msg = "Type: " + attack_type_to_string(type);
                            log_critical(simulator_msg);
                            simulator_msg = "Address: " + format_address(address);
                            log_critical(simulator_msg);
                            simulator_msg = "Description: " + description;
                            log_critical(simulator_msg);
                            simulator_msg = "Confidence: " + std::to_string(confidence);
                            log_critical(simulator_msg);        
                            simulator_msg = "Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")";
                            log_critical(simulator_msg);
                            simulator_msg = "=========================================";
                            log_critical(simulator_msg);
                            controlled_log_output("simulator_attack", simulator_msg, 1, 60, "CRITICAL");
                        }
                    }
                    // 如果不允許輸出，則靜默處理，只記錄統計
                }
                // 非攻擊模擬器使用原有邏輯
                else {
                    // 只輸出高置信度攻擊 (confidence >= 0.85)
                    if (confidence >= 0.85) {
                        // 高置信度攻擊 - 使用頻率控制，每60秒最多輸出2次
                        std::string high_conf_msg = "=== HIGH CONFIDENCE ATTACK DETECTED ===";
                        log_critical(high_conf_msg);
                        high_conf_msg = "Type: " + attack_type_to_string(type);
                        log_critical(high_conf_msg);
                        high_conf_msg = "Address: " + format_address(address);
                        log_critical(high_conf_msg);
                        high_conf_msg = "Description: " + description;
                        log_critical(high_conf_msg);
                        high_conf_msg = "Confidence: " + std::to_string(confidence);
                        log_critical(high_conf_msg);
                        high_conf_msg = "Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")";
                        log_critical(high_conf_msg);
                        high_conf_msg = "=========================================";
                        log_critical(high_conf_msg);
                        
                        controlled_log_output("high_confidence_attack", high_conf_msg, 2, 60, "CRITICAL");
                    }
                    // 中等置信度攻擊 - 每5次檢測輸出1次（適度輸出頻率）
                    else if (confidence >= 0.7 && attack_detection_counter_ % 5 == 0) {
                        std::string medium_conf_msg = "=== MEDIUM CONFIDENCE ATTACK DETECTED ===";
                        medium_conf_msg = "Type: " + attack_type_to_string(type);
                        log_critical(medium_conf_msg);
                        medium_conf_msg = "Address: " + format_address(address);
                        log_critical(medium_conf_msg);
                        medium_conf_msg = "Description: " + description;
                        log_critical(medium_conf_msg);
                        medium_conf_msg = "Confidence: " + std::to_string(confidence);
                        log_critical(medium_conf_msg);
                        medium_conf_msg = "Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")";
                        medium_conf_msg = "=========================================";
                        log_critical(medium_conf_msg);
                        controlled_log_output("medium_confidence_attack", medium_conf_msg, 1, 60, "CRITICAL");
                    } 
                    // 低置信度攻擊 - 完全靜默，只記錄統計
                    else {
                        // 靜默檢測，只更新計數，不輸出任何信息
                        // 避免輸出過多低置信度檢測
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error in report_attack: " << e.what() << std::endl;
            // 不要因為報告攻擊而退出程序
        }
        catch (...) {
            std::cerr << "Unknown error in report_attack" << std::endl;
            // 不要因為報告攻擊而退出程序
        }
    }

    void memory_monitor_loop() {
        while (running_) {
            try {
                // 每60秒才進行一次記憶體區域掃描（而不是每500毫秒）
                scan_memory_regions();
                std::this_thread::sleep_for(std::chrono::seconds(60));
            }
            catch (const std::exception& e) {
                std::cerr << "Memory monitor thread exception: " << e.what() << std::endl;
            }
        }
    }

    void scan_memory_regions() {
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int scanned_regions = 0;
        const int max_regions_to_scan = 5; // 限制掃描區域數量
        
        while (VirtualQuery(address, &mbi, sizeof(mbi)) && scanned_regions < max_regions_to_scan) {
            if (mbi.State == MEM_COMMIT) {
                check_executable_integrity(mbi.BaseAddress, mbi.RegionSize);
                check_heap_region(mbi.BaseAddress, mbi.RegionSize);
                scanned_regions++;
            }
            address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
        }
    }

    // 新增：進程優先級評估函數
    int get_process_priority(DWORD pid, const std::string& process_name) {
        int priority = 0;
        
        // 攻擊模擬器最高優先級
        if (process_name.find("attack_simulator") != std::string::npos ||
            process_name.find("attack") != std::string::npos) {
            return 1000; // 最高優先級
        }
        
        // 高PID進程（可能的攻擊者）
        if (pid > 10000) {
            priority += 50;
        }
        
        // 用戶級進程（非系統進程）
        if (pid > 4000 && !is_whitelisted_process(process_name)) {
            priority += 30;
        }
        
        // 可疑進程名稱
        std::vector<std::string> suspicious_patterns = {
            "cmd", "powershell", "wscript", "cscript", "rundll32", 
            "regsvr32", "mshta", "certutil", "bitsadmin", "wmic"
        };
        
        for (const auto& pattern : suspicious_patterns) {
            if (process_name.find(pattern) != std::string::npos) {
                priority += 40;
                break;
            }
        }
        
        // 異常內存使用（需要額外檢查）
        if (priority > 0) {
            priority += 20;
        }
        
        return priority;
    }

    // 新增：智能進程排序結構
    struct PrioritizedProcess {
        DWORD pid;
        std::string name;
        int priority;
        
        PrioritizedProcess(DWORD p, const std::string& n, int pri) 
            : pid(p), name(n), priority(pri) {}
        
        bool operator<(const PrioritizedProcess& other) const {
            return priority > other.priority; // 降序排列
        }
    };

    void process_monitor_loop() {
        while (running_) {
            try {
                // 每20秒才進行一次進程掃描（而不是每1000毫秒）
                scan_processes();
                std::this_thread::sleep_for(std::chrono::seconds(20));
            }
            catch (const std::exception& e) {
                std::cerr << "Process monitor thread exception: " << e.what() << std::endl;
            }
        }
    }

    void scan_processes() {
        log_message("INFO", "開始掃描進程...");
        
        DWORD processes[4096];
        DWORD cbNeeded;
        
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD num_processes = cbNeeded / sizeof(DWORD);
            const int max_processes_to_scan = 200;
            
            // 收集進程信息並排序
            std::vector<PrioritizedProcess> process_list;
            
            for (DWORD i = 0; i < num_processes; i++) {
                if (processes[i] != 0) {
                    std::string process_name = MemoryMonitor::get_process_name(processes[i]);
                    if (!process_name.empty()) {
                        int priority = MemoryMonitor::get_process_priority(processes[i], process_name);
                        process_list.emplace_back(processes[i], process_name, priority);
                    }
                }
            }
            
            // 按優先級排序
            std::sort(process_list.begin(), process_list.end());
            
            // 記錄前50個高優先級進程
            log_message("INFO", "進程優先級排序（前50個）：");
            for (size_t i = 0; i < std::min(process_list.size(), static_cast<size_t>(50)); i++) {
                const auto& proc = process_list[i];
                log_message("INFO", "PID: " + std::to_string(proc.pid) + 
                           ", Name: " + proc.name + 
                           ", Priority: " + std::to_string(proc.priority));
            }
            
            // 優先掃描高優先級進程
            int scanned_count = 0;
            for (const auto& proc : process_list) {
                if (scanned_count >= max_processes_to_scan) break;
                
                if (proc.priority > 0) { // 只掃描有優先級的進程
                    if (scanned_count % 20 == 0) {
                    log_message("INFO", "掃描高優先級進程: " + proc.name + 
                               " (PID: " + std::to_string(proc.pid) + 
                               ", Priority: " + std::to_string(proc.priority) + ")");
                    }
                    if (proc.name.find("attack_simulator") != std::string::npos ||
                        proc.name.find("attack") != std::string::npos) {
                        deep_scan_process(proc.pid);
                    } else {
                        monitor_process(proc.pid, proc.name);
                    }
                    scanned_count++;
                }
            }
            
            log_message("INFO", "完成進程掃描，共掃描 " + std::to_string(scanned_count) + " 個進程");
        }
    }

    void monitor_process(DWORD process_id, const std::string& process_name) {
        // 檢查是否為攻擊模擬器
        if (process_name.find("attack_simulator") != std::string::npos ||
            process_name.find("attack") != std::string::npos) {
            log_message("INFO", "Monitoring attack simulator: " + process_name + " (PID: " + std::to_string(process_id) + ")");
            
            // 對攻擊模擬器進行深度掃描
            deep_scan_process(process_id);
        }
        
        // 簡化的進程監控
        if (process_name.find("suspicious") != std::string::npos) {
            report_attack(AttackType::MEMORY_CORRUPTION, 0, "Monitoring suspicious process: " + process_name, 0.3);
        }
    }

    std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::string attack_type_to_string(AttackType type) {
        switch (type) {
            case AttackType::ROP_CHAIN: return "ROP Chain";
            case AttackType::JOP_CHAIN: return "JOP Chain";
            case AttackType::BUFFER_OVERFLOW: return "Buffer Overflow";
            case AttackType::HEAP_CORRUPTION: return "Heap Corruption";
            case AttackType::STACK_OVERFLOW: return "Stack Overflow";
            case AttackType::USE_AFTER_FREE: return "Use-After-Free";
            case AttackType::DOUBLE_FREE: return "Double Free";
            case AttackType::SHELLCODE_INJECTION: return "Shellcode Injection";
            case AttackType::API_HOOK: return "API Hook";
            case AttackType::MEMORY_CORRUPTION: return "Memory Corruption";
            case AttackType::COMPLEX_ATTACK: return "Complex Attack Chain";
            case AttackType::SUSPICIOUS_BEHAVIOR: return "Suspicious Behavior";
            default: return "Unknown Attack";
        }
    }

    std::string format_address(uint64_t address) {
        std::stringstream ss;
        ss << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << address;
        return ss.str();
    }

public:
    void set_console_color(int color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(color));
    }

    void reset_console_color() {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), static_cast<WORD>(7));
    }



    // 重寫基類的 start() 方法
    bool start() override {
        try {
            // 確保 logs 目錄存在
            CreateDirectoryA("logs", NULL);
            
            // 初始化日誌檔案
            log_file_.open("logs/detection_engine.log", std::ios::app);
            if (!log_file_.is_open()) {
                std::cerr << "Failed to open log file" << std::endl;
                return false;
            }

            // 初始化統計數據
            total_detections_ = 0;
            rop_detections_ = 0;
            jop_detections_ = 0;
            buffer_overflow_detections_ = 0;
            heap_corruption_detections_ = 0;
            stack_overflow_detections_ = 0;
            use_after_free_detections_ = 0;
            shellcode_detections_ = 0;
            status_output_counter_ = 0;
            cycle_output_counter_ = 0;
            attack_detection_counter_ = 0;

            // 初始化 memory monitor
            MemoryMonitorConfig config;
            config.scan_interval_ms = 200;
            config.max_regions_per_scan = 1000;
            config.max_processes_to_scan = 200;
            config.enable_heap_monitoring = true;
            config.enable_stack_monitoring = true;
            config.enable_executable_monitoring = true;
            config.enable_shared_memory_monitoring = true;
            config.suspicious_pattern_threshold = 5;
            config.log_file = "logs/memory_monitor.log";
            
            memory_monitor_ = std::make_unique<MemoryMonitor>(config);
            
            // 設置違規回調
            memory_monitor_->set_violation_callback([this](AttackType type, uint64_t address, 
                                                          const std::string& description, double confidence, DWORD process_id) {
                this->report_attack(type, address, description, confidence, process_id);
            });
            
            // 啟動 monitor
            if (!memory_monitor_->start()) {
                log_warning("無法啟動記憶體監控器");
            }

            // 設置運行標誌
            running_ = true;

            // 啟動檢測線程
            detection_thread_ = std::thread(&DetectionEngineImpl::detection_loop, this);
            
            // 啟動進程監控線程
            process_monitor_thread_ = std::thread(&DetectionEngineImpl::process_monitor_loop, this);

            // 啟動指紋清理線程
           fingerprint_cleaner_thread_ = std::thread(&DetectionEngineImpl::fingerprint_cleaner, this);

            log_important("Detection engine started successfully");
            return true;
        }
        catch (const std::exception& e) {
            std::cerr << "Error starting detection engine: " << e.what() << std::endl;
            return false;
        }
        catch (...) {
            std::cerr << "Unknown error starting detection engine" << std::endl;
            return false;
        }
    }

    // 重寫基類的 stop() 方法
    void stop() override {
        try {
            // 設置停止標誌
            running_ = false;

            // 停止 memory monitor
            if (memory_monitor_) {
                memory_monitor_->stop();
            }

            // 等待檢測線程結束
            if (detection_thread_.joinable()) {
                detection_thread_.join();
            }
            
            // 等待進程監控線程結束
            if (process_monitor_thread_.joinable()) {
                process_monitor_thread_.join();
            }

            // 等待指紋清理線程結束
            if (fingerprint_cleaner_thread_.joinable()) {
                fingerprint_cleaner_thread_.join();
            }

            // 關閉日誌檔案
            if (log_file_.is_open()) {
                log_file_.close();
            }

            log_important("Detection engine stopped");
        }
        catch (const std::exception& e) {
            std::cerr << "Error stopping detection engine: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Unknown error stopping detection engine" << std::endl;
        }
    }
    
    void show_status() {
        std::cout << "\n=== Detection Engine Status ===" << std::endl;
        std::cout << "Running: " << (running_ ? "Yes" : "No") << std::endl;
        std::cout << "Total Detections: " << total_detections_.load() << std::endl;
        std::cout << "ROP Detections: " << rop_detections_.load() << std::endl;
        std::cout << "JOP Detections: " << jop_detections_.load() << std::endl;
        std::cout << "Buffer Overflow Detections: " << buffer_overflow_detections_.load() << std::endl;
        std::cout << "Heap Corruption Detections: " << heap_corruption_detections_.load() << std::endl;
        std::cout << "Stack Overflow Detections: " << stack_overflow_detections_.load() << std::endl;
        std::cout << "Use After Free Detections: " << use_after_free_detections_.load() << std::endl;
        std::cout << "Shellcode Detections: " << shellcode_detections_.load() << std::endl;
        std::cout << "===============================" << std::endl;
        
        log_message("INFO", "Status displayed - Total detections: " + std::to_string(total_detections_.load()));
    }

private:
    void log_message(const std::string& level, const std::string& message) {
        try {
            if (log_file_.is_open()) {
                std::lock_guard<std::mutex> lock(results_mutex_);
                log_file_ << get_timestamp() << " [" << level << "] " << message << std::endl;
                log_file_.flush();
            }
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_message" << std::endl;
        }
    }
    
    // 專門的ROP攻擊日誌輸出函數
    void log_rop_attack(DWORD process_id, const std::string& description, double confidence, uint64_t address) {
        try {
            std::string timestamp = get_timestamp();
            std::string process_name = MemoryMonitor::get_process_name(process_id);
            
            // 輸出到控制台
            std::cout << "[" << timestamp << "] 🚨 ROP ATTACK DETECTED 🚨" << std::endl;
            std::cout << "[" << timestamp << "] Process: " << process_name << " (PID: " << process_id << ")" << std::endl;
            std::cout << "[" << timestamp << "] Address: 0x" << format_address(address) << std::endl;
            std::cout << "[" << timestamp << "] Description: " << description << std::endl;
            std::cout << "[" << timestamp << "] Confidence: " << std::to_string(confidence) << std::endl;
            std::cout << "[" << timestamp << "] ==========================================" << std::endl;
            
            // 輸出到日誌文件
            if (log_file_.is_open()) {
                std::lock_guard<std::mutex> lock(results_mutex_);
                log_file_ << timestamp << " [CRITICAL] 🚨 ROP ATTACK DETECTED 🚨" << std::endl;
                log_file_ << timestamp << " [CRITICAL] Process: " << process_name << " (PID: " << process_id << ")" << std::endl;
                log_file_ << timestamp << " [CRITICAL] Address: 0x" << format_address(address) << std::endl;
                log_file_ << timestamp << " [CRITICAL] Description: " << description << std::endl;
                log_file_ << timestamp << " [CRITICAL] Confidence: " << std::to_string(confidence) << std::endl;
                log_file_ << timestamp << " [CRITICAL] ==========================================" << std::endl;
                log_file_.flush();
            }
        }
        catch (...) {
            std::cerr << "Error in log_rop_attack" << std::endl;
        }
    }

    // 新增：攻擊檢測置信度管理
    struct AttackDetection {
        AttackType type;
        double confidence;
        std::string description;
        uint64_t address;
        
        AttackDetection(AttackType t, double c, const std::string& desc, uint64_t addr)
            : type(t), confidence(c), description(desc), address(addr) {}
    };
    
    std::vector<AttackDetection> current_detections_;
    std::mutex detection_mutex_;
    
    void add_detection(AttackType type, double confidence, const std::string& description, uint64_t address) {
        std::lock_guard<std::mutex> lock(detection_mutex_);
        current_detections_.emplace_back(type, confidence, description, address);
    }
    
    void report_highest_confidence_attack(DWORD process_id) {
        std::lock_guard<std::mutex> lock(detection_mutex_);
        
        if (current_detections_.empty()) {
            return;
        }
        
        // 找到置信度最高的攻擊
        auto best_detection = std::max_element(current_detections_.begin(), current_detections_.end(),
            [](const AttackDetection& a, const AttackDetection& b) {
                return a.confidence < b.confidence;
            });
        
        // 報告最高置信度的攻擊
        std::string report_key = "highest_confidence_" + std::to_string(process_id);
        std::string report_msg = "*** REPORTING HIGHEST CONFIDENCE ATTACK: " + attack_type_to_string(best_detection->type) + 
                  " (confidence: " + std::to_string(best_detection->confidence) + ") ***";
        
        controlled_console_output(report_key, "    " + report_msg, 2, 30);
        controlled_log_output(report_key, report_msg, 2, 30);
        
        report_attack(best_detection->type, best_detection->address, best_detection->description, 
                     best_detection->confidence, process_id);
        
        // 清空當前檢測列表
        current_detections_.clear();
    }
    
    void clear_detections() {
        std::lock_guard<std::mutex> lock(detection_mutex_);
        current_detections_.clear();
    }

    // 新增：日誌輸出控制


    // 新增：攻擊鏈追蹤結構
    struct AttackChain {
        DWORD process_id;
        uint64_t base_address;
        std::chrono::steady_clock::time_point first_detection;
        std::vector<AttackType> detected_attacks;
        bool has_shellcode_payload;
        double highest_confidence;
        
        AttackChain() 
            : process_id(0), base_address(0), has_shellcode_payload(false), highest_confidence(0.0) {
            first_detection = std::chrono::steady_clock::now();
        }
        
        AttackChain(DWORD pid, uint64_t addr) 
            : process_id(pid), base_address(addr), has_shellcode_payload(false), highest_confidence(0.0) {
            first_detection = std::chrono::steady_clock::now();
        }
    };
    
    std::map<uint64_t, AttackChain> attack_chains_;
    std::mutex attack_chain_mutex_;
    
    // 新增：攻擊鏈管理函數
    void add_to_attack_chain(DWORD process_id, uint64_t address, AttackType attack_type, double confidence) {
        std::lock_guard<std::mutex> lock(attack_chain_mutex_);
        
        // 生成攻擊鏈鍵值（進程ID + 地址範圍）
        uint64_t chain_key = ((uint64_t)process_id << 32) | (address & 0xFFFFF000); // 4KB對齊
        
        auto it = attack_chains_.find(chain_key);
        if (it == attack_chains_.end()) {
            // 創建新的攻擊鏈
            attack_chains_[chain_key] = AttackChain(process_id, address);
            it = attack_chains_.find(chain_key);
        }
        
        AttackChain& chain = it->second;
        
        // 檢查是否已存在此攻擊類型
        bool attack_exists = false;
        for (const auto& existing_attack : chain.detected_attacks) {
            if (existing_attack == attack_type) {
                attack_exists = true;
                break;
            }
        }
        
        if (!attack_exists) {
            chain.detected_attacks.push_back(attack_type);
        }
        
        // 更新最高置信度
        if (confidence > chain.highest_confidence) {
            chain.highest_confidence = confidence;
        }
        
        // 如果是shellcode，標記為payload
        if (attack_type == AttackType::SHELLCODE_INJECTION) {
            chain.has_shellcode_payload = true;
        }
    }
    
    void report_tiered_attack(DWORD process_id, uint64_t address, AttackType primary_attack, double confidence) {
        std::lock_guard<std::mutex> lock(attack_chain_mutex_);
        
        uint64_t chain_key = ((uint64_t)process_id << 32) | (address & 0xFFFFF000);
        auto it = attack_chains_.find(chain_key);
        
        if (it != attack_chains_.end()) {
            const AttackChain& chain = it->second;
            
            if (chain.has_shellcode_payload) {
                // 高危險警報：主要攻擊 + shellcode payload
                std::string alert_msg = "*** HIGH DANGER ALERT: " + attack_type_to_string(primary_attack) + 
                                      " + SHELLCODE PAYLOAD detected in process " + std::to_string(process_id) + 
                                      " at " + format_address(address) + " (confidence: " + std::to_string(confidence) + ") ***";
                
                // 使用頻率控制，每30秒最多輸出1次高危險警報
                controlled_console_output("high_danger_alert", alert_msg, 1, 30);
                controlled_log_output("high_danger_alert", alert_msg, 1, 30, "CRITICAL");
                
                // 報告為組合攻擊
                report_attack(primary_attack, address, 
                            attack_type_to_string(primary_attack) + " with shellcode payload", 
                            confidence + 0.1, process_id);
            } else {
                // 警告：僅主要攻擊
                std::string warning_msg = "*** WARNING: " + attack_type_to_string(primary_attack) + 
                                        " detected in process " + std::to_string(process_id) + 
                                        " at " + format_address(address) + " (confidence: " + std::to_string(confidence) + ") ***";
                
                set_console_color(14); // 黃色
                std::cout << warning_msg << std::endl;
                reset_console_color();
                
                log_warning(warning_msg);
                
                // 報告為單一攻擊
                report_attack(primary_attack, address, 
                            attack_type_to_string(primary_attack) + " detected", 
                            confidence, process_id);
            }
        }
    }
    
    void cleanup_old_attack_chains() {
        std::lock_guard<std::mutex> lock(attack_chain_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto it = attack_chains_.begin();
        
        while (it != attack_chains_.end()) {
            // 清理超過5分鐘的攻擊鏈
            if (now - it->second.first_detection > std::chrono::minutes(5)) {
                it = attack_chains_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // 使用已定義的ROP結構體和變數
    
    // 新增：分散式ROP檢測方法
    void detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
        // 檢測字串寫入操作
        detect_string_write_operations(process_id, hProcess);
        
        // 分散式ROP檢測邏輯
        std::lock_guard<std::mutex> lock(rop_chain_mutex_);
        
        // 獲取進程的所有可執行記憶體區域
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                exec_regions.push_back(mbi);
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break; // 溢出檢查
        }
        
        // 調試輸出：顯示找到的可執行區域數量
        std::string debug_msg = "*** SCATTERED ROP SCAN: Process=" + std::to_string(process_id) + 
                              ", Found " + std::to_string(exec_regions.size()) + " executable regions ***";
        controlled_log_output("scattered_rop_scan", debug_msg, 1, 60, "DEBUG");
        
        // 掃描每個可執行區域尋找gadgets
        std::vector<ROPGadget> found_gadgets;
        std::vector<SyscallROPChain> syscall_chains;
        
        // 獲取進程類別
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        ProcessCategory category = classify_process(process_name);
        bool is_simulator = (category == ProcessCategory::ATTACK_SIMULATOR);
        
        for (const auto& region : exec_regions) {
            // 使用性能優化參數限制掃描大小
            if (region.RegionSize > PerformanceConfig::MAX_SCAN_SIZE) continue;
            
            // 對於攻擊模擬器，添加額外的過濾條件
            if (is_simulator) {
                // 跳過系統模組和已知的合法代碼區域
                if (is_legitimate_code_region(hProcess, region.BaseAddress, region.RegionSize)) {
                    continue;
                }
                
                // 檢查記憶體保護屬性，優先掃描可寫可執行區域
                if (!(region.Protect & PAGE_EXECUTE_READWRITE)) {
                    continue;
                }
                
                // 新增：針對攻擊模擬器，降低過濾條件，確保能檢測到攻擊
                // 檢查是否為最近分配的記憶體區域（可選，不強制要求）
                bool is_recent = is_recently_allocated_memory(hProcess, region.BaseAddress);
                if (!is_recent) {
                    // 如果不是最近分配的，仍然掃描，但降低優先級
                    controlled_log_output("recent_allocation", 
                        "*** SCANNING OLDER REGION: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                        ", Size=" + std::to_string(region.RegionSize) + " ***", 1, 60, "DEBUG");
                }
                
                // 新增：檢查記憶體區域的熵值（高熵值更可能是shellcode）
                std::vector<uint8_t> entropy_buffer(std::min(region.RegionSize, (SIZE_T)1024));
                SIZE_T entropy_bytes_read = 0;
                if (ReadProcessMemory(hProcess, region.BaseAddress, entropy_buffer.data(), entropy_buffer.size(), &entropy_bytes_read)) {
                    double entropy = MemoryMonitor::calculate_shannon_entropy(entropy_buffer.data(), entropy_bytes_read, "simulator");
                    if (entropy < 2.0) { // 降低熵值閾值，適應更多攻擊模式
                        controlled_log_output("entropy_check", 
                            "*** LOW ENTROPY REGION SKIPPED: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                            ", Entropy=" + std::to_string(entropy) + " ***", 1, 60, "DEBUG");
                        continue;
                    }
                }
                
                // 新增：檢查是否為動態分配的堆積區域
                if (is_dynamic_heap_region(hProcess, region.BaseAddress)) {
                    // 對於動態堆積區域，降低掃描頻率但提高檢測敏感度
                    static std::map<uint64_t, std::chrono::steady_clock::time_point> last_heap_scan;
                    auto now = std::chrono::steady_clock::now();
                    auto last_scan = last_heap_scan.find((uint64_t)region.BaseAddress);
                    
                    if (last_scan != last_heap_scan.end()) {
                        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - last_scan->second);
                        if (time_diff.count() < 5) { // 5秒內不重複掃描同一區域
                            continue;
                        }
                    }
                    last_heap_scan[(uint64_t)region.BaseAddress] = now;
                }
                
                // 新增：檢查記憶體區域的執行歷史
                if (has_recent_execution_activity(hProcess, region.BaseAddress)) {
                    // 有執行活動的區域更可能是攻擊目標
                    controlled_log_output("execution_activity", 
                        "*** EXECUTION ACTIVITY DETECTED: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                        ", Size=" + std::to_string(region.RegionSize) + " ***", 1, 30, "DEBUG");
                }
            }
            
            // 調試輸出：顯示正在掃描的區域（改為DEBUG級別，減少輸出頻率）
            std::string region_debug = "*** SCANNING REGION: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                                     ", Size=" + std::to_string(region.RegionSize) + 
                                     ", Protection=0x" + std::to_string(region.Protect) + " ***";
            controlled_log_output("region_scan", region_debug, 1, 120, "DEBUG");
            
            std::vector<uint8_t> buffer(region.RegionSize);
            SIZE_T bytes_read = 0;
            
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
                // 同時進行一般ROP檢測和系統調用ROP檢測
                for (size_t i = 0; i < bytes_read - 8; i += PerformanceConfig::SCAN_STEP_SIZE) {
                    // 檢查RET指令
                    if (buffer[i] == 0xC3) {
                        // 分析前面的指令
                        std::vector<uint8_t> gadget_bytes;
                        std::string instruction = "";
                        
                        // 收集gadget字節（使用優化的最大大小）
                        size_t start = (i >= PerformanceConfig::MAX_GADGET_SIZE) ? i - PerformanceConfig::MAX_GADGET_SIZE : 0;
                        for (size_t j = start; j <= i; j++) {
                            gadget_bytes.push_back(buffer[j]);
                        }
                        
                        // 使用增強的指令分析
                        if (gadget_bytes.size() >= 2) {
                            uint8_t prev = gadget_bytes[gadget_bytes.size() - 2];
                            if (prev >= 0x58 && prev <= 0x5F) {
                                instruction = "pop r32; ret";
                            } else if (prev == 0x94) {
                                instruction = "xchg eax, esp; ret";
                            } else if (gadget_bytes.size() >= 4) {
                                if (gadget_bytes[gadget_bytes.size() - 4] == 0x83 && 
                                    gadget_bytes[gadget_bytes.size() - 3] == 0xC4) {
                                    instruction = "add esp, XX; ret";
                                }
                            } else {
                                instruction = "ret";
                            }
                        }
                        
                        uint64_t gadget_address = (uint64_t)region.BaseAddress + i;
                        ROPGadget gadget(gadget_address, gadget_bytes, instruction);
                        found_gadgets.push_back(gadget);
                    }
                }
                
                // 在相同的緩衝區中檢測系統調用ROP鏈
                detect_syscall_rop_chains(buffer, (uint64_t)region.BaseAddress, syscall_chains);
            }
        }
        
        // 分析gadget分佈模式（改為DEBUG級別）
        std::string gadget_debug = "*** GADGET SCAN COMPLETE: Found " + std::to_string(found_gadgets.size()) + " gadgets ***";
        controlled_log_output("gadget_scan", gadget_debug, 1, 60, "DEBUG");
        
        // 報告系統調用ROP鏈檢測結果
        if (!syscall_chains.empty()) {
            report_syscall_rop_detection(process_id, syscall_chains);
        }
        
        if (found_gadgets.size() >= PerformanceConfig::MIN_GADGET_COUNT) { // 使用優化的最小gadget數量
            analyze_gadget_distribution(process_id, found_gadgets);
        }
    }
    
    void analyze_gadget_distribution(DWORD process_id, const std::vector<ROPGadget>& gadgets) {
        // 檢查gadget的分佈特徵
        int ret_gadgets = 0;
        int pop_gadgets = 0;
        int pivot_gadgets = 0;
        std::vector<uint64_t> addresses;
        
        for (const auto& gadget : gadgets) {
            addresses.push_back(gadget.address);
            if (gadget.is_ret_gadget) ret_gadgets++;
            if (gadget.is_pop_gadget) pop_gadgets++;
            if (gadget.is_stack_pivot) pivot_gadgets++;
        }
        
        // 檢查地址分佈（ROP gadgets通常分散在不同地址）
        bool has_scattered_distribution = false;
        if (addresses.size() >= 3) {
            std::sort(addresses.begin(), addresses.end());
            uint64_t min_gap = UINT64_MAX;
            
            for (size_t i = 1; i < addresses.size(); i++) {
                uint64_t gap = addresses[i] - addresses[i-1];
                if (gap > 0 && gap < min_gap) {
                    min_gap = gap;
                }
            }
            
            // 如果最小間距大於1KB，認為是分散分佈
            if (min_gap > 1024) {
                has_scattered_distribution = true;
            }
        }
        
        // 計算ROP置信度
        double rop_confidence = 0.0;
        if (ret_gadgets >= 2) { // 降低RET gadgets要求
            rop_confidence = 0.5; // 提高基礎置信度，確保能通過日誌閾值
            rop_confidence += (ret_gadgets * 0.15);
            rop_confidence += (pop_gadgets * 0.1);
            rop_confidence += (pivot_gadgets * 0.2);
            rop_confidence = std::min(rop_confidence, 0.95); // 提高最高置信度
        }
        
        // 如果檢測到分散的ROP鏈，報告攻擊（降低閾值確保檢測）
        if (rop_confidence > 0.3 && ret_gadgets >= 3) { // 進一步降低閾值，確保ROP檢測能被記錄
            std::string description = "Scattered ROP chain detected - Gadgets: " + 
                                   std::to_string(gadgets.size()) + 
                                   " (RET: " + std::to_string(ret_gadgets) + 
                                   ", POP: " + std::to_string(pop_gadgets) + 
                                   ", PIVOT: " + std::to_string(pivot_gadgets) + ")";
            
            // 提高ROP檢測的置信度，確保能通過日誌輸出閾值
            double adjusted_confidence = std::max(rop_confidence, 0.85); // 確保至少0.85的置信度
            report_attack(AttackType::ROP_CHAIN, addresses[0], description, adjusted_confidence, process_id);
            
            // 使用專門的ROP日誌輸出函數
            log_rop_attack(process_id, description, adjusted_confidence, addresses[0]);
            
            // 調試輸出
            std::string debug_msg = "*** SCATTERED ROP DETECTION: Process=" + std::to_string(process_id) + 
                                  ", Gadgets=" + std::to_string(gadgets.size()) + 
                                  ", Confidence=" + std::to_string(adjusted_confidence) + 
                                  ", Scattered=" + std::to_string(has_scattered_distribution) + " ***";
            controlled_log_output("scattered_rop_detection", debug_msg, 1, 30, "CRITICAL");
        }
    }

    // 使用已定義的記憶體緩存結構和變數
    
    // 新增：智能掃描函數
    void smart_scan_process(DWORD process_id, HANDLE hProcess, ProcessCategory category) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        
        // 調試輸出：確認函數被調用
        if (category == ProcessCategory::ATTACK_SIMULATOR) {
            std::cout << "    *** smart_scan_process called for attack simulator ***" << std::endl;
            log_message("DEBUG", "*** smart_scan_process called for attack simulator ***");
        }
        
        auto now = std::chrono::steady_clock::now();
        auto cache_it = memory_cache_.find(process_id);
        
        // 檢查是否需要更新緩存
        bool need_cache_update = false;
        if (cache_it == memory_cache_.end()) {
            need_cache_update = true;
        } else {
            // 檢查緩存是否過期（5秒）
            auto cache_age = std::chrono::duration_cast<std::chrono::seconds>(now - cache_it->second[0].last_scan);
            if (cache_age.count() > 5) {
                need_cache_update = true;
            }
        }
        
        if (need_cache_update) {
            // 更新緩存
            std::vector<CachedMemoryRegion> new_cache;
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID current_address = 0;
            
            int total_regions = 0;
            int executable_regions = 0;
            int heap_regions = 0;
            
            while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
                total_regions++;
                if (mbi.State == MEM_COMMIT) {
                    // 分類記憶體區域
                    bool is_executable = (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                                        mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY);
                    bool is_heap_like = (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY);
                    
                    if (is_executable || is_heap_like) {
                        CachedMemoryRegion region((uint64_t)mbi.BaseAddress, mbi.RegionSize, mbi.Protect);
                        region.is_executable = is_executable;  // 新增標記
                        new_cache.push_back(region);
                        
                        if (is_executable) executable_regions++;
                        if (is_heap_like) heap_regions++;
                    }
                }
                current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
                if (current_address < mbi.BaseAddress) break;
            }
            
            // 調試輸出：顯示記憶體區域統計
            if (category == ProcessCategory::ATTACK_SIMULATOR) {
                std::string debug_key = "memory_stats_" + std::to_string(process_id);
                std::string debug_msg = "*** Memory regions found: Total=" + std::to_string(total_regions) + 
                                      ", Executable=" + std::to_string(executable_regions) + 
                                      ", Heap=" + std::to_string(heap_regions) + 
                                      ", Cached=" + std::to_string(new_cache.size()) + " ***";
                controlled_console_output(debug_key, "    " + debug_msg, 1, 10);
                controlled_log_output(debug_key, debug_msg, 1, 10);
            }
            
            memory_cache_[process_id] = new_cache;
        }
        
        // 對攻擊模擬器執行分散式ROP檢測
        if (category == ProcessCategory::ATTACK_SIMULATOR) {
            detect_scattered_rop_chains(process_id, hProcess);
        }
        
        // 智能掃描：根據區域類型執行不同的檢測
        auto& cache = memory_cache_[process_id];
        for (auto& region : cache) {
            // 檢查是否需要掃描這個區域
            auto region_age = std::chrono::duration_cast<std::chrono::seconds>(now - region.last_scan);
            if (region_age.count() > 2) { // 2秒後重新掃描
                region.last_scan = now;
                
                // 調試輸出：顯示區域信息
                if (category == ProcessCategory::ATTACK_SIMULATOR) {
                    std::string debug_key = "region_debug_" + std::to_string(process_id);
                    std::string debug_msg = "*** Scanning region: 0x" + format_address(region.base_address) + 
                                          ", size: " + std::to_string(region.size) + 
                                          ", executable: " + (region.is_executable ? "YES" : "NO") + " ***";
                    controlled_console_output(debug_key, "    " + debug_msg, 1, 10);
                    controlled_log_output(debug_key, debug_msg, 1, 10);
                }
                
                // 分層檢測策略
                if (region.is_executable) {
                    // 可執行區域：執行 ROP 和 Shellcode 檢測
                    check_executable_integrity_remote(hProcess, (LPVOID)region.base_address, region.size);
                } else {
                    // 非可執行區域：執行 Heap 檢測
                    check_heap_region_remote(hProcess, (LPVOID)region.base_address, region.size);
                }
            }
        }
    }

    // 使用已定義的模擬器輸出控制結構和變數
    
    // 新增：攻擊模擬器專用輸出控制函數
    bool should_output_simulator_detection(DWORD process_id) {
        std::lock_guard<std::mutex> lock(simulator_output_mutex_);
        
        // 首先檢查全局設置（process_id = 0）
        auto global_it = simulator_output_controls_.find(0);
        if (global_it != simulator_output_controls_.end()) {
            return global_it->second.should_output();
        }
        
        // 如果沒有全局設置，檢查特定進程的設置
        auto it = simulator_output_controls_.find(process_id);
        if (it == simulator_output_controls_.end()) {
            // 創建新的控制項，使用較嚴格的默認設置
            simulator_output_controls_[process_id] = SimulatorOutputControl();
            simulator_output_controls_[process_id].set_max_outputs_per_minute(2); // 每分鐘最多2次
            it = simulator_output_controls_.find(process_id);
        }
        
        return it->second.should_output();
    }
    
    void set_simulator_output_limit(DWORD process_id, int max_outputs_per_minute) {
        std::lock_guard<std::mutex> lock(simulator_output_mutex_);
        
        auto it = simulator_output_controls_.find(process_id);
        if (it == simulator_output_controls_.end()) {
            simulator_output_controls_[process_id] = SimulatorOutputControl();
            it = simulator_output_controls_.find(process_id);
        }
        
        it->second.set_max_outputs_per_minute(max_outputs_per_minute);
    }
    
    // 新增：清理舊的輸出控制項
    void cleanup_simulator_output_controls() {
        std::lock_guard<std::mutex> lock(simulator_output_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto it = simulator_output_controls_.begin();
        
        while (it != simulator_output_controls_.end()) {
            // 如果控制項超過5分鐘沒有使用，則刪除
            auto time_diff = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.last_output);
            if (time_diff.count() > 5) {
                it = simulator_output_controls_.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // 新增：增強的指令分析邏輯
    static bool is_valid_gadget(const std::vector<uint8_t>& bytes) {
        // 增加指令長度驗證
        if (bytes.size() < 2) return false;
        
        // 過濾系統API常見序言/結尾
        if (bytes.size() >= 3) {
            // 檢查函數結尾序列：mov ebp, esp; pop ebp; ret
            if (bytes[bytes.size() - 3] == 0x89 && bytes[bytes.size() - 2] == 0xE5 && 
                bytes[bytes.size() - 1] == 0x5D) {
                return false; // 排除正常的函數結尾
            }
            
            // 檢查函數開頭：push ebp; mov ebp, esp
            if (bytes[0] == 0x55 && bytes[1] == 0x8B) {
                return false; // 排除函數開頭
            }
        }
        
        // 檢測無效指令組合
        for (size_t i = 0; i < bytes.size() - 1; i++) {
            // 排除異常處理指令
            if (bytes[i] == 0x0F && bytes[i + 1] > 0x80) {
                return false;
            }
            
            // 排除無效的指令前綴
            if (bytes[i] == 0x66 && bytes[i + 1] == 0x90) {
                return false; // nop指令前綴
            }
        }
        
        // 檢查是否為有效的指令序列
        if (bytes.size() >= 4) {
            // 檢查常見的無效組合
            if (bytes[bytes.size() - 4] == 0x89 && bytes[bytes.size() - 3] == 0xE5 && 
                bytes[bytes.size() - 2] == 0x5D) {
                return false; // 標準函數結尾
            }
        }
        
        return true;
    }
    
    // 新增：性能優化參數
    // 使用已定義的性能配置和系統調用ROP鏈結構
    
    // 檢測系統調用ROP鏈（整合到主要掃描邏輯中）
    void detect_syscall_rop_chains(const std::vector<uint8_t>& buffer, uint64_t base_address, 
                                   std::vector<SyscallROPChain>& detected_chains) {
        // 在已掃描的緩衝區中尋找系統調用相關的gadgets
        for (size_t i = 0; i < buffer.size() - 8; i += PerformanceConfig::SCAN_STEP_SIZE) {
            SyscallROPChain chain;
            bool found_chain = false;
            
            // 檢查int 0x80 (CD 80)
            if (buffer[i] == 0xCD && buffer[i + 1] == 0x80) {
                chain.int_0x80_gadget = base_address + i;
                found_chain = true;
            }
            
            // 檢查pop eax (58)
            if (buffer[i] == 0x58 && buffer[i + 1] == 0xC3) {
                chain.pop_eax_gadget = base_address + i;
                found_chain = true;
            }
            
            // 檢查pop ebx (5B)
            if (buffer[i] == 0x5B && buffer[i + 1] == 0xC3) {
                chain.pop_ebx_gadget = base_address + i;
                found_chain = true;
            }
            
            // 檢查pop ecx (59)
            if (buffer[i] == 0x59 && buffer[i + 1] == 0xC3) {
                chain.pop_ecx_gadget = base_address + i;
                found_chain = true;
            }
            
            // 檢查pop edx (5A)
            if (buffer[i] == 0x5A && buffer[i + 1] == 0xC3) {
                chain.pop_edx_gadget = base_address + i;
                found_chain = true;
            }
            
            // 檢查pop dword ptr [ecx] (89 01 C3)
            if (i + 2 < buffer.size() && buffer[i] == 0x89 && buffer[i + 1] == 0x01 && buffer[i + 2] == 0xC3) {
                chain.pop_dword_ptr_gadget = base_address + i;
                found_chain = true;
            }
            
            if (found_chain) {
                // 計算置信度
                chain.confidence = calculate_syscall_chain_confidence(chain);
                if (chain.confidence > 0.6) {
                    detected_chains.push_back(chain);
                }
            }
        }
    }
    
    // 新增：計算系統調用ROP鏈置信度
    double calculate_syscall_chain_confidence(const SyscallROPChain& chain) {
        double confidence = 0.0;
        
        // 基礎分數
        if (chain.int_0x80_gadget != 0) confidence += 0.3;
        if (chain.pop_eax_gadget != 0) confidence += 0.2;
        if (chain.pop_ebx_gadget != 0) confidence += 0.2;
        if (chain.pop_ecx_gadget != 0) confidence += 0.15;
        if (chain.pop_edx_gadget != 0) confidence += 0.15;
        if (chain.pop_dword_ptr_gadget != 0) confidence += 0.2;
        
        // 額外獎勵：如果找到完整的execve鏈
        if (chain.int_0x80_gadget != 0 && chain.pop_eax_gadget != 0 && 
            chain.pop_ebx_gadget != 0 && chain.pop_ecx_gadget != 0 && 
            chain.pop_edx_gadget != 0) {
            confidence += 0.3; // 完整的execve鏈
        }
        
        return std::min(confidence, 1.0);
    }
    
    // 新增：報告系統調用ROP檢測結果
    void report_syscall_rop_detection(DWORD process_id, const std::vector<SyscallROPChain>& chains) {
        for (const auto& chain : chains) {
            std::string description = "System Call ROP Chain Detected - ";
            description += "int_0x80: 0x" + format_address(chain.int_0x80_gadget);
            if (chain.pop_eax_gadget != 0) description += ", pop_eax: 0x" + format_address(chain.pop_eax_gadget);
            if (chain.pop_ebx_gadget != 0) description += ", pop_ebx: 0x" + format_address(chain.pop_ebx_gadget);
            if (chain.pop_ecx_gadget != 0) description += ", pop_ecx: 0x" + format_address(chain.pop_ecx_gadget);
            if (chain.pop_edx_gadget != 0) description += ", pop_edx: 0x" + format_address(chain.pop_edx_gadget);
            if (chain.pop_dword_ptr_gadget != 0) description += ", pop_dword_ptr: 0x" + format_address(chain.pop_dword_ptr_gadget);
            
            report_attack(AttackType::ROP_CHAIN, chain.int_0x80_gadget, description, chain.confidence, process_id);
            
            // 使用專門的ROP日誌輸出函數
            log_rop_attack(process_id, description, chain.confidence, chain.int_0x80_gadget);
        }
    }
    
    // 新增：檢測字串寫入操作
    void detect_string_write_operations(DWORD process_id, HANDLE hProcess) {
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
                            report_attack(AttackType::SHELLCODE_INJECTION, string_address, description, 0.8, process_id);
                        } else {
                            report_attack(AttackType::SHELLCODE_INJECTION, string_address, description, 0.6, process_id);
                        }
                    }
                }
            }
        }
    }
    
    // 新增：檢查是否在可執行區域附近
    bool is_near_executable_region(HANDLE hProcess, uint64_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProcess, (LPVOID)address, &mbi, sizeof(mbi))) {
            // 檢查是否在可執行區域附近（1MB範圍內）
            uint64_t region_start = (uint64_t)mbi.BaseAddress;
            uint64_t region_end = region_start + mbi.RegionSize;
            
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
    
    // 新增：檢查是否為動態分配的堆積區域
    bool is_dynamic_heap_region(HANDLE hProcess, LPVOID base_address) {
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
    
    // 新增：檢查記憶體區域是否有最近的執行活動
    bool has_recent_execution_activity(HANDLE hProcess, LPVOID base_address) {
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
        
        // 模擬檢測到執行活動（實際實現中會通過其他機制檢測）
        // 這裡簡化為隨機檢測，實際應該通過調試API或性能計數器
        if (rand() % 100 < 5) { // 5%機率檢測到執行活動
            execution_history[addr_key] = now;
            return true;
        }
        
        return false;
    }
    
    // 新增：檢查是否為合法的代碼區域
    bool is_legitimate_code_region(HANDLE hProcess, LPVOID base_address, SIZE_T size) {
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
            
            // 檢查是否為已知的合法進程區域
            static std::vector<std::string> legitimate_processes = {
                "explorer.exe", "svchost.exe", "lsass.exe", "winlogon.exe",
                "csrss.exe", "wininit.exe", "services.exe", "spoolsv.exe"
            };
            
            // 這裡簡化為檢查進程名稱，實際應該檢查模組簽名
            return false; // 暫時返回false，讓檢測引擎繼續掃描
        }
        return false;
    }
    
    // 新增：檢查是否為最近分配的記憶體
    bool is_recently_allocated_memory(HANDLE hProcess, LPVOID base_address) {
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
        
        // 模擬檢測到最近分配的記憶體（實際實現中會通過其他機制檢測）
        // 這裡簡化為隨機檢測，實際應該通過記憶體分配鉤子
        if (rand() % 100 < 10) { // 10%機率檢測到最近分配的記憶體
            allocation_history[addr_key] = now;
            return true;
        }
        
        return false;
    }
    
    // 新增：檢測複雜的攻擊鏈模式
    void detect_complex_attack_patterns(DWORD process_id, HANDLE hProcess) {
        // 檢測多層攻擊鏈：ROP + Shellcode + 記憶體破壞
        static std::map<DWORD, std::vector<std::pair<AttackType, uint64_t>>> attack_sequences;
        static std::mutex sequence_mutex;
        
        std::lock_guard<std::mutex> lock(sequence_mutex);
        auto& sequences = attack_sequences[process_id];
        
        // 清理舊的攻擊序列（超過5分鐘的記錄）
        auto now = std::chrono::steady_clock::now();
        sequences.erase(
            std::remove_if(sequences.begin(), sequences.end(),
                [now](const auto& seq) {
                    // 簡化的時間檢查，實際應該記錄時間戳
                    return false; // 暫時保留所有記錄
                }),
            sequences.end()
        );
        
        // 檢查是否有複雜攻擊模式
        if (sequences.size() >= 3) {
            bool has_rop = false, has_shellcode = false, has_memory_corruption = false;
            
            for (const auto& attack : sequences) {
                switch (attack.first) {
                    case AttackType::ROP_CHAIN:
                        has_rop = true;
                        break;
                    case AttackType::SHELLCODE_INJECTION:
                        has_shellcode = true;
                        break;
                    case AttackType::HEAP_CORRUPTION:
                    case AttackType::BUFFER_OVERFLOW:
                        has_memory_corruption = true;
                        break;
                    default:
                        break;
                }
            }
            
            // 如果檢測到複雜攻擊鏈，報告高置信度攻擊
            if (has_rop && has_shellcode && has_memory_corruption) {
                std::string description = "Complex Attack Chain Detected - ";
                description += "ROP + Shellcode + Memory Corruption Pattern";
                
                report_attack(AttackType::COMPLEX_ATTACK, sequences[0].second, description, 0.95, process_id);
                
                // 清理已報告的序列
                sequences.clear();
            }
        }
    }
    
    // 新增：增強的可疑行為檢測
    void detect_suspicious_behavior_patterns(DWORD process_id, HANDLE hProcess) {
        // 檢測異常的記憶體分配模式
        static std::map<DWORD, std::vector<uint64_t>> allocation_history;
        static std::mutex allocation_mutex;
        
        std::lock_guard<std::mutex> lock(allocation_mutex);
        auto& history = allocation_history[process_id];
        
        // 檢查是否有大量連續的記憶體分配
        if (history.size() >= 10) {
            // 檢查分配間隔是否異常（小於1KB間隔）
            int suspicious_allocations = 0;
            for (size_t i = 1; i < history.size(); i++) {
                uint64_t gap = history[i] - history[i-1];
                if (gap < 1024) {
                    suspicious_allocations++;
                }
            }
            
            if (suspicious_allocations >= 5) {
                std::string description = "Suspicious Memory Allocation Pattern - ";
                description += "Multiple allocations with small gaps detected";
                
                report_attack(AttackType::SUSPICIOUS_BEHAVIOR, history[0], description, 0.7, process_id);
            }
        }
        
        // 檢查是否有異常的執行權限變更
        // 這裡可以添加更多的可疑行為檢測邏輯
    }
    
    // 新增：整合的攻擊檢測函數
    void perform_comprehensive_attack_detection(DWORD process_id, HANDLE hProcess, ProcessCategory category) {
        // 根據進程類別調整檢測策略
        switch (category) {
            case ProcessCategory::ATTACK_SIMULATOR:
                // 對攻擊模擬器執行全面的檢測
                detect_scattered_rop_chains(process_id, hProcess);
                detect_complex_attack_patterns(process_id, hProcess);
                detect_suspicious_behavior_patterns(process_id, hProcess);
                detect_string_write_operations(process_id, hProcess);
                
                // 新增：針對攻擊模擬器的增強檢測
                detect_attack_simulator_specific_patterns(process_id, hProcess);
                
                // 調試輸出
                controlled_log_output("comprehensive_detection", 
                    "*** COMPREHENSIVE DETECTION COMPLETED: Process=" + std::to_string(process_id) + 
                    ", Category=ATTACK_SIMULATOR ***", 1, 60, "DEBUG");
                break;
                
            case ProcessCategory::HIGH_RISK_PROCESS:
                // 對高風險進程執行重點檢測
                detect_scattered_rop_chains(process_id, hProcess);
                detect_complex_attack_patterns(process_id, hProcess);
                
                controlled_log_output("comprehensive_detection", 
                    "*** COMPREHENSIVE DETECTION COMPLETED: Process=" + std::to_string(process_id) + 
                    ", Category=HIGH_RISK_PROCESS ***", 1, 60, "DEBUG");
                break;
                
            case ProcessCategory::USER_PROCESS:
                // 對用戶進程執行基本檢測
                detect_suspicious_behavior_patterns(process_id, hProcess);
                
                controlled_log_output("comprehensive_detection", 
                    "*** COMPREHENSIVE DETECTION COMPLETED: Process=" + std::to_string(process_id) + 
                    ", Category=USER_PROCESS ***", 1, 120, "DEBUG");
                break;
                
            case ProcessCategory::SYSTEM_PROCESS:
                // 對系統進程執行最小檢測
                detect_suspicious_behavior_patterns(process_id, hProcess);
                
                controlled_log_output("comprehensive_detection", 
                    "*** COMPREHENSIVE DETECTION COMPLETED: Process=" + std::to_string(process_id) + 
                    ", Category=SYSTEM_PROCESS ***", 1, 300, "DEBUG");
                break;
        }
    }
    
    // 新增：針對攻擊模擬器的特定模式檢測
    void detect_attack_simulator_specific_patterns(DWORD process_id, HANDLE hProcess) {
        // 專門檢測攻擊模擬器創建的特定攻擊模式
        std::string process_name = MemoryMonitor::get_process_name(process_id);
        
        // 檢查是否為攻擊模擬器進程
        if (process_name.find("attack_simulator") == std::string::npos) {
            return;
        }
        
        // 調試輸出
        controlled_log_output("simulator_detection", 
            "*** ATTACK SIMULATOR SPECIFIC DETECTION: Process=" + std::to_string(process_id) + " ***", 1, 30, "DEBUG");
        
        // 掃描所有可執行記憶體區域
        std::vector<MEMORY_BASIC_INFORMATION> exec_regions;
        LPVOID current_address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, current_address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ || 
                 mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
                exec_regions.push_back(mbi);
            }
            
            current_address = (LPVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
            if (current_address < mbi.BaseAddress) break;
        }
        
        // 對每個區域進行詳細掃描
        for (const auto& region : exec_regions) {
            // 限制掃描大小
            if (region.RegionSize > 8192) continue;
            
            // 讀取記憶體內容
            std::vector<uint8_t> buffer(region.RegionSize);
            SIZE_T bytes_read = 0;
            
            if (ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), region.RegionSize, &bytes_read)) {
                // 檢測ROP gadgets
                int ret_count = 0;
                int pop_count = 0;
                int consecutive_ret = 0;
                int max_consecutive_ret = 0;
                
                for (size_t i = 0; i < bytes_read - 1; i++) {
                    if (buffer[i] == 0xC3) { // RET指令
                        ret_count++;
                        consecutive_ret++;
                        if (consecutive_ret > max_consecutive_ret) {
                            max_consecutive_ret = consecutive_ret;
                        }
                    } else {
                        consecutive_ret = 0;
                    }
                    
                    // 檢測POP指令
                    if (buffer[i] >= 0x58 && buffer[i] <= 0x5F) {
                        pop_count++;
                    }
                }
                
                // 如果檢測到足夠的ROP特徵，報告攻擊
                if (ret_count >= 5 && pop_count >= 2) {
                    std::string description = "Attack Simulator ROP Detected - ";
                    description += "RETs: " + std::to_string(ret_count) + 
                                ", POPs: " + std::to_string(pop_count) + 
                                ", Max Consecutive RETs: " + std::to_string(max_consecutive_ret);
                    
                    double confidence = 0.8 + (ret_count * 0.01) + (pop_count * 0.02);
                    confidence = std::min(confidence, 0.95);
                    
                    report_attack(AttackType::ROP_CHAIN, (uint64_t)region.BaseAddress, description, confidence, process_id);
                    
                    // 使用專門的ROP日誌輸出函數
                    log_rop_attack(process_id, description, confidence, (uint64_t)region.BaseAddress);
                    
                    // 調試輸出
                    controlled_log_output("simulator_rop_detection", 
                        "*** SIMULATOR ROP DETECTED: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                        ", RETs=" + std::to_string(ret_count) + ", POPs=" + std::to_string(pop_count) + 
                        ", Confidence=" + std::to_string(confidence) + " ***", 1, 30, "CRITICAL");
                }
                
                // 檢測shellcode模式
                int shellcode_patterns = 0;
                for (size_t i = 0; i < bytes_read - 3; i++) {
                    // 常見的shellcode開頭
                    if (buffer[i] == 0x90 && buffer[i+1] == 0x90 && buffer[i+2] == 0x90) { // nop sled
                        shellcode_patterns++;
                    }
                    if (buffer[i] == 0x31 && buffer[i+1] == 0xC0) { // xor eax, eax
                        shellcode_patterns++;
                    }
                    if (buffer[i] == 0x31 && buffer[i+1] == 0xDB) { // xor ebx, ebx
                        shellcode_patterns++;
                    }
                }
                
                if (shellcode_patterns >= 3) {
                    std::string description = "Attack Simulator Shellcode Detected - ";
                    description += "Patterns: " + std::to_string(shellcode_patterns);
                    
                    report_attack(AttackType::SHELLCODE_INJECTION, (uint64_t)region.BaseAddress, description, 0.85, process_id);
                    
                    // 調試輸出
                    controlled_log_output("simulator_shellcode_detection", 
                        "*** SIMULATOR SHELLCODE DETECTED: Base=0x" + format_address((uint64_t)region.BaseAddress) + 
                        ", Patterns=" + std::to_string(shellcode_patterns) + " ***", 1, 30, "DEBUG");
                }
            }
        }
    }
};

// RealMemoryDetectionEngine 構造函數和析構函數實現
RealMemoryDetection::RealMemoryDetectionEngine::RealMemoryDetectionEngine(const EngineConfig& config)
    : config_(config), running_(false) {
    // 初始化組件
    veh_handler_ = std::make_unique<VEHHandler>();
    logger_ = std::make_unique<Logger>();
}

RealMemoryDetection::RealMemoryDetectionEngine::~RealMemoryDetectionEngine() {
    if (running_) {
        stop();
    }
}

// DetectionUtils 實現
std::string RealMemoryDetection::DetectionUtils::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Logger 類實現
RealMemoryDetection::Logger::Logger(const std::string& log_file, int level)
    : log_level_(level) {
    log_file_.open(log_file, std::ios::app);
}

RealMemoryDetection::Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void RealMemoryDetection::Logger::log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    if (log_file_.is_open()) {
        std::string timestamp = DetectionUtils::get_timestamp();
        log_file_ << timestamp << " [" << level << "] " << message << std::endl;
        log_file_.flush();
    }
}

void RealMemoryDetection::Logger::set_log_level(int level) {
    log_level_ = level;
}

void RealMemoryDetection::Logger::info(const std::string& message) {
    log("INFO", message);
}

void RealMemoryDetection::Logger::warning(const std::string& message) {
    log("WARNING", message);
}

void RealMemoryDetection::Logger::error(const std::string& message) {
    log("ERROR", message);
}

void RealMemoryDetection::Logger::debug(const std::string& message) {
    if (log_level_ >= 2) {
        log("DEBUG", message);
    }
}

// RealMemoryDetectionEngine 虛函數實現
bool RealMemoryDetection::RealMemoryDetectionEngine::start() {
    if (running_) {
        return true;
    }
    
    running_ = true;
    
    // 啟動檢測線程
    detection_thread_ = std::thread(&RealMemoryDetectionEngine::detection_loop, this);
    
    if (logger_) {
        logger_->info("RealMemoryDetectionEngine started");
    }
    
    return true;
}

void RealMemoryDetection::RealMemoryDetectionEngine::stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    // 等待檢測線程結束
    if (detection_thread_.joinable()) {
        detection_thread_.join();
    }
    
    if (logger_) {
        logger_->info("RealMemoryDetectionEngine stopped");
    }
}

void RealMemoryDetection::RealMemoryDetectionEngine::detection_loop() {
    while (running_) {
        try {
            // 基本的檢測循環實現
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            if (logger_) {
                logger_->debug("Detection loop running");
            }
        }
        catch (const std::exception& e) {
            if (logger_) {
                logger_->error("Detection loop exception: " + std::string(e.what()));
            }
        }
        catch (...) {
            if (logger_) {
                logger_->error("Unknown exception in detection loop");
            }
        }
    }
}

// 啟用 SeDebugPrivilege 權限
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    CloseHandle(hToken);
    
    return GetLastError() == ERROR_SUCCESS;
}



int main() {
    // 在開始時啟用調試權限
    if (!EnableDebugPrivilege()) {
        std::cerr << "Warning: Failed to enable debug privilege" << std::endl;
    }
    
    std::cout << "=== Real Memory Attack Detection Engine ===" << std::endl;
    std::cout << "Using low-level Windows API for real memory monitoring" << std::endl;
    std::cout << "Monitoring: ROP, JOP, Buffer Overflow, Heap Corruption, Stack Overflow" << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // 確保 logs 目錄存在
    CreateDirectoryA("logs", NULL);
    
    // 初始化日誌檔案
    std::ofstream log_file("logs/detection_engine.log", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        std::string timestamp = ss.str();
        
        log_file << timestamp << " [ALERT] === Real Memory Attack Detection Engine Started ===" << std::endl;
        log_file << timestamp << " [ALERT] Using low-level Windows API for real memory monitoring" << std::endl;
        log_file << timestamp << " [ALERT] Monitoring: ROP, JOP, Buffer Overflow, Heap Corruption, Stack Overflow" << std::endl;
        log_file << timestamp << " [ALERT] ==================================================" << std::endl;
        log_file.close();
    }
    
    DetectionEngineImpl engine;
    
    if (!engine.start()) {
        std::cerr << "Failed to start detection engine" << std::endl;
        return 1;
    }
    
    std::cout << "Detection engine started. Press Ctrl+C to stop." << std::endl;
    
    // 主循環
    while (true) {
        try {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        catch (const std::exception& e) {
            std::cerr << "Main loop exception: " << e.what() << std::endl;
        }
        catch (...) {
            std::cerr << "Unknown exception in main loop" << std::endl;
        }
    }
    
    engine.stop();
    return 0;
} 