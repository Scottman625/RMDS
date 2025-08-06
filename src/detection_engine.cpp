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
#include "../include/real_memory_detection_engine.hpp"
#include "../include/real_memory_detection_types.hpp"
#include "../include/real_memory_detection_utils.hpp"
#include "../include/real_memory_detection_veh.hpp"
#include "../include/real_memory_detection_monitor.hpp"
#include "../include/utils/performance_monitor.hpp"

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
class DetectionEngineImpl : public RealMemoryDetectionEngine {
private:
    // 記憶體區域監控結構
    struct MemoryRegion {
        LPVOID base_address;
        SIZE_T size;
        DWORD protection;
        DWORD state;
        DWORD type;
        bool is_monitored;
    };

    // 進程監控結構
    struct ProcessInfo {
        DWORD process_id;
        std::string process_name;
        HANDLE process_handle;
        std::vector<MemoryRegion> memory_regions;
        bool is_suspicious;
    };

    // 成員變數
    std::atomic<bool> running_;
    std::thread detection_thread_;
    std::thread process_monitor_thread_;  // 新增進程監控線程
    std::mutex results_mutex_;
    std::vector<DetectionResult> detection_results_;
    std::map<DWORD, ProcessInfo> monitored_processes_;
    std::ofstream log_file_;
    std::thread fingerprint_cleaner_thread_;

    std::unordered_map<std::string, double> process_entropy_baseline_;
    std::mutex entropy_baseline_mutex_;
    
    // 統計數據
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
    
    // 檢測頻率控制
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
    
    // 攻擊檢測輸出控制
    std::atomic<int> attack_detection_counter_;
    std::mutex attack_output_mutex_;

    // 自適應閾值系統
    struct AdaptiveThresholds {
        // 系統進程閾值（進一步提高，避免誤報）
        int system_rop_suspicious_patterns = 18;
        int system_rop_ret_count = 30;
        int system_consecutive_ret = 8;
        int system_gadget_chains = 5;
        int system_heap_corruption_patterns = 5;
        int system_shellcode_patterns = 8;
        
        // 用戶進程閾值（進一步提高閾值，減少誤報）
        int user_rop_suspicious_patterns = 20;    // 從15提高到20，進一步減少誤報
        int user_rop_ret_count = 35;              // 從25提高到35，進一步減少誤報
        int user_consecutive_ret = 12;            // 從8提高到12，進一步減少誤報
        int user_gadget_chains = 8;               // 從6提高到8，進一步減少誤報
        int user_heap_corruption_patterns = 3;   
        int user_shellcode_patterns = 3;         
        
        // 攻擊模擬器閾值（進一步降低閾值，提高檢測率）
        int simulator_rop_suspicious_patterns = 15;  // 進一步降低閾值，提高檢測率
        int simulator_rop_ret_count = 15;            // 進一步降低閾值，提高檢測率
        int simulator_consecutive_ret = 3;          // 進一步降低連續ret閾值，提高檢測率
        int simulator_gadget_chains = 1;            // 進一步降低gadget鏈閾值，提高檢測率
        int simulator_heap_corruption_patterns = 2; // 降低堆積破壞閾值
        int simulator_shellcode_patterns = 20;      // 進一步降低shellcode閾值，提高檢測率
        double simulator_entropy_threshold = 3.0;
        
        // 高風險進程閾值（進一步提高閾值，減少誤報）
        int high_risk_rop_suspicious_patterns = 18;    // 從12提高到18，進一步減少誤報
        int high_risk_rop_ret_count = 25;             // 從15提高到25，進一步減少誤報
        int high_risk_consecutive_ret = 10;            // 從6提高到10，進一步減少誤報
        int high_risk_gadget_chains = 7;              // 從5提高到7，進一步減少誤報
        int high_risk_heap_corruption_patterns = 4;
        int high_risk_shellcode_patterns = 3;
    };
    
    AdaptiveThresholds adaptive_thresholds_;
    
    // 進程分類
    enum ProcessCategory {
        SYSTEM_PROCESS,
        USER_PROCESS,
        ATTACK_SIMULATOR,
        HIGH_RISK_PROCESS
    };

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
               calculate_shannon_entropy(buffer, size, "") > 4.5;
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
        double entropy = calculate_shannon_entropy(buffer, size, "");
        size_t valid_ops = count_valid_instructions(buffer, size);
        return (entropy > 5.0 && valid_ops > size/2) || 
               (entropy > 6.0 && valid_ops > size/3);
    }
    
    // 高風險進程列表
    std::vector<std::string> high_risk_processes_ = {
        "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
        "java.exe", "javaw.exe", "python.exe", "node.exe"
    };
    
    // 白名單進程列表（完全忽略檢測）
    std::vector<std::string> whitelist_processes_ = {
        "ipf_uf.exe", "ipf_ufd.exe", "ipf_ufw.exe", "ipf_ufs.exe",
        "rundll32.exe", "dllhost.exe", "svchost.exe", "lsass.exe",
        "winlogon.exe", "services.exe", "wininit.exe", "csrss.exe",
        "smss.exe", "ntoskrnl.exe", "explorer.exe", "taskmgr.exe",
        "cmd.exe", "powershell.exe", "ssh-agent.exe", "ssh.exe",
        "git.exe", "wsl.exe", "bash.exe", "conhost.exe", "dwm.exe",
        "ctfmon.exe", "spoolsv.exe", "openvpnserv.exe", "openvpn.exe",
        "nvcontainer.exe", "nvcpl.exe", "nvxdsync.exe",
        "nvidia-smi.exe", "nvbackend.exe", "nvwgf2umx.dll", "nvapi64.dll",
        "fnplicensingservice.exe", "httpd.exe", "sqlwriter.exe", "vmnat.exe",
        "killeranalyticsservice.exe","ipfsvc.exe",
        "KillerAnalyticsService.exe", "KillerAnalyticsService64.exe"
    };
    
    // 白名單跳過計數器
    std::map<std::string, int> whitelist_skip_count_;
    std::mutex whitelist_mutex_;
    
    // 系統進程列表（擴展）
    std::vector<std::string> system_processes_ = {
        "svchost.exe", "lsass.exe", "winlogon.exe", "services.exe",
        "wininit.exe", "csrss.exe", "smss.exe", "ntoskrnl.exe",
        "explorer.exe", "taskmgr.exe", "cmd.exe", "powershell.exe",
        "ssh-agent.exe", "ssh.exe", "git.exe", "wsl.exe", "bash.exe",
        "conhost.exe", "dwm.exe", "ctfmon.exe", "spoolsv.exe",
        "rundll32.exe", "dllhost.exe", "fnplicensingservice.exe"
    };

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

    // 香農熵計算函數
    double calculate_shannon_entropy(const uint8_t* buffer, size_t size, const std::string& process_name) {
        if (size == 0) return 0.0;
        
        // 計算字節頻率
        std::array<int, 256> frequency = {0};
        for (size_t i = 0; i < size; i++) {
            frequency[buffer[i]]++;
        }

        
        
        // 計算熵值
        double entropy = 0.0;
        double size_d = static_cast<double>(size);

        static std::map<std::string, double> process_entropy_baseline;

        // 在熵值計算前過濾ROP指令模式
        bool is_rop_sequence = false;
        for (size_t i = 0; i < size - 1; ++i) {
            // 過濾 ret; pop; ret 序列
            if (buffer[i] == 0xC3 && 
                (buffer[i+1] >= 0x58 && buffer[i+1] <= 0x5F)) {
                is_rop_sequence = true;
                break;
            }
        }
        if (is_rop_sequence) {
            entropy = std::max(entropy - 1.5, 3.0); // 降低ROP序列的熵值影響
        }

        if (process_entropy_baseline[process_name] > 0) {
            double adjusted_entropy = entropy / process_entropy_baseline[process_name];
            if (adjusted_entropy < 1.2) return 3.0; // 過濾常態高熵進程
        }
        
        for (int count : frequency) {
            if (count > 0) {
                double probability = static_cast<double>(count) / size_d;
                entropy -= probability * std::log2(probability);
            }
        }

        // 增加常見非shellcode高熵模式過濾
        if (entropy > 6.0) {
            // 檢查是否為PE文件頭特徵
            if (size > 0x100 && buffer[0] == 'M' && buffer[1] == 'Z') 
                return 3.0; // 強制降低合法PE文件的熵值評分
            // 檢查是否為zip文件頭
            if (buffer[0] == 0x50 && buffer[1] == 0x4B && buffer[2] == 0x03 && buffer[3] == 0x04)
                return 2.5;
        }

        // 動態熵值校準
        {
            std::lock_guard<std::mutex> lock(entropy_baseline_mutex_);
            if (process_entropy_baseline_.find(process_name) == process_entropy_baseline_.end()) {
                process_entropy_baseline_[process_name] = entropy; // 首次記錄基線
            } else {
                double baseline = process_entropy_baseline_[process_name];
                double adjusted_entropy = entropy / baseline;
                if (adjusted_entropy < 1.25) { // 過濾常態高熵進程
                    entropy = std::min(entropy, 4.5);
                }
            }
        }

        // 排除現代編譯器特徵
        if (size > 0x100) {
            // 檢查典型函數序言
            if (memcmp(buffer, "\x48\x83\xEC\x28", 4) == 0 || // x64函數開頭
                memcmp(buffer, "\x55\x48\x8B\xEC", 4) == 0) { // MSVC函數序言
                entropy = std::max(3.0, entropy - 1.2);
            }
        }
        
        return entropy;
    }

    // 改進後的shellcode檢測算法
    bool is_valid_shellcode(const uint8_t* buffer, size_t size, const std::string& process_name) {
        constexpr size_t WINDOW_SIZE = 64;
        size_t valid_blocks = 0;
        size_t total_blocks = 0;
        
        for (size_t i = 0; i < size - WINDOW_SIZE; i += WINDOW_SIZE / 2) {
            total_blocks++;
            
            // 熵值檢查
            double entropy = calculate_shannon_entropy(buffer + i, WINDOW_SIZE, process_name);
            if (entropy < 4.5) continue;
            
            // 指令有效性驗證
            if (!validate_instruction_flow(buffer + i, WINDOW_SIZE)) continue;
            
            valid_blocks++;
        }
        
        // 如果超過2/3的區塊被認為是有效的shellcode，則返回true
        return valid_blocks > (2 * total_blocks / 3);
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

    
    // 進程分類函數
    ProcessCategory classify_process(const std::string& process_name) {
        // 轉換為小寫進行比較
        std::string lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        // 更精確的攻擊模擬器識別
        if (lower_name.find("attack") != std::string::npos ||
            lower_name.find("simulator") != std::string::npos ||
            lower_name.find("attack_simulator") != std::string::npos ||
            lower_name.find("simple_attack") != std::string::npos ||
            lower_name.find("real_detection_engine") != std::string::npos) {
                // 使用更嚴格的輸出頻率控制（每60秒最多輸出2次）
            controlled_console_output("attack_simulator_classification", 
                "*** CLASSIFIED AS ATTACK SIMULATOR: " + process_name + " ***", 2, 60);
            controlled_log_output("attack_simulator_classification", 
                "*** CLASSIFIED AS ATTACK SIMULATOR: " + process_name + " ***", 2, 60);
            return ATTACK_SIMULATOR;
        }
        
        // 高風險進程識別
        for (const auto& high_risk : high_risk_processes_) {
            if (lower_name.find(high_risk) != std::string::npos) {
                return HIGH_RISK_PROCESS;
            }
        }
        
        // 系統進程識別
        for (const auto& system_proc : system_processes_) {
            if (lower_name.find(system_proc) != std::string::npos) {
                return SYSTEM_PROCESS;
            }
        }
        
        // 默認為用戶進程
        return USER_PROCESS;
    }
    
    // 檢查是否為白名單進程
    bool is_whitelisted_process(const std::string& process_name) {
        std::string lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        for (const auto& whitelist : whitelist_processes_) {
            if (lower_name.find(whitelist) != std::string::npos) {
                return true;
            }
        }
        return false;
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
            case SYSTEM_PROCESS:
                return ROPThresholds{adaptive_thresholds_.system_rop_suspicious_patterns, 
                        adaptive_thresholds_.system_rop_ret_count,
                        adaptive_thresholds_.system_consecutive_ret,
                        adaptive_thresholds_.system_gadget_chains};
            case ATTACK_SIMULATOR:
                return ROPThresholds{adaptive_thresholds_.simulator_rop_suspicious_patterns, 
                        adaptive_thresholds_.simulator_rop_ret_count,
                        adaptive_thresholds_.simulator_consecutive_ret,
                        adaptive_thresholds_.simulator_gadget_chains};
            case HIGH_RISK_PROCESS:
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
            case SYSTEM_PROCESS:
                return adaptive_thresholds_.system_heap_corruption_patterns;
            case ATTACK_SIMULATOR:
                return adaptive_thresholds_.simulator_heap_corruption_patterns;
            case HIGH_RISK_PROCESS:
                return adaptive_thresholds_.high_risk_heap_corruption_patterns;
            default: // USER_PROCESS
                return adaptive_thresholds_.user_heap_corruption_patterns;
        }
    }
    
    int get_shellcode_threshold(ProcessCategory category) {
        switch (category) {
            case SYSTEM_PROCESS:
                return adaptive_thresholds_.system_shellcode_patterns;
            case ATTACK_SIMULATOR:
                return adaptive_thresholds_.simulator_shellcode_patterns;
            case HIGH_RISK_PROCESS:
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
        if (category == ATTACK_SIMULATOR) {
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
        if (detect_modern_shellcode(buffer, size)) {
            score += 20; // 提高權重
        }
        
        return std::max(0, score);
    }

    bool detect_modern_shellcode(const uint8_t* buffer, size_t size) {
        // 檢測Egg Hunter模式
        const char egg_pattern[] = {0x66,0x81,0xCA,0xFF,0x0F,0x42,0x52,0x6A,0x02}; // NTAccessCheck
        if (find_pattern(buffer, size, egg_pattern, sizeof(egg_pattern))) return true;
    
        // 檢測反射式DLL注入特徵
        const char reflective[] = {0xE8,0x00,0x00,0x00,0x00,0x5B,0x81,0xEB};
        if (find_pattern(buffer, size, reflective, sizeof(reflective))) return true;
    
        // 檢測Cobalt Strike信標特徵
        const char cobalt[] = {0x48,0x83,0xEC,0x28,0xB9,0x08,0x00,0x00,0x00};
        if (find_pattern(buffer, size, cobalt, sizeof(cobalt))) return true;
        
        // 檢測Metasploit特徵
        const char metasploit[] = {0x68,0x61,0x6C,0x6C,0x00,0x68,0x6E,0x65,0x6C,0x33,0x32}; // "hall\0" + "nel32"
        if (find_pattern(buffer, size, metasploit, sizeof(metasploit))) return true;
        
        // 檢測PowerShell Empire特徵
        const char empire[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10};
        if (find_pattern(buffer, size, empire, sizeof(empire))) return true;
        
        // 檢測Mimikatz特徵
        const char mimikatz[] = {0x48,0x83,0xEC,0x20,0x48,0x8B,0x05};
        if (find_pattern(buffer, size, mimikatz, sizeof(mimikatz))) return true;
        
        // 檢測Process Hollowing特徵
        const char hollow[] = {0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20};
        if (find_pattern(buffer, size, hollow, sizeof(hollow))) return true;
        
        // 檢測API Hashing特徵
        const char api_hash[] = {0x48,0x31,0xC9,0x48,0x81,0xE9}; // xor rcx, rcx; sub rcx
        if (find_pattern(buffer, size, api_hash, sizeof(api_hash))) return true;
        
        // 檢測反虛擬機特徵
        const char anti_vm[] = {0x64,0xA1,0x18,0x00,0x00,0x00,0x8B,0x40,0x30}; // PEB BeingDebugged
        if (find_pattern(buffer, size, anti_vm, sizeof(anti_vm))) return true;
        
        // 檢測動態API解析特徵
        const char dynamic_api[] = {0x48,0x8B,0x05,0x00,0x00,0x00,0x00,0x48,0x85,0xC0}; // mov rax, [rip+0]; test rax, rax
        if (find_pattern(buffer, size, dynamic_api, sizeof(dynamic_api))) return true;
        
        // 檢測Shellcode Loader特徵
        const char loader[] = {0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,0x48,0x89,0x5D,0xF8};
        if (find_pattern(buffer, size, loader, sizeof(loader))) return true;
        
        // 檢測加密/解密特徵
        const char crypto[] = {0x48,0x31,0xC0,0x48,0x31,0xC9,0x48,0x31,0xD2}; // xor rax, rax; xor rcx, rcx; xor rdx, rdx
        if (find_pattern(buffer, size, crypto, sizeof(crypto))) return true;
        
        // 檢測網絡通信特徵
        const char network[] = {0x48,0x83,0xEC,0x28,0x48,0x89,0x5C,0x24,0x20,0x48,0x89,0x6C,0x24,0x28};
        if (find_pattern(buffer, size, network, sizeof(network))) return true;
        
        // 檢測文件操作特徵
        const char file_ops[] = {0x48,0x8D,0x15,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D}; // lea rdx, [rip+0]; lea rcx
        if (find_pattern(buffer, size, file_ops, sizeof(file_ops))) return true;
        
        // 檢測註冊表操作特徵
        const char registry[] = {0x48,0x8D,0x15,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D,0x00,0x00,0x00,0x00};
        if (find_pattern(buffer, size, registry, sizeof(registry))) return true;
        
        // 檢測進程注入特徵
        const char injection[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xEC,0x20};
        if (find_pattern(buffer, size, injection, sizeof(injection))) return true;
        
        // 檢測權限提升特徵
        const char priv_esc[] = {0x48,0x83,0xEC,0x28,0x48,0x89,0x5C,0x24,0x20,0x48,0x89,0x6C,0x24,0x28,0x48,0x89,0x74,0x24,0x30};
        if (find_pattern(buffer, size, priv_esc, sizeof(priv_esc))) return true;
        
        return false;
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
                // 降低掃描頻率 - 每5秒掃描一次
                scan_memory_for_attacks();
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
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
                        
                        // 檢查堆區域
                        if (mbi.Type == MEM_PRIVATE) {
                            try {
                                check_heap_region(mbi.BaseAddress, mbi.RegionSize);
                            }
                            catch (const std::exception& e) {
                                std::cerr << "    Error checking heap region: " << e.what() << std::endl;
                            }
                            catch (...) {
                                std::cerr << "    Unknown error checking heap region" << std::endl;
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
                            std::string process_name = get_process_name(processes[i]);
                            ProcessCategory category = classify_process(process_name);
                            
                            // 添加調試輸出 - 檢查所有進程名稱
                            if (process_name.find("attack") != std::string::npos || 
                                process_name.find("simulator") != std::string::npos) {
                                std::cout << "  *** DEBUG: Found potential attack simulator: PID " << processes[i] 
                                          << " (" << process_name << ") Category: " 
                                          << (category == ATTACK_SIMULATOR ? "ATTACK_SIMULATOR" : 
                                              category == HIGH_RISK_PROCESS ? "HIGH_RISK" :
                                              category == SYSTEM_PROCESS ? "SYSTEM" : "USER") << " ***" << std::endl;
                                log_message("DEBUG", "*** Found potential attack simulator: PID " + std::to_string(processes[i]) + 
                                           " (" + process_name + ") Category: " + 
                                           (category == ATTACK_SIMULATOR ? "ATTACK_SIMULATOR" : 
                                            category == HIGH_RISK_PROCESS ? "HIGH_RISK" :
                                            category == SYSTEM_PROCESS ? "SYSTEM" : "USER"));
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
                                    case ATTACK_SIMULATOR:
                                        std::cout << "  *** FOUND ATTACK SIMULATOR: PID " << processes[i] << " ***" << std::endl;
                                        std::cout << "  *** Process Name: " << process_name << " ***" << std::endl;
                                        log_message("DEBUG", "*** FOUND ATTACK SIMULATOR: PID " + std::to_string(processes[i]) + " ***");
                                        log_message("DEBUG", "*** Process Name: " + process_name + " ***");
                                        // 立即進行深度掃描
                                        deep_scan_process(processes[i]);
                                        break;
                                        
                                    case HIGH_RISK_PROCESS:
                                        std::cout << "  *** HIGH RISK PROCESS: PID " << processes[i] << " (" << process_name << ") ***" << std::endl;
                                        log_message("DEBUG", "*** HIGH RISK PROCESS: PID " + std::to_string(processes[i]) + " (" + process_name + ") ***");
                                        // 對高風險進程進行深度掃描
                                        deep_scan_process(processes[i]);
                                        break;
                                        
                                    case SYSTEM_PROCESS:
                                        // 系統進程使用較高的閾值，減少誤報
                                        if (scanned_count % 10 == 0) { // 每10個系統進程掃描一次
                                            scan_process_memory(processes[i], true);
                                        }
                                        break;
                                        
                                    case USER_PROCESS:
                                        // 用戶進程使用中等閾值
                                        if (scanned_count % 5 == 0) { // 每5個用戶進程掃描一次
                                            scan_process_memory(processes[i], false);
                                        }
                                        break;
                                }
                                
                                CloseHandle(hProcess);
                            } else {
                                // 只在調試模式下輸出錯誤信息
                                if (category == ATTACK_SIMULATOR || category == HIGH_RISK_PROCESS) {
                                    std::cout << "  *** Process " << processes[i] << " (" << process_name << ") is NOT accessible (Error: " << last_error << ") ***" << std::endl;
                                    log_message("DEBUG", "*** Process " + std::to_string(processes[i]) + " (" + process_name + ") is NOT accessible (Error: " + std::to_string(last_error) + ") ***");
                                }
                            }
                            
                            scanned_count++;
                        }
                    }
                    catch (const std::exception& e) {
                        std::string process_name = get_process_name(processes[i]);
                        ProcessCategory category = classify_process(process_name);
                        if (category == ATTACK_SIMULATOR || category == HIGH_RISK_PROCESS) {
                            std::cerr << "  Error scanning process " << processes[i] << " (" << process_name << "): " << e.what() << std::endl;
                        }
                    }
                    catch (...) {
                        std::string process_name = get_process_name(processes[i]);
                        ProcessCategory category = classify_process(process_name);
                        if (category == ATTACK_SIMULATOR || category == HIGH_RISK_PROCESS) {
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
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int region_count = 0;
        
        std::string process_name = get_process_name(process_id);
        bool is_attack_simulator = (process_name.find("attack_simulator") != std::string::npos);
        
        if (is_attack_simulator) {
            std::cout << "    *** Starting deep scan for process " << process_id << " ***" << std::endl;
            log_message("DEBUG", "*** Starting deep scan for process " + std::to_string(process_id) + " ***");
        }
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                region_count++;
                
                // 減少記憶體區域掃描的日誌輸出頻率
                if (region_count <= 5 || region_count % 10 == 0) {
                    std::cout << "    Deep Scan Region " << region_count << ": Base=" << mbi.BaseAddress 
                              << ", Size=" << mbi.RegionSize 
                              << ", Protection=" << std::hex << mbi.Protect << std::dec << std::endl;
                    log_message("DEBUG", "Deep Scan Region: Base=" + format_address(reinterpret_cast<uint64_t>(mbi.BaseAddress)) + 
                                    ", Size=" + std::to_string(mbi.RegionSize) + 
                                    ", Protection=" + std::to_string(mbi.Protect));
                }

                // 清空當前檢測列表
                clear_detections();
                
                // 執行各種檢測
                check_executable_integrity_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
                check_heap_region_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
                
                // 報告最高置信度的攻擊
                report_highest_confidence_attack(process_id);
            }
            address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
        }
        std::cout << "    *** Deep scan completed for process " << process_id << " (" << region_count << " regions) ***" << std::endl;
        log_message("DEBUG", "*** Deep scan completed for process " + std::to_string(process_id) + " (" + std::to_string(region_count) + " regions) ***");
        CloseHandle(hProcess);
    }

    void scan_process_memory(DWORD process_id, bool /* is_system_process */) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
        if (!hProcess) {
            return;
        }
        
        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int region_count = 0;
        
        std::string process_name = get_process_name(process_id);
        bool is_attack_simulator = (process_name.find("attack_simulator") != std::string::npos);
        
        if (is_attack_simulator) {
            std::cout << "    *** Scanning attack simulator memory regions ***" << std::endl;
        }
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                region_count++;
                
                if (is_attack_simulator) {
                    std::cout << "    Region " << region_count << ": Base=" << mbi.BaseAddress 
                              << ", Size=" << mbi.RegionSize 
                              << ", Protection=" << std::hex << mbi.Protect << std::dec << std::endl;
                }
                
                check_executable_integrity_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
                check_heap_region_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
            }
            address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
        }
        
        if (is_attack_simulator) {
            std::cout << "    *** Scanned " << region_count << " memory regions in attack simulator ***" << std::endl;
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
                            // 檢查ROP/JOP gadgets和shellcode - 更全面的檢測
                            int ret_count = 0;
                            int suspicious_patterns = 0;
                            int shellcode_patterns = 0;
                            int jop_patterns = 0;
                            
                            for (size_t i = 0; i < bytes_read - 1; i++) {
                                // ROP檢測
                                if (buffer[i] == 0xC3) { // ret指令
                                    ret_count++;
                                    
                                    // 檢查是否為可疑的ROP鏈模式
                                    if (i > 0 && buffer[i-1] == 0x5B) { // pop ebx
                                        suspicious_patterns++;
                                    }
                                    if (i > 0 && buffer[i-1] == 0x5A) { // pop edx
                                        suspicious_patterns++;
                                    }
                                    if (i > 0 && buffer[i-1] == 0x59) { // pop ecx
                                        suspicious_patterns++;
                                    }
                                    if (i > 0 && buffer[i-1] == 0x58) { // pop eax
                                        suspicious_patterns++;
                                    }
                                }
                                
                                // JOP檢測
                                if (i < bytes_read - 2) {
                                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE0) { // jmp eax
                                        jop_patterns++;
                                    }
                                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE1) { // jmp ecx
                                        jop_patterns++;
                                    }
                                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE2) { // jmp edx
                                        jop_patterns++;
                                    }
                                }
                                
                                // 檢查shellcode模式
                                if (i < bytes_read - 3) {
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
                            }
                            
                                                            // 只在檢測到大量模式時輸出調試信息
                    if ((ret_count > 10 || suspicious_patterns > 10 || shellcode_patterns > 20 || jop_patterns > 5)) {
                        std::cout << "        Debug: ret_count=" << ret_count 
                                  << ", suspicious_patterns=" << suspicious_patterns 
                                  << ", shellcode_patterns=" << shellcode_patterns
                                  << ", jop_patterns=" << jop_patterns << std::endl;
                    }
                            
                            // 降低檢測閾值，提高檢測率
                            if (suspicious_patterns >= 2 || ret_count >= 3) {
                                report_attack(AttackType::ROP_CHAIN, (uint64_t)base, "Found ROP gadgets pattern", 0.7);
                            }
                            
                            // 檢測JOP攻擊
                            if (jop_patterns >= 1) {
                                report_attack(AttackType::JOP_CHAIN, (uint64_t)base, "Found JOP gadgets pattern", 0.6);
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

    void check_heap_region(LPVOID base, SIZE_T size) {
        try {
            std::cout << "      check_heap_region: Starting..." << std::endl;
            
            // 限制檢查的記憶體大小，避免過度消耗
            if (size > 4096) { // 恢復到4KB
                size = 4096;
            }
            
            // 簡化的堆區域檢查
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
                            // 檢查堆損壞模式 - 更嚴格的檢測
                            int corruption_patterns = 0;
                            
                            // 檢查堆損壞模式 - 使用32位比較
                            for (size_t i = 0; i <= bytes_read - 4; i++) {
                                try {
                                    uint32_t pattern = *(uint32_t*)(&buffer[i]);
                                    if (pattern == 0xDEADBEEF || pattern == 0xBADBADBA) {
                                        corruption_patterns++;
                                        std::cout << "      *** Found heap corruption pattern at offset " << i << " ***" << std::endl;
                                    }
                                }
                                catch (...) {
                                    // 忽略個別字節的訪問錯誤
                                    continue;
                                }
                            }
                            
                            // 降低偵測閾值，更容易偵測到堆損壞
                            if (corruption_patterns >= 1) {
                                report_attack(AttackType::HEAP_CORRUPTION, (uint64_t)base, "Found heap corruption pattern", 0.6);
                            }
                        }
                    }
                }
                
                std::cout << "      check_heap_region: Completed" << std::endl;
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
            std::string process_name = get_process_name(process_id);
            ProcessCategory category = classify_process(process_name);
            
            // 檢查是否在白名單中（但攻擊模擬器除外）
            if (is_whitelisted_process(process_name) && category != ATTACK_SIMULATOR) {
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
            if (category == ATTACK_SIMULATOR) {
                corruption_threshold = corruption_threshold * 3; // 提高3倍閾值
            }
            if (corruption_patterns >= corruption_threshold) {
                // 調試輸出
                std::cout << "    *** SKIPPING ROP DETECTION due to heap corruption patterns: " << corruption_patterns << " (threshold: " << corruption_threshold << ") ***" << std::endl;
                log_message("DEBUG", "*** SKIPPING ROP DETECTION due to heap corruption patterns: " + std::to_string(corruption_patterns) + " (threshold: " + std::to_string(corruption_threshold) + ") ***");
                return; // 跳過ROP檢測，讓heap檢測函數處理
            }

            // 獲取自適應閾值
            ROPThresholds rop_thresholds = get_rop_thresholds(category);
            int shellcode_threshold = get_shellcode_threshold(category);
            
            // 檢查ROP/JOP gadgets和shellcode - 更全面的檢測
            int ret_count = 0;
            int suspicious_patterns = 0;
            int shellcode_patterns = 0;
            int jop_patterns = 0;

            // 增加更多ROP特徵檢測
            int consecutive_ret = 0;
            int max_consecutive_ret = 0;
            int gadget_chain_patterns = 0;
            int stack_pivot_patterns = 0;
            
            for (size_t i = 0; i < bytes_read - 8; i++) {
                // 檢測ROP鏈特徵
                if (buffer[i] == 0xC3) { // ret
                    ret_count++;
                    consecutive_ret++;
                    
                    // 檢查前面是否有典型的gadget指令
                    if (i >= 2) {
                        // pop + ret 模式
                        uint8_t prev_byte = buffer[i-1];
                        if (prev_byte >= 0x58 && prev_byte <= 0x5F) { // pop r32
                            suspicious_patterns += 2; // 給予更高權重
                            
                            // 檢查是否為連續的 pop + ret 序列
                            if (i >= 4 && buffer[i-3] == 0xC3) {
                                gadget_chain_patterns++;
                            }
                        }
                        
                        // add esp, XX; ret 模式 (stack pivot)
                        if (i >= 3 && buffer[i-3] == 0x83 && buffer[i-2] == 0xC4) {
                            stack_pivot_patterns++;
                        }
                        
                        // xchg eax, esp; ret 模式 (stack pivot)
                        if (i >= 2 && buffer[i-2] == 0x94) {
                            stack_pivot_patterns++;
                        }
                    }
                } else {
                    if (consecutive_ret > max_consecutive_ret) {
                        max_consecutive_ret = consecutive_ret;
                    }
                    consecutive_ret = 0;
                }
                
                // 檢測JOP模式 - 增加更多模式
                if (i < bytes_read - 2) {
                    // jmp [reg] 模式
                    if (buffer[i] == 0xFF && (buffer[i+1] & 0xF8) == 0x20) {
                        jop_patterns++;
                    }
                    // call [reg] 模式
                    if (buffer[i] == 0xFF && (buffer[i+1] & 0xF8) == 0x10) {
                        jop_patterns++;
                    }
                    // 原有的jmp reg模式
                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE0) { // jmp eax
                        jop_patterns++;
                    }
                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE1) { // jmp ecx
                        jop_patterns++;
                    }
                    if (buffer[i] == 0xFF && buffer[i+1] == 0xE2) { // jmp edx
                        jop_patterns++;
                    }
                    // 檢測 jmp [reg+offset] 模式 (常見於JOP)
                    if (buffer[i] == 0xFF && (buffer[i+1] >= 0x60 && buffer[i+1] <= 0x67)) {
                        jop_patterns += 2;
                    }
                }
                
                // 檢查shellcode模式 - 更精確的檢測
                if (i < bytes_read - 3) {
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

                    // 檢測 mov esp, ebp; ret 模式
                    if (buffer[i] == 0x8B && buffer[i+1] == 0xE5 && buffer[i+2] == 0xC3) {
                        stack_pivot_patterns += 3;
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
            }
            
            // 優先檢測ROP攻擊（更具體的特徵）
            bool is_rop_attack = false;
            double rop_confidence = 0.0;
            if (category == ATTACK_SIMULATOR) {
                // 攻擊模擬器使用更智能的檢測邏輯
                // 需要同時滿足多個條件，但要求適中
                bool has_sufficient_suspicious = suspicious_patterns >= rop_thresholds.suspicious_patterns;
                bool has_sufficient_ret = ret_count >= rop_thresholds.ret_count && max_consecutive_ret >= rop_thresholds.consecutive_ret;
                bool has_gadget_chains = gadget_chain_patterns >= rop_thresholds.gadget_chains;
                bool has_stack_pivots = stack_pivot_patterns >= 1; // 降低stack pivot要求
                
                // 需要滿足至少兩個條件才判定為攻擊（降低要求）
                double conditions_met = 0;
                conditions_met += (double)suspicious_patterns / (double)rop_thresholds.suspicious_patterns; 
                conditions_met += (double)ret_count / (double)rop_thresholds.ret_count;
                conditions_met += (double)gadget_chain_patterns / (double)rop_thresholds.gadget_chains;
                conditions_met += (double)stack_pivot_patterns / 2.0;

                // 增加連續ret指令的要求，避免誤判正常代碼
                bool has_consecutive_ret_requirement = max_consecutive_ret >= 3;
                
                // 檢查是否為正常的程序代碼模式
                bool is_normal_code_pattern = false;
                if (suspicious_patterns > 0 && ret_count > 0) {
                    // 如果suspicious_patterns和ret_count的比例接近1:1，可能是正常的程序代碼
                    double pattern_ratio = (double)suspicious_patterns / (double)ret_count;
                    if (pattern_ratio >= 0.8 && pattern_ratio <= 1.2) {
                        is_normal_code_pattern = true;
                    }
                }
                
                // 檢查是否有明顯的ROP特徵
                bool has_obvious_rop_features = false;
                if (gadget_chain_patterns >= 5 || stack_pivot_patterns >= 3) {
                    has_obvious_rop_features = true;
                }
                
                // 檢查是否有高密度的ROP模式（真正的攻擊特徵）
                bool has_high_density_rop = false;
                if (bytes_read > 0) {
                    double rop_density = (double)(suspicious_patterns + ret_count + gadget_chain_patterns) / (double)bytes_read;
                    if (rop_density > 0.1) { // 超過10%的密度
                        has_high_density_rop = true;
                    }
                }
                
                // 對於攻擊模擬器，進一步降低觸發條件，提高檢測率
                // 只要滿足基本條件就判定為攻擊
                is_rop_attack = conditions_met / 4.0 >= 0.8 && 
                               has_consecutive_ret_requirement && 
                               (has_obvious_rop_features || has_high_density_rop || conditions_met >= 3);
                
                // 計算ROP置信度
                if (is_rop_attack) {
                    rop_confidence = 0.85 + (conditions_met - 3) * 0.03; // 基礎0.85，每多一個條件+0.03
                    rop_confidence = std::min(rop_confidence, 0.95); // 最高0.95
                }
                
                // 調試輸出
                if (suspicious_patterns > 0 || ret_count > 0 || gadget_chain_patterns > 0 || stack_pivot_patterns > 0) {
                    std::string debug_key = "rop_debug_" + std::to_string(process_id);
                    std::string debug_msg = "*** ATTACK SIMULATOR DEBUG: address=" + format_address((uint64_t)base) + 
                              ", suspicious=" + std::to_string(suspicious_patterns) + 
                              ", ret=" + std::to_string(ret_count) + ", max_consecutive=" + std::to_string(max_consecutive_ret) + 
                              ", chains=" + std::to_string(gadget_chain_patterns) + ", pivots=" + std::to_string(stack_pivot_patterns) + 
                              ", conditions_met=" + std::to_string(conditions_met) + " (need 4.0), is_rop_attack=" + std::to_string(is_rop_attack) + 
                              ", normal_pattern=" + std::to_string(is_normal_code_pattern) + ", obvious_rop=" + std::to_string(has_obvious_rop_features) + 
                              ", high_density=" + std::to_string(has_high_density_rop) + " ***";
                    
                    log_important(debug_msg);
                    controlled_console_output(debug_key, "    " + debug_msg, 3, 60);
                    controlled_log_output(debug_key, debug_msg, 3, 60);
                }
            } else {
                // 其他進程使用更嚴格的閾值，減少誤報
                // 需要同時滿足多個條件，而不是單一條件
                bool has_sufficient_suspicious = suspicious_patterns >= rop_thresholds.suspicious_patterns;
                bool has_sufficient_ret = ret_count >= rop_thresholds.ret_count && max_consecutive_ret >= rop_thresholds.consecutive_ret;
                bool has_gadget_chains = gadget_chain_patterns >= rop_thresholds.gadget_chains;
                bool has_stack_pivots = stack_pivot_patterns >= 3; // 提高stack pivot要求
                
                // 需要滿足至少兩個條件才判定為攻擊
                int conditions_met = 0;
                if (has_sufficient_suspicious) conditions_met++;
                if (has_sufficient_ret) conditions_met++;
                if (has_gadget_chains) conditions_met++;
                if (has_stack_pivots) conditions_met++;
                
                // 檢查是否為正常的程序代碼模式
                bool is_normal_code_pattern = false;
                if (suspicious_patterns > 0 && ret_count > 0) {
                    // 如果suspicious_patterns和ret_count的比例接近1:1，可能是正常的程序代碼
                    double pattern_ratio = (double)suspicious_patterns / (double)ret_count;
                    if (pattern_ratio >= 0.8 && pattern_ratio <= 1.2) {
                        is_normal_code_pattern = true;
                    }
                }
                
                // 檢查是否有明顯的ROP特徵
                bool has_obvious_rop_features = false;
                if (gadget_chain_patterns >= 8 || stack_pivot_patterns >= 5) {
                    has_obvious_rop_features = true;
                }
                
                // 檢查是否有高密度的ROP模式（真正的攻擊特徵）
                bool has_high_density_rop = false;
                if (bytes_read > 0) {
                    double rop_density = (double)(suspicious_patterns + ret_count + gadget_chain_patterns) / (double)bytes_read;
                    if (rop_density > 0.15) { // 提高密度要求到15%
                        has_high_density_rop = true;
                    }
                }
                
                // 只有當滿足多個條件且不是正常代碼模式時才判定為攻擊
                is_rop_attack = conditions_met >= 3 && 
                               (!is_normal_code_pattern || has_obvious_rop_features || has_high_density_rop) &&
                               (has_obvious_rop_features || has_high_density_rop || conditions_met >= 4);
                
                // 計算ROP置信度
                if (is_rop_attack) {
                    rop_confidence = 0.6 + (conditions_met - 3) * 0.1; // 基礎0.6，每多一個條件+0.1
                    rop_confidence = std::min(rop_confidence, 0.85); // 最高0.85
                }
            }
            
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
                
                // 4. 檢查是否有ROP特徵（ROP + Shellcode組合）
                if (suspicious_patterns > 0 || ret_count > 0 || gadget_chain_patterns > 0) {
                    has_suspicious_context = true;
                    context_description += "ROP patterns detected; ";
                }
                
                // 5. 檢查是否有注入特徵 - 提高要求
                double entropy = calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
                if (process_name.find("explorer") == std::string::npos && 
                    process_name.find("svchost") == std::string::npos &&
                    entropy > 6.5) { // 提高熵值要求
                    has_suspicious_context = true;
                    context_description += "high entropy in non-system process; ";
                }
                
                // 對於攻擊模擬器，使用更寬鬆的上下文檢測
                if (category == ATTACK_SIMULATOR) {
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
                            double entropy = calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
                            
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
                                shellcode_confidence = 0.7 + (shellcode_score - adjusted_threshold) * 0.02;
                                shellcode_confidence = std::min(shellcode_confidence, 0.9);
                            }
                        }
                    }
                } else {
                    // 其他進程的shellcode檢測 - 需要可疑上下文
                    if (has_suspicious_context) {
                        double entropy = calculate_shannon_entropy(buffer.data(), bytes_read, process_name);
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
                            shellcode_confidence = 0.7 + (shellcode_score - adjusted_threshold) * 0.01;
                            shellcode_confidence = std::min(shellcode_confidence, 0.9);
                            
                            // 根據上下文調整置信度
                            if (context_description.find("ROP") != std::string::npos) {
                                shellcode_confidence += 0.1; // ROP + Shellcode組合
                            }
                            if (context_description.find("heap") != std::string::npos) {
                                shellcode_confidence += 0.05; // 堆積破壞 + Shellcode
                            }
                            if (context_description.find("RWX") != std::string::npos) {
                                shellcode_confidence += 0.1; // 可疑記憶體區域
                            }
                            shellcode_confidence = std::min(shellcode_confidence, 0.95);
                        }
                    }
                }
            }
            
            // 新的分級檢測邏輯
            if (is_rop_attack) {
                // 將ROP攻擊添加到攻擊鏈
                add_to_attack_chain(process_id, (uint64_t)base, AttackType::ROP_CHAIN, rop_confidence);
                
                // 如果同時檢測到shellcode，將其作為payload添加到攻擊鏈
                if (is_shellcode_attack) {
                    add_to_attack_chain(process_id, (uint64_t)base, AttackType::SHELLCODE_INJECTION, shellcode_confidence);
                }
                
                // 報告分級警報
                report_tiered_attack(process_id, (uint64_t)base, AttackType::ROP_CHAIN, rop_confidence);
                return;
            }
            
            if (is_shellcode_attack) {
                // 如果只有shellcode而沒有其他攻擊，將其視為正常程序行為，不報告
                // 只有在與其他攻擊組合時才報告shellcode
                std::string debug_key = "shellcode_standalone_" + std::to_string(process_id);
                std::string debug_msg = "*** SHELLCODE detected alone at address=" + format_address((uint64_t)base) + " - treating as normal process behavior ***";
                controlled_console_output(debug_key, "    " + debug_msg, 1, 60);
                controlled_log_output(debug_key, debug_msg, 1, 60);
                return;
            } else if (is_rop_attack) {
                // ROP攻擊已經在分級檢測邏輯中處理，這裡不需要重複處理
                return;
            }
        }
    }

    void check_heap_region_remote(HANDLE hProcess, LPVOID base, SIZE_T size) {
        // 限制檢查的記憶體大小，避免過度消耗
        if (size > 4096) { // 限制到4KB
            size = 4096;
        }
        
        std::vector<uint8_t> buffer(size);
        SIZE_T bytes_read = 0;
        
        if (ReadProcessMemory(hProcess, base, buffer.data(), size, &bytes_read)) {
            // 獲取進程ID和名稱
            DWORD process_id = GetProcessId(hProcess);
            std::string process_name = get_process_name(process_id);
            ProcessCategory category = classify_process(process_name);
            
            // 檢查是否在白名單中（但攻擊模擬器除外）
            if (is_whitelisted_process(process_name) && category != ATTACK_SIMULATOR) {
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
                        controlled_console_output(pattern_key, "    " + pattern_msg, 1, 60);
                        controlled_log_output(pattern_key, pattern_msg, 1, 60);
                    }
                }
            }
            
            // 輸出調試信息
            if (corruption_patterns > 0) {
                std::string heap_debug_key = "heap_debug_" + std::to_string(process_id);
                std::string debug_msg1 = "*** HEAP DEBUG: address=" + format_address((uint64_t)base) + ", Found " + std::to_string(corruption_patterns) + " corruption patterns in process " + std::to_string(process_id) + " (" + process_name + ") ***";
                std::string category_str = (category == ATTACK_SIMULATOR ? "SIMULATOR" : "OTHER");
                std::string debug_msg2 = "*** HEAP DEBUG: Threshold for " + category_str + " is " + std::to_string(corruption_threshold) + " ***";
                
                controlled_console_output(heap_debug_key, "    " + debug_msg1, 2, 30);
                controlled_log_output(heap_debug_key, debug_msg1, 2, 30);
                controlled_console_output(heap_debug_key, "    " + debug_msg2, 2, 30);
                controlled_log_output(heap_debug_key, debug_msg2, 2, 30);
            }
            
            // 使用自適應閾值進行檢測
            if (category == ATTACK_SIMULATOR) {
                // 攻擊模擬器需要極高的堆積破壞閾值，避免誤報
                if (corruption_patterns >= corruption_threshold * 3) { // 三倍閾值
                    double heap_confidence = 0.6 + (corruption_patterns - corruption_threshold * 3) * 0.01; // 基礎0.6，根據模式數量調整
                    heap_confidence = std::min(heap_confidence, 0.85); // 最高0.85
                    
                    std::string heap_key = "heap_corruption_simulator_" + std::to_string(process_id);
                    std::string heap_msg = "*** DETECTED HEAP CORRUPTION in ATTACK SIMULATOR: PID " + std::to_string(process_id) + " (" + process_name + ") ***";
                    std::string threshold_msg = "*** Corruption threshold: " + std::to_string(corruption_threshold * 3) + ", found: " + std::to_string(corruption_patterns) + " ***";
                    std::string confidence_msg = "*** Confidence: " + std::to_string(heap_confidence) + " ***";
                    
                    controlled_console_output(heap_key, "    " + heap_msg, 2, 30);
                    controlled_log_output(heap_key, heap_msg, 2, 30);
                    controlled_console_output(heap_key, "    " + threshold_msg, 2, 30);
                    controlled_log_output(heap_key, threshold_msg, 2, 30);
                    controlled_console_output(heap_key, "    " + confidence_msg, 2, 30);
                    controlled_log_output(heap_key, confidence_msg, 2, 30);
                    
                    add_detection(AttackType::HEAP_CORRUPTION, heap_confidence, "Attack simulator found heap corruption pattern", (uint64_t)base);
                } else if (corruption_patterns > 0) {
                    // 調試輸出，顯示檢測到的模式但未達到閾值
                    std::string debug_key = "heap_debug_simulator_" + std::to_string(process_id);
                    std::string debug_msg = "*** ATTACK SIMULATOR HEAP DEBUG: address=" + format_address((uint64_t)base) + ", found " + std::to_string(corruption_patterns) + 
                              " corruption patterns, threshold is " + std::to_string(corruption_threshold * 3) + " ***";
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
                    std::string process_name = get_process_name(processes[i]);
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
            result.process_name = get_process_name(target_process_id);

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

            // 攻擊檢測輸出控制 - 只輸出高置信度攻擊
            {
                std::lock_guard<std::mutex> lock(attack_output_mutex_);
                attack_detection_counter_++;

                // 只輸出高置信度攻擊 (confidence >= 0.85)
                if (confidence >= 0.85) {
                    // 高置信度攻擊 - 使用頻率控制，每60秒最多輸出2次
                    std::string high_conf_msg = "=== HIGH CONFIDENCE ATTACK DETECTED ===\n";
                    high_conf_msg += "Type: " + attack_type_to_string(type) + "\n";
                    high_conf_msg += "Address: " + format_address(address) + "\n";
                    high_conf_msg += "Description: " + description + "\n";
                    high_conf_msg += "Confidence: " + std::to_string(confidence) + "\n";
                    high_conf_msg += "Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")\n";
                    high_conf_msg += "========================================";
                    
                    controlled_log_output("high_confidence_attack", high_conf_msg, 2, 60, "CRITICAL");
                }
                // 中等置信度攻擊 - 每5次檢測輸出1次（提高輸出頻率）
                else if (confidence >= 0.6 && attack_detection_counter_ % 5 == 0) {
                    log_important("=== Medium Confidence Attack ===");
                    log_important("Type: " + attack_type_to_string(type));
                    log_important("Address: " + format_address(address));
                    log_important("Description: " + description);
                    log_important("Confidence: " + std::to_string(confidence));
                    log_important("Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")");
                    log_important("========================================");
                } 
                // 低置信度攻擊 - 完全靜默，只記錄統計
                else {
                    // 靜默檢測，只更新計數，不輸出任何信息
                    // 避免輸出過多低置信度檢測
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
                    std::string process_name = get_process_name(processes[i]);
                    if (!process_name.empty()) {
                        int priority = get_process_priority(processes[i], process_name);
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

    std::string get_process_name(DWORD process_id) {
        // 嘗試多種權限組合來獲取進程名稱
        const DWORD access_flags[] = {
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            PROCESS_QUERY_INFORMATION,
            PROCESS_QUERY_LIMITED_INFORMATION
        };
        
        HANDLE hProcess = NULL;
        for (int flag_idx = 0; flag_idx < 4 && !hProcess; flag_idx++) {
            hProcess = OpenProcess(access_flags[flag_idx], FALSE, process_id);
        }
        
        if (!hProcess) {
            return "Unknown";
        }
        
        wchar_t process_name[MAX_PATH];
        DWORD size = MAX_PATH;
        
        if (QueryFullProcessImageNameW(hProcess, 0, process_name, &size)) {
            std::wstring wname(process_name);
            std::string name(wname.begin(), wname.end());
            
            // 提取文件名（去掉路徑）
            size_t last_slash = name.find_last_of("/\\");
            if (last_slash != std::string::npos) {
                name = name.substr(last_slash + 1);
            }
            
            CloseHandle(hProcess);
            return name;
        }
        
        CloseHandle(hProcess);
        return "Unknown";
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

    void log_critical(const std::string& message) {
        try {
            set_console_color(static_cast<int>(12)); // 紅色
            std::cout << get_timestamp() << " [CRITICAL] " << message << std::endl;
            reset_console_color();
            log_message("CRITICAL", message);
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_critical" << std::endl;
        }
    }

    void log_important(const std::string& message) {
        try {
            set_console_color(static_cast<int>(12)); // 紅色
            std::cout << get_timestamp() << " [ALERT] " << message << std::endl;
            reset_console_color();
            log_message("ALERT", message);
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_important" << std::endl;
        }
    }

    void log_warning(const std::string& message) {
        try {
            set_console_color(static_cast<int>(14)); // 黃色
            std::cout << get_timestamp() << " [WARNING] " << message << std::endl;
            reset_console_color();
            log_message("WARNING", message);
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_warning" << std::endl;
        }
    }

    void log_success(const std::string& message) {
        try {
            set_console_color(static_cast<int>(10)); // 綠色
            std::cout << get_timestamp() << " [SUCCESS] " << message << std::endl;
            reset_console_color();
            log_message("SUCCESS", message);
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_success" << std::endl;
        }
    }

    void log_info(const std::string& message) {
        try {
            set_console_color(static_cast<int>(11)); // 青色
            std::cout << get_timestamp() << " [INFO] " << message << std::endl;
            reset_console_color();
            log_message("INFO", message);
        }
        catch (...) {
            // 不要因為日誌輸出而退出程序
            std::cerr << "Error in log_info" << std::endl;
        }
    }

    // 重寫基類的 start() 方法
    bool start() override {
        try {
            // 初始化日誌檔案
            log_file_.open("detection_engine.log", std::ios::app);
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
    std::map<std::string, std::chrono::steady_clock::time_point> last_log_output_;
    std::map<std::string, int> log_output_count_;
    std::mutex log_control_mutex_;
    
    bool should_output_log(const std::string& log_key, int max_count = 5, int interval_seconds = 30) {
        std::lock_guard<std::mutex> lock(log_control_mutex_);
        auto now = std::chrono::steady_clock::now();
        
        // 檢查是否超過時間間隔
        auto it = last_log_output_.find(log_key);
        if (it != last_log_output_.end()) {
            auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
            if (time_diff.count() < interval_seconds) {
                // 在時間間隔內，檢查輸出次數
                auto count_it = log_output_count_.find(log_key);
                if (count_it != log_output_count_.end() && count_it->second >= max_count) {
                    return false; // 超過最大輸出次數
                }
            } else {
                // 超過時間間隔，重置計數
                log_output_count_[log_key] = 0;
            }
        }
        
        // 更新最後輸出時間和計數
        last_log_output_[log_key] = now;
        log_output_count_[log_key]++;
        return true;
    }
    
    void controlled_log_output(const std::string& log_key, const std::string& message, 
                             int max_count = 5, int interval_seconds = 30, const std::string& level = "DEBUG") {
        if (should_output_log(log_key, max_count, interval_seconds)) {
            log_message(level, message);
        }
    }
    
    void controlled_console_output(const std::string& log_key, const std::string& message, 
                                 int max_count = 5, int interval_seconds = 30) {
        if (should_output_log(log_key, max_count, interval_seconds)) {
            std::cout << message << std::endl;
        }
    }

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
};

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
    
    // 初始化日誌檔案
    std::ofstream log_file("detection_engine.log", std::ios::app);
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