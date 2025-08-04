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

using namespace RealMemoryDetection;

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
        // 系統進程閾值（較高，避免誤報）
        int system_rop_suspicious_patterns = 12;
        int system_rop_ret_count = 20;
        int system_heap_corruption_patterns = 5;
        int system_shellcode_patterns = 5;
        
        // 用戶進程閾值（中等，但更嚴格）
        int user_rop_suspicious_patterns = 8;
        int user_rop_ret_count = 12;
        int user_heap_corruption_patterns = 3;
        int user_shellcode_patterns = 3;
        
        // 攻擊模擬器閾值（較低，更容易檢測）
        int simulator_rop_suspicious_patterns = 2;
        int simulator_rop_ret_count = 3;
        int simulator_heap_corruption_patterns = 1;
        int simulator_shellcode_patterns = 1;
        
        // 高風險進程閾值（更低）
        int high_risk_rop_suspicious_patterns = 2;
        int high_risk_rop_ret_count = 3;
        int high_risk_heap_corruption_patterns = 1;
        int high_risk_shellcode_patterns = 1;
    };
    
    AdaptiveThresholds adaptive_thresholds_;
    
    // 進程分類
    enum ProcessCategory {
        SYSTEM_PROCESS,
        USER_PROCESS,
        ATTACK_SIMULATOR,
        HIGH_RISK_PROCESS
    };
    
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
    
    // 進程分類函數
    ProcessCategory classify_process(const std::string& process_name) {
        std::string lower_name = process_name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        
        // 檢查是否為攻擊模擬器 - 支持多種可能的進程名稱
        if (lower_name.find("attack_simulator") != std::string::npos ||
            lower_name.find("simple_attack_simulator") != std::string::npos ||
            lower_name.find("attack") != std::string::npos) {
            return ATTACK_SIMULATOR;
        }
        
        // 檢查是否為高風險進程
        for (const auto& high_risk : high_risk_processes_) {
            if (lower_name.find(high_risk) != std::string::npos) {
                return HIGH_RISK_PROCESS;
            }
        }
        
        // 檢查是否為系統進程（基於名稱）
        for (const auto& sys_proc : system_processes_) {
            if (lower_name.find(sys_proc) != std::string::npos) {
                return SYSTEM_PROCESS;
            }
        }
        
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
        } else if (whitelist_skip_count_[process_name] % 500 == 0) {
            std::cout << "    Skipped " << whitelist_skip_count_[process_name] << " times for whitelisted process: " << process_name << std::endl;
            log_message("DEBUG", "Skipped " + std::to_string(whitelist_skip_count_[process_name]) + " times for whitelisted process: " + process_name);
        }
    }
    
    // 獲取自適應閾值
    std::pair<int, int> get_rop_thresholds(ProcessCategory category) {
        switch (category) {
            case SYSTEM_PROCESS:
                return {adaptive_thresholds_.system_rop_suspicious_patterns, 
                        adaptive_thresholds_.system_rop_ret_count};
            case ATTACK_SIMULATOR:
                return {adaptive_thresholds_.simulator_rop_suspicious_patterns, 
                        adaptive_thresholds_.simulator_rop_ret_count};
            case HIGH_RISK_PROCESS:
                return {adaptive_thresholds_.high_risk_rop_suspicious_patterns, 
                        adaptive_thresholds_.high_risk_rop_ret_count};
            default: // USER_PROCESS
                return {adaptive_thresholds_.user_rop_suspicious_patterns, 
                        adaptive_thresholds_.user_rop_ret_count};
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

    void detection_loop() {
        while (running_) {
            try {
                // 降低掃描頻率 - 每5秒掃描一次
                scan_memory_for_attacks();
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
                // 每10秒進行一次全進程掃描（原本是60秒）
                if (cycle_output_counter_ % 10 == 0) {
                    scan_all_processes_memory();
                }
                
                // 每60秒輸出一次狀態 (每12次循環 = 12 * 5秒 = 60秒)
                status_output_counter_++;
                if (status_output_counter_ >= 12) { // 12 * 5s = 60s
                    show_status();
                    status_output_counter_ = 0;
                }
                
                // 每300秒輸出一次循環信息 (每60次循環 = 60 * 5秒 = 300秒)
                cycle_output_counter_++;
                if (cycle_output_counter_ >= 60) { // 60 * 5s = 300s
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
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (!hProcess) {
            return;
        }

        MEMORY_BASIC_INFORMATION mbi;
        LPVOID address = 0;
        int region_count = 0;

        std::cout << "    *** Starting deep scan for process " << process_id << " ***" << std::endl;
        log_message("DEBUG", "*** Starting deep scan for process " + std::to_string(process_id) + " ***");

        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT) {
                region_count++;
                
                std::cout << "    Deep Scan Region " << region_count << ": Base=" << mbi.BaseAddress 
                          << ", Size=" << mbi.RegionSize 
                          << ", Protection=" << std::hex << mbi.Protect << std::dec << std::endl;
                log_message("DEBUG", "Deep Scan Region: Base=" + format_address(reinterpret_cast<uint64_t>(mbi.BaseAddress)) + 
                                ", Size=" + std::to_string(mbi.RegionSize) + 
                                ", Protection=" + std::to_string(mbi.Protect));

                check_executable_integrity_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
                check_heap_region_remote(hProcess, mbi.BaseAddress, mbi.RegionSize);
            }
            address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
        }
        std::cout << "    *** Deep scan completed for process " << process_id << " (" << region_count << " regions) ***" << std::endl;
        log_message("DEBUG", "*** Deep scan completed for process " + std::to_string(process_id) + " (" + std::to_string(region_count) + " regions) ***");
        CloseHandle(hProcess);
    }

    void scan_process_memory(DWORD process_id, bool is_system_process) {
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
                            
                            for (size_t i = 0; i < bytes_read - 1; i++) {
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
                                }
                            }
                            
                            // 輸出調試信息
                            if (ret_count > 0 || suspicious_patterns > 0 || shellcode_patterns > 0) {
                                std::cout << "        Debug: ret_count=" << ret_count 
                                          << ", suspicious_patterns=" << suspicious_patterns 
                                          << ", shellcode_patterns=" << shellcode_patterns << std::endl;
                            }
                            
                                    // 進一步提高 ROP 偵測閾值，避免誤報
        if (suspicious_patterns >= 5 || ret_count >= 8) {
            report_attack(AttackType::ROP_CHAIN, (uint64_t)base, "Found ROP gadgets pattern", 0.6);
        }
                            
                            // 偵測shellcode - 降低閾值
                            if (shellcode_patterns >= 1) {
                                report_attack(AttackType::SHELLCODE_INJECTION, (uint64_t)base, "Found shellcode pattern", 0.7);
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
                            
                            for (size_t i = 0; i <= bytes_read - 8; i++) {
                                try {
                                    uint64_t pattern = *(uint64_t*)(&buffer[i]);
                                    if (pattern == 0xDEADBEEF || pattern == 0xBADBADBA) {
                                        corruption_patterns++;
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

            // 獲取自適應閾值
            auto [suspicious_threshold, ret_threshold] = get_rop_thresholds(category);
            int shellcode_threshold = get_shellcode_threshold(category);
            
            // 檢查ROP/JOP gadgets和shellcode - 更全面的檢測
            int ret_count = 0;
            int suspicious_patterns = 0;
            int shellcode_patterns = 0;
            int consecutive_ret = 0; // 連續的ret指令
            int max_consecutive_ret = 0; // 最大連續ret指令數
            
            for (size_t i = 0; i < bytes_read - 1; i++) {
                if (buffer[i] == 0xC3) { // ret指令
                    ret_count++;
                    consecutive_ret++;
                    
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
                    if (i > 0 && buffer[i-1] == 0x5E) { // pop esi
                        suspicious_patterns++;
                    }
                    if (i > 0 && buffer[i-1] == 0x5F) { // pop edi
                        suspicious_patterns++;
                    }
                } else {
                    // 重置連續ret計數
                    if (consecutive_ret > max_consecutive_ret) {
                        max_consecutive_ret = consecutive_ret;
                    }
                    consecutive_ret = 0;
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
                }
                
                // 檢查更複雜的shellcode模式
                if (i < bytes_read - 7) {
                    // 檢查常見的shellcode特徵
                    if (buffer[i] == 0x90 && buffer[i+1] == 0x90 && buffer[i+2] == 0x90 && 
                        buffer[i+3] == 0x90 && buffer[i+4] == 0x90 && buffer[i+5] == 0x90) { // 長nop sled
                        shellcode_patterns += 2; // 給予更高權重
                    }
                    if (buffer[i] == 0xCC && buffer[i+1] == 0xCC && buffer[i+2] == 0xCC && 
                        buffer[i+3] == 0xCC && buffer[i+4] == 0xCC && buffer[i+5] == 0xCC) { // 長int3 sled
                        shellcode_patterns += 2; // 給予更高權重
                    }
                }
            }
            
            // 更新最大連續ret計數
            if (consecutive_ret > max_consecutive_ret) {
                max_consecutive_ret = consecutive_ret;
            }
            
            // 使用自適應閾值進行檢測，並考慮連續ret指令
            bool is_suspicious_rop = (suspicious_patterns >= suspicious_threshold || 
                                    (ret_count >= ret_threshold && max_consecutive_ret >= 3));
            
            if (is_suspicious_rop) {
                std::cout << "    *** REPORTING ROP ATTACK in process " << process_id << " (" << process_name << ") ***" << std::endl;
                std::cout << "    *** Category: " << (category == SYSTEM_PROCESS ? "SYSTEM" : 
                                                      category == ATTACK_SIMULATOR ? "SIMULATOR" :
                                                      category == HIGH_RISK_PROCESS ? "HIGH_RISK" : "USER") << " ***" << std::endl;
                std::cout << "    *** Thresholds: suspicious=" << suspicious_threshold << ", ret=" << ret_threshold << " ***" << std::endl;
                std::cout << "    *** Found: suspicious=" << suspicious_patterns << ", ret=" << ret_count << ", max_consecutive_ret=" << max_consecutive_ret << " ***" << std::endl;
                log_message("DEBUG", "*** REPORTING ROP ATTACK in process " + std::to_string(process_id) + " (" + process_name + ") ***");
                report_attack(AttackType::ROP_CHAIN, (uint64_t)base, "Remote process found ROP gadgets", 0.8, process_id);
            }
            
            // 偵測shellcode
            if (shellcode_patterns >= shellcode_threshold) {
                std::cout << "    *** REPORTING SHELLCODE in process " << process_id << " (" << process_name << ") ***" << std::endl;
                std::cout << "    *** Category: " << (category == SYSTEM_PROCESS ? "SYSTEM" : 
                                                      category == ATTACK_SIMULATOR ? "SIMULATOR" :
                                                      category == HIGH_RISK_PROCESS ? "HIGH_RISK" : "USER") << " ***" << std::endl;
                std::cout << "    *** Shellcode threshold: " << shellcode_threshold << ", found: " << shellcode_patterns << " ***" << std::endl;
                log_message("DEBUG", "*** REPORTING SHELLCODE in process " + std::to_string(process_id) + " (" + process_name + ") ***");
                report_attack(AttackType::SHELLCODE_INJECTION, (uint64_t)base, "Remote process found shellcode pattern", 0.8, process_id);
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

            // 獲取自適應閾值
            int corruption_threshold = get_heap_corruption_threshold(category);
            
            // 檢查堆積破壞模式
            int corruption_patterns = 0;
            
            for (size_t i = 0; i < bytes_read - 4; i++) {
                // 檢查常見的堆積破壞模式
                if (buffer[i] == 0xDE && buffer[i+1] == 0xAD && buffer[i+2] == 0xBE && buffer[i+3] == 0xEF) {
                    corruption_patterns++;
                    std::cout << "    *** Found DEADBEEF pattern at offset " << i << " in process " << process_id << " (" << process_name << ") ***" << std::endl;
                    log_message("DEBUG", "*** Found DEADBEEF pattern at offset " + std::to_string(i) + " in process " + std::to_string(process_id) + " (" + process_name + ") ***");
                }
                if (buffer[i] == 0xBA && buffer[i+1] == 0xAD && buffer[i+2] == 0xF0 && buffer[i+3] == 0x0D) {
                    corruption_patterns++;
                    std::cout << "    *** Found BAADF00D pattern at offset " << i << " in process " << process_id << " (" << process_name << ") ***" << std::endl;
                    log_message("DEBUG", "*** Found BAADF00D pattern at offset " + std::to_string(i) + " in process " + std::to_string(process_id) + " (" + process_name + ") ***");
                }
            }
            
            // 輸出調試信息
            if (corruption_patterns > 0) {
                std::cout << "    Debug: Found " << corruption_patterns << " corruption patterns in process " << process_id << " (" << process_name << ")" << std::endl;
                log_message("DEBUG", "Found " + std::to_string(corruption_patterns) + " corruption patterns in process " + std::to_string(process_id) + " (" + process_name + ")");
            }
            
            // 使用自適應閾值進行檢測
            if (corruption_patterns >= corruption_threshold) {
                std::cout << "    *** REPORTING HEAP CORRUPTION in process " << process_id << " (" << process_name << ") ***" << std::endl;
                std::cout << "    *** Category: " << (category == SYSTEM_PROCESS ? "SYSTEM" : 
                                                      category == ATTACK_SIMULATOR ? "SIMULATOR" :
                                                      category == HIGH_RISK_PROCESS ? "HIGH_RISK" : "USER") << " ***" << std::endl;
                std::cout << "    *** Corruption threshold: " << corruption_threshold << ", found: " << corruption_patterns << " ***" << std::endl;
                log_message("DEBUG", "*** REPORTING HEAP CORRUPTION in process " + std::to_string(process_id) + " (" + process_name + ") ***");
                report_attack(AttackType::HEAP_CORRUPTION, (uint64_t)base, "Remote process found heap corruption pattern", 0.6, process_id);
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
        try {
            // 如果沒有指定目標進程ID，使用當前進程ID（用於本地偵測）
            if (target_process_id == 0) {
                target_process_id = GetCurrentProcessId();
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
                        
                        // 如果這個模式在過去60秒內已經報告過，則跳過
                        if (now - pattern.first_detection < std::chrono::seconds(60)) {
                            std::cout << "Skipping duplicate attack pattern: " << attack_type_to_string(type) 
                                      << " (count: " << pattern.detection_count << ") at " << format_address(address) 
                                      << " in process " << target_process_id << std::endl;
                            return;
                        } else {
                            // 超過60秒，重置計數
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
                    for (auto it = attack_patterns_.begin(); it != attack_patterns_.end(); ++it) {
                        if (it->second.first_detection < oldest->second.first_detection) {
                            oldest = it;
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

            // 攻擊檢測輸出控制 - 每5次檢測輸出1次
            {
                std::lock_guard<std::mutex> lock(attack_output_mutex_);
                attack_detection_counter_++;
                
                if (attack_detection_counter_ % 5 == 0) {
                    // 輸出檢測結果
                    log_important("=== Real Attack Detection ===");
                    log_important("Type: " + attack_type_to_string(type));
                    log_important("Address: " + format_address(address));
                    log_important("Description: " + description);
                    log_important("Confidence: " + std::to_string(confidence));
                    log_important("Process: " + result.process_name + " (PID: " + std::to_string(result.process_id) + ")");
                    log_important("========================================");
                    
                    // 顯示當前檢測計數
                    std::cout << "*** Attack detection output (every 5 detections) - Total detections: " 
                              << attack_detection_counter_ << " ***" << std::endl;
                } else {
                    // 靜默檢測，只更新計數
                    std::cout << "*** Silent attack detection #" << attack_detection_counter_ 
                              << " - " << attack_type_to_string(type) << " in " 
                              << result.process_name << " ***" << std::endl;
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
                // 每120秒才進行一次進程掃描（而不是每1000毫秒）
                scan_processes();
                std::this_thread::sleep_for(std::chrono::seconds(120));
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
                    log_message("INFO", "掃描高優先級進程: " + proc.name + 
                               " (PID: " + std::to_string(proc.pid) + 
                               ", Priority: " + std::to_string(proc.priority) + ")");
                    
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
        ss << "0x" << std::hex << std::uppercase << address;
        return ss.str();
    }

public:
    void set_console_color(int color) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
    }

    void reset_console_color() {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
    }

    void log_important(const std::string& message) {
        try {
            set_console_color(12); // 紅色
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
            set_console_color(14); // 黃色
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
            set_console_color(10); // 綠色
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
            set_console_color(11); // 青色
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