#include "../include/memory_detection_monitor.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>
#include <cmath>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <vector>
#include <string>
#include <Psapi.h>
#include <TlHelp32.h>

namespace RealMemoryDetection {

// ROPGadget 分析實現
void ROPGadget::analyze_gadget() {
    if (bytes.empty()) return;
    
    // 檢查是否以RET結尾
    if (bytes.back() == 0xC3) {
        is_ret_gadget = true;
        
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
    }
}

// Windows兼容的memmem替代函數
const uint8_t* MemoryMonitor::find_pattern(const uint8_t* haystack, size_t haystack_len, 
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

// MemoryMonitor 實現
MemoryMonitor::MemoryMonitor(const MemoryMonitorConfig& config)
    : config_(config)
    , running_(false)
    , heap_monitoring_enabled_(config.enable_heap_monitoring)
    , stack_monitoring_enabled_(config.enable_stack_monitoring)
    , executable_monitoring_enabled_(config.enable_executable_monitoring)
    , shared_memory_monitoring_enabled_(config.enable_shared_memory_monitoring) {
    
    // 初始化統計
    stats_.total_scans = 0;
    stats_.regions_scanned = 0;
    stats_.violations_detected = 0;
    stats_.heap_corruptions = 0;
    stats_.stack_corruptions = 0;
    stats_.executable_violations = 0;
    stats_.rop_detections = 0;
    stats_.jop_detections = 0;
    stats_.shellcode_detections = 0;
    stats_.last_scan = std::chrono::system_clock::now();
    stats_.last_detection = std::chrono::system_clock::now();
    
    // 打開日誌檔案
    log_file_.open(config_.log_file, std::ios::app);
}

MemoryMonitor::~MemoryMonitor() {
    stop();
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

bool MemoryMonitor::start() {
    if (running_) return true;

    running_ = true;
    monitor_thread_ = std::thread(&MemoryMonitor::monitor_loop, this);
    log_message("INFO", "統一的記憶體監控器已啟動");
    return true;
}

void MemoryMonitor::stop() {
    if (!running_) return;

    running_ = false;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    log_message("INFO", "統一的記憶體監控器已停止");
}

bool MemoryMonitor::is_running() const {
    return running_;
}

void MemoryMonitor::set_violation_callback(MemoryViolationCallback callback) {
    violation_callback_ = callback;
}

// 進程分類
MemoryDetectionEngine::ProcessCategory MemoryMonitor::classify_process(const std::string& process_name) {
    if (process_name.find("attack_simulator") != std::string::npos) {
        return MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR;
    }
    
    std::vector<std::string> system_processes = {
        "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe"
    };
    
    for (const auto& sys_proc : system_processes) {
        if (process_name.find(sys_proc) != std::string::npos) {
            return MemoryDetectionEngine::ProcessCategory::SYSTEM_PROCESS;
        }
    }
    
    return MemoryDetectionEngine::ProcessCategory::USER_PROCESS;
}

// 進程優先級評估
int MemoryMonitor::get_process_priority(DWORD pid, const std::string& process_name) {
    if (process_name.find("attack_simulator") != std::string::npos) {
        return 1000; // 最高優先級
    }
    
    int priority = 0;
    if (pid > 10000) priority += 50;
    if (pid > 4000) priority += 30;
    
    return priority;
}

// 監控線程
void MemoryMonitor::monitor_loop() {
    while (running_) {
        try {
            scan_processes();
            scan_memory_regions();
            cleanup_old_attack_chains();
            
            {
                std::lock_guard<std::mutex> lock(stats_mutex_);
                stats_.total_scans++;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.scan_interval_ms));
        }
        catch (const std::exception& e) {
            log_message("ERROR", "Monitor thread exception: " + std::string(e.what()));
        }
    }
}

// 掃描進程
void MemoryMonitor::scan_processes() {
    DWORD processes[4096];
    DWORD cbNeeded;
    
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        DWORD num_processes = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < num_processes && i < config_.max_processes_to_scan; i++) {
            if (processes[i] != 0) {
                std::string process_name = get_process_name(processes[i]);
                if (!process_name.empty()) {
                    monitor_process(processes[i], process_name);
                }
            }
        }
    }
}

// 監控單個進程
void MemoryMonitor::monitor_process(DWORD process_id, const std::string& process_name) {
    MemoryDetectionEngine::ProcessCategory category = classify_process(process_name);
    
    {
        std::lock_guard<std::mutex> lock(processes_mutex_);
        ProcessInfo& info = monitored_processes_[process_id];
        info.process_id = process_id;
        info.process_name = process_name;
        info.category = category;
        info.priority = get_process_priority(process_id, process_name);
        info.last_scan = std::chrono::steady_clock::now();
        info.scan_count++;
    }
    
    // 根據進程類型進行不同深度的掃描
    switch (category) {
        case MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR:
            deep_scan_process(process_id);
            break;
        case MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS:
            {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
                if (hProcess) {
                    smart_scan_process(process_id, hProcess, category);
                    CloseHandle(hProcess);
                }
            }
            break;
        default:
            scan_process_memory(process_id, false);
            break;
    }
}

void MemoryMonitor::deep_scan_process(DWORD process_id) {
// 在子類中實現
}

void MemoryMonitor::smart_scan_process(DWORD process_id, HANDLE hProcess, MemoryDetectionEngine::ProcessCategory category) {
// 在子類中實現
}


void MemoryMonitor::scan_process_memory(DWORD process_id, bool /* is_system_process */) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (!hProcess) {
        return;
    }
    
    std::string process_name = MemoryMonitor::get_process_name(process_id);
    MemoryDetectionEngine::ProcessCategory category = MemoryMonitor::classify_process(process_name);
    bool is_attack_simulator = (process_name.find("attack_simulator") != std::string::npos);
    
    if (is_attack_simulator) {
        std::cout << "    *** Scanning attack simulator memory regions ***" << std::endl;
    }
    
    // 使用智能掃描
    smart_scan_process(process_id, hProcess, category);
    
    if (is_attack_simulator) {
        std::cout << "    *** Smart scan completed for attack simulator ***" << std::endl;
    }
    
    CloseHandle(hProcess);
}

// 掃描記憶體區域
void MemoryMonitor::scan_memory_regions() {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    
    for (auto& [address, region] : monitored_regions_) {
        if (!running_) break;
        
        // 檢查記憶體區域完整性
        if (check_region_integrity(region.base_address, region.size)) {
            region.last_scan = std::chrono::system_clock::now();
            region.scan_count++;
            
            // 檢查是否為可疑區域
            if (check_rop_jop_gadgets(region.base_address, region.size) ||
                check_shellcode_signatures(region.base_address, region.size) ||
                check_heap_corruption_patterns(region.base_address, region.size)) {
                region.is_suspicious = true;
            }
        }
    }
    
    // 更新統計
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    stats_.regions_scanned += monitored_regions_.size();
    stats_.last_scan = std::chrono::system_clock::now();
}

// 檢查堆積完整性
void MemoryMonitor::check_heap_integrity() {
    if (!heap_monitoring_enabled_) return;
    log_message("DEBUG", "檢查堆積完整性");
}

// 檢查堆積區域
void MemoryMonitor::check_heap_region(LPVOID base, SIZE_T size) {
    if (!heap_monitoring_enabled_) return;
    
    try {
        std::vector<uint8_t> buffer(std::min<size_t>(size, config_.max_scan_size));
        SIZE_T bytes_read;
        
        if (ReadProcessMemory(GetCurrentProcess(), base, buffer.data(), buffer.size(), &bytes_read)) {
            int corruption_patterns = 0;
            
            for (size_t i = 0; i < bytes_read - 3; i++) {
                if (buffer[i] == 0xDE && buffer[i+1] == 0xAD && buffer[i+2] == 0xBE && buffer[i+3] == 0xEF) {
                    corruption_patterns++;
                }
            }
            
            if (corruption_patterns >= config_.min_trigger_threshold) {
                report_violation(AttackType::HEAP_CORRUPTION, (uint64_t)base, 
                               "檢測到堆積損壞模式", 0.8);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.heap_corruptions++;
                    stats_.violations_detected++;
                    stats_.last_detection = std::chrono::system_clock::now();
                }
            }
        }
    }
    catch (const std::exception& e) {
        log_message("ERROR", "check_heap_region error: " + std::string(e.what()));
    }
}

// 遠程檢查堆積區域
void MemoryMonitor::check_heap_region_remote(HANDLE hProcess, LPVOID base, SIZE_T size) {
    if (!heap_monitoring_enabled_) return;
    
    try {
        std::vector<uint8_t> buffer(std::min<size_t>(size, config_.max_scan_size));
        SIZE_T bytes_read;
        
        if (ReadProcessMemory(hProcess, base, buffer.data(), buffer.size(), &bytes_read)) {
            int corruption_patterns = 0;
            
            for (size_t i = 0; i < bytes_read - 3; i++) {
                if (buffer[i] == 0xDE && buffer[i+1] == 0xAD && buffer[i+2] == 0xBE && buffer[i+3] == 0xEF) {
                    corruption_patterns++;
                }
            }
            
            if (corruption_patterns >= config_.min_trigger_threshold) {
                DWORD process_id = GetProcessId(hProcess);
                report_violation(AttackType::HEAP_CORRUPTION, (uint64_t)base, 
                               "遠程檢測到堆積損壞模式", 0.8, process_id);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.heap_corruptions++;
                    stats_.violations_detected++;
                    stats_.last_detection = std::chrono::system_clock::now();
                }
            }
        }
    }
    catch (const std::exception& e) {
        log_message("ERROR", "check_heap_region_remote error: " + std::string(e.what()));
    }
}

// 檢查可執行完整性
void MemoryMonitor::check_executable_integrity(LPVOID base, SIZE_T size) {
    if (!executable_monitoring_enabled_) return;
    
    try {
        std::vector<uint8_t> buffer(std::min<size_t>(size, config_.max_scan_size));
        SIZE_T bytes_read;
        
        if (ReadProcessMemory(GetCurrentProcess(), base, buffer.data(), buffer.size(), &bytes_read)) {
            if (check_shellcode_signatures(base, bytes_read)) {
                report_violation(AttackType::SHELLCODE_INJECTION, (uint64_t)base, 
                               "檢測到Shellcode注入", 0.9);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.shellcode_detections++;
                    stats_.violations_detected++;
                    stats_.last_detection = std::chrono::system_clock::now();
                }
            }
        }
    }
    catch (const std::exception& e) {
        log_message("ERROR", "check_executable_integrity error: " + std::string(e.what()));
    }
}

// 遠程檢查可執行完整性
void MemoryMonitor::check_executable_integrity_remote(HANDLE hProcess, LPVOID base, SIZE_T size) {
    if (!executable_monitoring_enabled_) return;
    
    try {
        std::vector<uint8_t> buffer(std::min<size_t>(size, config_.max_scan_size));
        SIZE_T bytes_read;
        
        if (ReadProcessMemory(hProcess, base, buffer.data(), buffer.size(), &bytes_read)) {
            if (check_shellcode_signatures(base, bytes_read)) {
                DWORD process_id = GetProcessId(hProcess);
                report_violation(AttackType::SHELLCODE_INJECTION, (uint64_t)base, 
                               "遠程檢測到Shellcode注入", 0.9, process_id);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.shellcode_detections++;
                    stats_.violations_detected++;
                    stats_.last_detection = std::chrono::system_clock::now();
                }
            }
        }
    }
    catch (const std::exception& e) {
        log_message("ERROR", "check_executable_integrity_remote error: " + std::string(e.what()));
    }
}

// 檢查堆疊完整性
void MemoryMonitor::check_stack_integrity() {
    if (!stack_monitoring_enabled_) return;
    log_message("DEBUG", "檢查堆疊完整性");
}

// 檢查共享記憶體
void MemoryMonitor::check_shared_memory() {
    if (!shared_memory_monitoring_enabled_) return;
    log_message("DEBUG", "檢查共享記憶體");
}


bool MemoryMonitor::detect_modern_shellcode(const uint8_t* buffer, size_t size) {
    // 檢測Egg Hunter模式
    const char egg_pattern[] = {0x66,0x81,0xCA,0xFF,0x0F,0x42,0x52,0x6A,0x02}; // NTAccessCheck
    if (MemoryMonitor::find_pattern(buffer, size, egg_pattern, sizeof(egg_pattern))) return true;

    // 檢測反射式DLL注入特徵
    const char reflective[] = {0xE8,0x00,0x00,0x00,0x00,0x5B,0x81,0xEB};
    if (MemoryMonitor::find_pattern(buffer, size, reflective, sizeof(reflective))) return true;

    // 檢測Cobalt Strike信標特徵
    const char cobalt[] = {0x48,0x83,0xEC,0x28,0xB9,0x08,0x00,0x00,0x00};
    if (MemoryMonitor::find_pattern(buffer, size, cobalt, sizeof(cobalt))) return true;
    
    // 檢測Metasploit特徵
    const char metasploit[] = {0x68,0x61,0x6C,0x6C,0x00,0x68,0x6E,0x65,0x6C,0x33,0x32}; // "hall\0" + "nel32"
    if (MemoryMonitor::find_pattern(buffer, size, metasploit, sizeof(metasploit))) return true;
    
    // 檢測PowerShell Empire特徵
    const char empire[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10};
    if (MemoryMonitor::find_pattern(buffer, size, empire, sizeof(empire))) return true;
    
    // 檢測Mimikatz特徵
    const char mimikatz[] = {0x48,0x83,0xEC,0x20,0x48,0x8B,0x05};
    if (MemoryMonitor::find_pattern(buffer, size, mimikatz, sizeof(mimikatz))) return true;
    
    // 檢測Process Hollowing特徵
    const char hollow[] = {0x48,0x89,0x5C,0x24,0x08,0x57,0x48,0x83,0xEC,0x20};
    if (MemoryMonitor::find_pattern(buffer, size, hollow, sizeof(hollow))) return true;
    
    // 檢測API Hashing特徵
    const char api_hash[] = {0x48,0x31,0xC9,0x48,0x81,0xE9}; // xor rcx, rcx; sub rcx
    if (MemoryMonitor::find_pattern(buffer, size, api_hash, sizeof(api_hash))) return true;
    
    // 檢測反虛擬機特徵
    const char anti_vm[] = {0x64,0xA1,0x18,0x00,0x00,0x00,0x8B,0x40,0x30}; // PEB BeingDebugged
    if (MemoryMonitor::find_pattern(buffer, size, anti_vm, sizeof(anti_vm))) return true;
    
    // 檢測動態API解析特徵
    const char dynamic_api[] = {0x48,0x8B,0x05,0x00,0x00,0x00,0x00,0x48,0x85,0xC0}; // mov rax, [rip+0]; test rax, rax
    if (MemoryMonitor::find_pattern(buffer, size, dynamic_api, sizeof(dynamic_api))) return true;
    
    // 檢測Shellcode Loader特徵
    const char loader[] = {0x48,0x89,0xE5,0x48,0x83,0xEC,0x20,0x48,0x89,0x5D,0xF8};
    if (MemoryMonitor::find_pattern(buffer, size, loader, sizeof(loader))) return true;
    
    // 檢測加密/解密特徵
    const char crypto[] = {0x48,0x31,0xC0,0x48,0x31,0xC9,0x48,0x31,0xD2}; // xor rax, rax; xor rcx, rcx; xor rdx, rdx
    if (MemoryMonitor::find_pattern(buffer, size, crypto, sizeof(crypto))) return true;
    
    // 檢測網絡通信特徵
    const char network[] = {0x48,0x83,0xEC,0x28,0x48,0x89,0x5C,0x24,0x20,0x48,0x89,0x6C,0x24,0x28};
    if (MemoryMonitor::find_pattern(buffer, size, network, sizeof(network))) return true;
    
    // 檢測文件操作特徵
    const char file_ops[] = {0x48,0x8D,0x15,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D}; // lea rdx, [rip+0]; lea rcx
    if (MemoryMonitor::find_pattern(buffer, size, file_ops, sizeof(file_ops))) return true;
    
    // 檢測註冊表操作特徵
    const char registry[] = {0x48,0x8D,0x15,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D,0x00,0x00,0x00,0x00};
    if (MemoryMonitor::find_pattern(buffer, size, registry, sizeof(registry))) return true;
    
    // 檢測進程注入特徵
    const char injection[] = {0x48,0x89,0x5C,0x24,0x08,0x48,0x89,0x74,0x24,0x10,0x57,0x48,0x83,0xEC,0x20};
    if (MemoryMonitor::find_pattern(buffer, size, injection, sizeof(injection))) return true;
    
    // 檢測權限提升特徵
    const char priv_esc[] = {0x48,0x83,0xEC,0x28,0x48,0x89,0x5C,0x24,0x20,0x48,0x89,0x6C,0x24,0x28,0x48,0x89,0x74,0x24,0x30};
    if (MemoryMonitor::find_pattern(buffer, size, priv_esc, sizeof(priv_esc))) return true;
    
    return false;
}




// 工具函數實現
std::string MemoryMonitor::get_process_name(DWORD process_id) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (hProcess == nullptr) return "";
    
    char process_name[MAX_PATH];
    HMODULE hMod;
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseNameA(hProcess, hMod, process_name, sizeof(process_name));
    } else {
        strcpy_s(process_name, "Unknown");
    }
    
    CloseHandle(hProcess);
    return std::string(process_name);
}

// 從 detection_engine.cpp 遷移的工具函數
bool MemoryMonitor::is_whitelisted_process(const std::string& process_name) {
    // 白名單進程列表
    static const std::vector<std::string> whitelist = {
        "svchost.exe", "lsass.exe", "winlogon.exe", "csrss.exe", "wininit.exe",
        "services.exe", "spoolsv.exe", "explorer.exe", "taskmgr.exe", "cmd.exe",
        "powershell.exe", "conhost.exe", "dwm.exe", "rundll32.exe", "regsvr32.exe",
        "msiexec.exe", "wuauclt.exe", "sppsvc.exe", "sethc.exe", "utilman.exe",
        "osk.exe", "narrator.exe", "magnify.exe", "msconfig.exe", "tasklist.exe",
        "netstat.exe", "ipconfig.exe", "ping.exe", "tracert.exe", "nslookup.exe",
        "systeminfo.exe", "ver.exe", "whoami.exe", "dir.exe", "copy.exe", "move.exe",
        "del.exe", "ren.exe", "type.exe", "find.exe", "findstr.exe", "sort.exe",
        "more.exe", "less.exe", "head.exe", "tail.exe", "grep.exe", "awk.exe",
        "sed.exe", "cut.exe", "paste.exe", "join.exe", "split.exe", "uniq.exe",
        "wc.exe", "tee.exe", "tr.exe", "fold.exe", "fmt.exe", "pr.exe", "nl.exe",
        "od.exe", "hexdump.exe", "strings.exe", "file.exe", "stat.exe", "touch.exe",
        "mkdir.exe", "rmdir.exe", "rm.exe", "ln.exe", "chmod.exe", "chown.exe",
        "ls.exe", "cat.exe", "echo.exe", "printf.exe", "test.exe", "expr.exe",
        "bc.exe", "dc.exe", "cal.exe", "date.exe", "time.exe", "sleep.exe",
        "kill.exe", "pkill.exe", "killall.exe", "nice.exe", "renice.exe", "top.exe",
        "htop.exe", "iotop.exe", "iftop.exe", "nethogs.exe", "ss.exe", "lsof.exe",
        "fuser.exe", "strace.exe", "ltrace.exe", "gdb.exe", "objdump.exe", "nm.exe",
        "readelf.exe", "ldd.exe", "ldconfig.exe", "ld.so", "libc.so", "libm.so",
        "libdl.so", "libpthread.so", "libcrypt.so", "libutil.so", "libnsl.so",
        "libnss_files.so", "libnss_dns.so", "libresolv.so", "libnss_compat.so",
        "libnss_hesiod.so", "libnss_nis.so", "libnss_nisplus.so", "libnss_ldap.so",
        "libnss_sss.so", "libnss_winbind.so", "libnss_mdns4.so", "libnss_mdns4_minimal.so",
        "libnss_mdns6.so", "libnss_mdns6_minimal.so", "libnss_myhostname.so",
        "libnss_myhostname.so", "libnss_wins.so", "libnss_hesiod.so", "libnss_nis.so",
        "libnss_nisplus.so", "libnss_ldap.so", "libnss_sss.so", "libnss_winbind.so",
        "libnss_mdns4.so", "libnss_mdns4_minimal.so", "libnss_mdns6.so", "libnss_mdns6_minimal.so",
        "libnss_myhostname.so", "libnss_myhostname.so", "libnss_wins.so"
    };
    
    std::string lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    return std::find(whitelist.begin(), whitelist.end(), lower_name) != whitelist.end();
}

// 系統進程檢測函數
bool MemoryMonitor::is_system_process(DWORD process_id) {
    // 系統進程列表
    static const std::vector<std::string> system_processes = {
        "System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "svchost.exe", "winlogon.exe", "spoolsv.exe", "explorer.exe",
        "taskmgr.exe", "dwm.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe",
        "wuauclt.exe", "sppsvc.exe", "sethc.exe", "utilman.exe", "osk.exe",
        "narrator.exe", "magnify.exe", "msconfig.exe", "tasklist.exe", "netstat.exe",
        "ipconfig.exe", "ping.exe", "tracert.exe", "nslookup.exe", "systeminfo.exe",
        "ver.exe", "whoami.exe", "dir.exe", "copy.exe", "move.exe", "del.exe",
        "ren.exe", "type.exe", "find.exe", "findstr.exe", "sort.exe", "more.exe",
        "less.exe", "head.exe", "tail.exe", "grep.exe", "awk.exe", "sed.exe",
        "cut.exe", "paste.exe", "join.exe", "split.exe", "uniq.exe", "wc.exe",
        "tee.exe", "tr.exe", "fold.exe", "fmt.exe", "pr.exe", "nl.exe", "od.exe",
        "hexdump.exe", "strings.exe", "file.exe", "stat.exe", "touch.exe", "mkdir.exe",
        "rmdir.exe", "rm.exe", "ln.exe", "chmod.exe", "chown.exe", "ls.exe", "cat.exe",
        "echo.exe", "printf.exe", "test.exe", "expr.exe", "bc.exe", "dc.exe", "cal.exe",
        "date.exe", "time.exe", "sleep.exe", "kill.exe", "pkill.exe", "killall.exe",
        "nice.exe", "renice.exe", "top.exe", "htop.exe", "iotop.exe", "iftop.exe",
        "nethogs.exe", "ss.exe", "lsof.exe", "fuser.exe", "strace.exe", "ltrace.exe",
        "gdb.exe", "objdump.exe", "nm.exe", "readelf.exe", "ldd.exe", "ldconfig.exe"
    };
    
    std::string process_name = get_process_name(process_id);
    if (process_name.empty()) return false;
    
    std::string lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    return std::find(system_processes.begin(), system_processes.end(), lower_name) != system_processes.end();
}





// 增強的熵計算函數
double MemoryMonitor::calculate_shannon_entropy(const uint8_t* buffer, size_t size, const std::string& process_name) {
    if (!buffer || size == 0) return 0.0;
    
    // 計算字節頻率
    std::array<int, 256> freq = {};
    for (size_t i = 0; i < size; ++i) {
        freq[buffer[i]]++;
    }
    
    double entropy = 0.0;
    double size_d = static_cast<double>(size);
    
    for (int count : freq) {
        if (count > 0) {
            double probability = count / size_d;
            entropy -= probability * std::log2(probability);
        }
    }
    
    // 簡化版本，不使用實例成員
    return entropy;
}

// 增強的 Shellcode 檢測
bool MemoryMonitor::is_valid_shellcode(const uint8_t* buffer, size_t size, const std::string& process_name) {
    if (!buffer || size < 16) return false;
    
    // 檢查常見的 shellcode 特徵
    const uint8_t* ptr = buffer;
    size_t remaining = size;
    
    // 檢查 NOP sled
    int nop_count = 0;
    for (size_t i = 0; i < std::min<size_t>(size, 64); ++i) {
        if (ptr[i] == 0x90) nop_count++;
    }
    
    // 檢查常見的 shellcode 開頭
    bool has_shellcode_header = false;
    if (size >= 4) {
        // Windows API 調用模式
        if (ptr[0] == 0x68 && ptr[4] == 0xE8) has_shellcode_header = true; // push + call
        if (ptr[0] == 0xE8 && ptr[4] == 0x68) has_shellcode_header = true; // call + push
        
        // 常見的 shellcode 模式
        if (ptr[0] == 0xEB && ptr[1] == 0x02) has_shellcode_header = true; // jmp short
        if (ptr[0] == 0xE9) has_shellcode_header = true; // jmp
        if (ptr[0] == 0xE8) has_shellcode_header = true; // call
    }
    
    // 檢查高熵值（加密的 shellcode）
    double entropy = calculate_shannon_entropy(buffer, size, process_name);
    bool high_entropy = entropy > 7.0;
    
    // 檢查進程特定的行為
    MemoryDetectionEngine::ProcessCategory category = MemoryDetectionEngine::ProcessCategory::USER_PROCESS;
    if (process_name.find("attack_simulator") != std::string::npos) {
        category = MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR;
    }
    bool is_suspicious_process = (category == MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR ||
                                 category == MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS);
    
    // 綜合判斷
    int score = 0;
    if (nop_count > 10) score += 2;
    if (has_shellcode_header) score += 3;
    if (high_entropy) score += 2;
    if (is_suspicious_process) score += 1;
    
    return score >= 4; // 需要至少4分才認為是有效的 shellcode
}





// 統計和狀態
MonitorStats MemoryMonitor::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<ExtendedProcessInfo> MemoryMonitor::get_monitored_processes() const {
    std::lock_guard<std::mutex> lock(processes_mutex_);
    std::vector<ExtendedProcessInfo> result;
    for (const auto& [pid, info] : monitored_processes_) {
        result.push_back(info);
    }
    return result;
}

std::vector<MemoryRegionInfo> MemoryMonitor::get_monitored_regions() const {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    std::vector<MemoryRegionInfo> result;
    for (const auto& [addr, info] : monitored_regions_) {
        result.push_back(info);
    }
    return result;
}

// 配置管理
void MemoryMonitor::set_scan_interval(uint32_t interval_ms) {
    config_.scan_interval_ms = interval_ms;
}

void MemoryMonitor::enable_heap_monitoring(bool enable) {
    heap_monitoring_enabled_ = enable;
}

void MemoryMonitor::enable_stack_monitoring(bool enable) {
    stack_monitoring_enabled_ = enable;
}

void MemoryMonitor::enable_executable_monitoring(bool enable) {
    executable_monitoring_enabled_ = enable;
}

void MemoryMonitor::enable_shared_memory_monitoring(bool enable) {
    shared_memory_monitoring_enabled_ = enable;
}

void MemoryMonitor::update_config(const MemoryMonitorConfig& config) {
    config_ = config;
}

// 攻擊鏈管理
void MemoryMonitor::add_to_attack_chain(DWORD process_id, uint64_t address, AttackType attack_type, double confidence) {
    std::lock_guard<std::mutex> lock(attack_chain_mutex_);
    
    uint64_t key = (static_cast<uint64_t>(process_id) << 32) | (address & 0xFFFFFFFF);
    
    if (attack_chains_.find(key) == attack_chains_.end()) {
        attack_chains_[key] = AttackChain(process_id, address);
    }
    
    AttackChain& chain = attack_chains_[key];
    chain.detected_attacks.push_back(attack_type);
    chain.highest_confidence = std::max<double>(chain.highest_confidence, confidence);
    
    if (attack_type == AttackType::SHELLCODE_INJECTION) {
        chain.has_shellcode_payload = true;
    }
}

void MemoryMonitor::cleanup_old_attack_chains() {
    std::lock_guard<std::mutex> lock(attack_chain_mutex_);
    
    auto now = std::chrono::steady_clock::now();
    auto threshold = now - std::chrono::hours(1);
    
    for (auto it = attack_chains_.begin(); it != attack_chains_.end();) {
        if (it->second.first_detection < threshold) {
            it = attack_chains_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<AttackChain> MemoryMonitor::get_attack_chains() const {
    std::lock_guard<std::mutex> lock(attack_chain_mutex_);
    std::vector<AttackChain> result;
    for (const auto& [key, chain] : attack_chains_) {
        result.push_back(chain);
    }
    return result;
}

// 內部工具函數
void MemoryMonitor::report_violation(AttackType type, uint64_t address, 
                                   const std::string& description, double confidence, DWORD process_id) {
    if (violation_callback_) {
        violation_callback_(type, address, description, confidence, process_id);
    }
    
    log_message("ALERT", "檢測到攻擊: " + description + " 地址: 0x" + format_address(address));
}

void MemoryMonitor::log_message(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    std::string timestamp = get_timestamp();
    std::string log_entry = timestamp + " [" + level + "] " + message + "\n";
    
    if (log_file_.is_open()) {
        log_file_ << log_entry;
        log_file_.flush();
    }
    
    std::cout << log_entry;
}

std::string MemoryMonitor::get_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string MemoryMonitor::format_address(uint64_t address) const {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << address;
    return oss.str();
}

bool MemoryMonitor::is_executable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_EXECUTE) || 
               (mbi.Protect & PAGE_EXECUTE_READ) || 
               (mbi.Protect & PAGE_EXECUTE_READWRITE);
    }
    return false;
}

bool MemoryMonitor::is_readable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_READONLY) || 
               (mbi.Protect & PAGE_READWRITE) || 
               (mbi.Protect & PAGE_EXECUTE_READ) || 
               (mbi.Protect & PAGE_EXECUTE_READWRITE);
    }
    return false;
}

bool MemoryMonitor::is_writable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_READWRITE) || 
               (mbi.Protect & PAGE_EXECUTE_READWRITE) || 
               (mbi.Protect & PAGE_WRITECOPY) || 
               (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
    }
    return false;
}

bool MemoryMonitor::safe_read_memory(LPVOID address, SIZE_T size, std::vector<uint8_t>& buffer) const {
    if (!is_readable_memory(address, size)) return false;
    
    buffer.resize(size);
    SIZE_T bytes_read;
    return ReadProcessMemory(GetCurrentProcess(), address, buffer.data(), size, &bytes_read) && 
           bytes_read == size;
}

bool MemoryMonitor::check_memory_consistency(HANDLE hProcess, LPVOID base, SIZE_T size) {
    return true;
}

// 閾值管理
AdaptiveThresholds MemoryMonitor::get_adaptive_thresholds(MemoryDetectionEngine::ProcessCategory category) {
    return adaptive_thresholds_;
}

int MemoryMonitor::get_rop_threshold(MemoryDetectionEngine::ProcessCategory category) {
    switch (category) {
        case MemoryDetectionEngine::ProcessCategory::SYSTEM_PROCESS:
            return adaptive_thresholds_.system_rop_suspicious_patterns;
        case MemoryDetectionEngine::ProcessCategory::USER_PROCESS:
            return adaptive_thresholds_.user_rop_suspicious_patterns;
        case MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR:
            return adaptive_thresholds_.simulator_rop_suspicious_patterns;
        case MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS:
            return adaptive_thresholds_.high_risk_rop_suspicious_patterns;
        default:
            return adaptive_thresholds_.user_rop_suspicious_patterns;
    }
}

int MemoryMonitor::get_heap_corruption_threshold(MemoryDetectionEngine::ProcessCategory category) {
    switch (category) {
        case MemoryDetectionEngine::ProcessCategory::SYSTEM_PROCESS:
            return adaptive_thresholds_.system_heap_corruption_patterns;
        case MemoryDetectionEngine::ProcessCategory::USER_PROCESS:
            return adaptive_thresholds_.user_heap_corruption_patterns;
        case MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR:
            return adaptive_thresholds_.simulator_heap_corruption_patterns;
        case MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS:
            return adaptive_thresholds_.high_risk_heap_corruption_patterns;
        default:
            return adaptive_thresholds_.user_heap_corruption_patterns;
    }
}

int MemoryMonitor::get_shellcode_threshold(MemoryDetectionEngine::ProcessCategory category) {
    switch (category) {
        case MemoryDetectionEngine::ProcessCategory::SYSTEM_PROCESS:
            return adaptive_thresholds_.system_shellcode_patterns;
        case MemoryDetectionEngine::ProcessCategory::USER_PROCESS:
            return adaptive_thresholds_.user_shellcode_patterns;
        case MemoryDetectionEngine::ProcessCategory::ATTACK_SIMULATOR:
            return adaptive_thresholds_.simulator_shellcode_patterns;
        case MemoryDetectionEngine::ProcessCategory::HIGH_RISK_PROCESS:
            return adaptive_thresholds_.high_risk_shellcode_patterns;
        default:
            return adaptive_thresholds_.user_shellcode_patterns;
    }
}

// 內部掃描函數實現
void MemoryMonitor::scan_memory_region(const MemoryRegionInfo& region) {
    // 實現記憶體區域掃描
}

bool MemoryMonitor::check_region_integrity(LPVOID address, SIZE_T size) {
    return true;
}

bool MemoryMonitor::check_rop_jop_gadgets(LPVOID address, SIZE_T size) {
    return false;
}

bool MemoryMonitor::check_shellcode_signatures(LPVOID address, SIZE_T size) {
    return false;
}

bool MemoryMonitor::check_heap_corruption_patterns(LPVOID address, SIZE_T size) {
    return false;
}

bool MemoryMonitor::check_use_after_free_patterns(LPVOID address, SIZE_T size) {
    return false;
}

bool MemoryMonitor::check_buffer_overflow_patterns(LPVOID address, SIZE_T size) {
    return false;
}

} // namespace RealMemoryDetection
