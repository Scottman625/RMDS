#include "../include/real_memory_detection_monitor.hpp"
#include "../include/real_memory_detection_types.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <Psapi.h>
#include <TlHelp32.h>

// 添加缺少的常數定義
#ifndef PROCESS_HEAP_ENTRY_CORRUPTED
#define PROCESS_HEAP_ENTRY_CORRUPTED 0x00000010
#endif

namespace RealMemoryDetection {

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
    stats_.last_scan = std::chrono::system_clock::now();
    
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
    if (running_) {
        return true;
    }

    running_ = true;
    monitor_thread_ = std::thread(&MemoryMonitor::monitor_loop, this);
    
    log_message("INFO", "記憶體監控器已啟動");
    return true;
}

void MemoryMonitor::stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    
    log_message("INFO", "記憶體監控器已停止");
}

bool MemoryMonitor::is_running() const {
    return running_;
}

void MemoryMonitor::set_violation_callback(MemoryViolationCallback callback) {
    violation_callback_ = callback;
}

void MemoryMonitor::scan_memory_regions() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;
    uint32_t regions_scanned = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi)) && regions_scanned < config_.max_regions_per_scan) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegionInfo region;
            region.base_address = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            region.is_monitored = false;
            region.last_scan = std::chrono::system_clock::now();
            region.scan_count = 0;
            region.is_suspicious = false;

            scan_memory_region(region);
            regions_scanned++;
        }
        
        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_scans++;
        stats_.regions_scanned += regions_scanned;
        stats_.last_scan = std::chrono::system_clock::now();
    }
}

void MemoryMonitor::check_heap_integrity() {
    if (!heap_monitoring_enabled_) {
        return;
    }

    HANDLE hHeap = GetProcessHeap();
    if (!hHeap) {
        return;
    }

    PROCESS_HEAP_ENTRY entry;
    entry.lpData = NULL;

    if (HeapLock(hHeap)) {
        while (HeapWalk(hHeap, &entry)) {
            if (entry.wFlags & PROCESS_HEAP_ENTRY_CORRUPTED) {
                report_violation(AttackType::HEAP_CORRUPTION, 
                               (uint64_t)entry.lpData, 
                               "堆損壞檢測", 0.9);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.heap_corruptions++;
                }
            }
        }
        HeapUnlock(hHeap);
    }
}

void MemoryMonitor::check_stack_integrity() {
    if (!stack_monitoring_enabled_) {
        return;
    }

    // 檢查當前線程的堆疊
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // 檢查堆疊指針是否在合理範圍內
        uint64_t stack_ptr = ctx.Rsp;
        
        // 檢查堆疊是否溢出
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)stack_ptr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_FREE) {
                report_violation(AttackType::STACK_OVERFLOW, 
                               stack_ptr, 
                               "堆疊溢出檢測", 0.8);
                
                {
                    std::lock_guard<std::mutex> lock(stats_mutex_);
                    stats_.stack_corruptions++;
                }
            }
        }
    }
}

void MemoryMonitor::check_executable_memory() {
    if (!executable_monitoring_enabled_) {
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE)) {
            MemoryRegionInfo region;
            region.base_address = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            region.is_monitored = false;
            region.last_scan = std::chrono::system_clock::now();
            region.scan_count = 0;
            region.is_suspicious = false;

            scan_memory_region(region);
        }
        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
    }
}

void MemoryMonitor::check_shared_memory() {
    if (!shared_memory_monitoring_enabled_) {
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED) {
            MemoryRegionInfo region;
            region.base_address = mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protection = mbi.Protect;
            region.state = mbi.State;
            region.type = mbi.Type;
            region.is_monitored = false;
            region.last_scan = std::chrono::system_clock::now();
            region.scan_count = 0;
            region.is_suspicious = false;

            scan_memory_region(region);
        }
        address = (LPVOID)((uint64_t)mbi.BaseAddress + mbi.RegionSize);
    }
}

MemoryMonitor::MonitorStats MemoryMonitor::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<MemoryRegionInfo> MemoryMonitor::get_monitored_regions() const {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    std::vector<MemoryRegionInfo> regions;
    regions.reserve(monitored_regions_.size());
    
    for (const auto& pair : monitored_regions_) {
        regions.push_back(pair.second);
    }
    
    return regions;
}

void MemoryMonitor::add_region_to_monitor(LPVOID address, SIZE_T size) {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    
    MemoryRegionInfo region;
    region.base_address = address;
    region.size = size;
    region.is_monitored = true;
    region.last_scan = std::chrono::system_clock::now();
    region.scan_count = 0;
    region.is_suspicious = false;
    
    // 獲取記憶體保護信息
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        region.protection = mbi.Protect;
        region.state = mbi.State;
        region.type = mbi.Type;
    }
    
    monitored_regions_[address] = region;
    log_message("INFO", "添加記憶體區域到監控: " + format_address((uint64_t)address));
}

void MemoryMonitor::remove_region_from_monitor(LPVOID address) {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    
    auto it = monitored_regions_.find(address);
    if (it != monitored_regions_.end()) {
        monitored_regions_.erase(it);
        log_message("INFO", "移除記憶體區域監控: " + format_address((uint64_t)address));
    }
}

void MemoryMonitor::clear_monitored_regions() {
    std::lock_guard<std::mutex> lock(regions_mutex_);
    monitored_regions_.clear();
    log_message("INFO", "清空所有監控的記憶體區域");
}

void MemoryMonitor::set_scan_interval(uint32_t interval_ms) {
    config_.scan_interval_ms = interval_ms;
}

void MemoryMonitor::enable_heap_monitoring(bool enable) {
    heap_monitoring_enabled_ = enable;
    log_message("INFO", "堆監控 " + std::string(enable ? "已啟用" : "已禁用"));
}

void MemoryMonitor::enable_stack_monitoring(bool enable) {
    stack_monitoring_enabled_ = enable;
    log_message("INFO", "堆疊監控 " + std::string(enable ? "已啟用" : "已禁用"));
}

void MemoryMonitor::enable_executable_monitoring(bool enable) {
    executable_monitoring_enabled_ = enable;
    log_message("INFO", "可執行記憶體監控 " + std::string(enable ? "已啟用" : "已禁用"));
}

void MemoryMonitor::enable_shared_memory_monitoring(bool enable) {
    shared_memory_monitoring_enabled_ = enable;
    log_message("INFO", "共享記憶體監控 " + std::string(enable ? "已啟用" : "已禁用"));
}

void MemoryMonitor::monitor_loop() {
    while (running_) {
        try {
            // 掃描記憶體區域
            scan_memory_regions();
            
            // 檢查堆完整性
            check_heap_integrity();
            
            // 檢查堆疊完整性
            check_stack_integrity();
            
            // 檢查可執行記憶體
            check_executable_memory();
            
            // 檢查共享記憶體
            check_shared_memory();
            
            // 掃描監控的區域
            {
                std::lock_guard<std::mutex> lock(regions_mutex_);
                for (auto& pair : monitored_regions_) {
                    scan_memory_region(pair.second);
                    pair.second.scan_count++;
                    pair.second.last_scan = std::chrono::system_clock::now();
                }
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.scan_interval_ms));
        }
        catch (const std::exception& e) {
            log_message("ERROR", "記憶體監控線程異常: " + std::string(e.what()));
        }
    }
}

void MemoryMonitor::scan_memory_region(const MemoryRegionInfo& region) {
    // 檢查記憶體區域的完整性
    if (!check_region_integrity(region.base_address, region.size)) {
        return;
    }
    
    // 檢查ROP/JOP gadgets
    if (check_rop_jop_gadgets(region.base_address, region.size)) {
        report_violation(AttackType::ROP_CHAIN, 
                        (uint64_t)region.base_address, 
                        "發現ROP/JOP gadgets", 0.7);
    }
    
    // 檢查Shellcode特徵
    if (check_shellcode_signatures(region.base_address, region.size)) {
        report_violation(AttackType::SHELLCODE_INJECTION, 
                        (uint64_t)region.base_address, 
                        "發現Shellcode特徵", 0.6);
    }
    
    // 檢查堆損壞模式
    if (check_heap_corruption_patterns(region.base_address, region.size)) {
        report_violation(AttackType::HEAP_CORRUPTION, 
                        (uint64_t)region.base_address, 
                        "發現堆損壞模式", 0.8);
    }
    
    // 檢查Use-After-Free模式
    if (check_use_after_free_patterns(region.base_address, region.size)) {
        report_violation(AttackType::USE_AFTER_FREE, 
                        (uint64_t)region.base_address, 
                        "發現Use-After-Free模式", 0.7);
    }
    
    // 檢查緩衝區溢出模式
    if (check_buffer_overflow_patterns(region.base_address, region.size)) {
        report_violation(AttackType::BUFFER_OVERFLOW, 
                        (uint64_t)region.base_address, 
                        "發現緩衝區溢出模式", 0.6);
    }
}

bool MemoryMonitor::check_region_integrity(LPVOID address, SIZE_T size) {
    // 檢查記憶體是否可讀
    if (!is_readable_memory(address, size)) {
        return false;
    }
    
    // 檢查記憶體是否有效
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) {
        return false;
    }
    
    return (mbi.State == MEM_COMMIT);
}

bool MemoryMonitor::check_rop_jop_gadgets(LPVOID address, SIZE_T size) {
    std::vector<uint8_t> buffer;
    if (!safe_read_memory(address, size, buffer)) {
        return false;
    }
    
    // 檢查ROP gadgets (ret指令)
    for (size_t i = 0; i < buffer.size() - 1; i++) {
        if (buffer[i] == 0xC3) { // ret指令
            return true;
        }
        
        // 檢查JOP gadgets (jmp指令)
        if (buffer[i] == 0xFF && buffer[i + 1] == 0xE0) { // jmp rax
            return true;
        }
    }
    
    return false;
}

bool MemoryMonitor::check_shellcode_signatures(LPVOID address, SIZE_T size) {
    std::vector<uint8_t> buffer;
    if (!safe_read_memory(address, size, buffer)) {
        return false;
    }
    
    // 檢查NOP sled
    for (size_t i = 0; i < buffer.size() - 3; i++) {
        if (buffer[i] == 0x90 && buffer[i + 1] == 0x90 && 
            buffer[i + 2] == 0x90 && buffer[i + 3] == 0x90) {
            return true;
        }
    }
    
    // 檢查常見的Shellcode特徵
    std::vector<uint8_t> shellcode_signatures[] = {
        {0x31, 0xC0}, // xor eax, eax
        {0x31, 0xDB}, // xor ebx, ebx
        {0x31, 0xC9}, // xor ecx, ecx
        {0x31, 0xD2}, // xor edx, edx
    };
    
    for (const auto& sig : shellcode_signatures) {
        for (size_t i = 0; i <= buffer.size() - sig.size(); i++) {
            if (std::equal(sig.begin(), sig.end(), buffer.begin() + i)) {
                return true;
            }
        }
    }
    
    return false;
}

bool MemoryMonitor::check_heap_corruption_patterns(LPVOID address, SIZE_T size) {
    std::vector<uint8_t> buffer;
    if (!safe_read_memory(address, size, buffer)) {
        return false;
    }
    
    // 檢查堆損壞模式
    for (size_t i = 0; i <= buffer.size() - 8; i++) {
        uint64_t pattern = *(uint64_t*)(&buffer[i]);
        if (pattern == 0xDEADBEEF || pattern == 0xBADBADBA) {
            return true;
        }
    }
    
    return false;
}

bool MemoryMonitor::check_use_after_free_patterns(LPVOID address, SIZE_T size) {
    std::vector<uint8_t> buffer;
    if (!safe_read_memory(address, size, buffer)) {
        return false;
    }
    
    // 檢查Use-After-Free模式
    for (size_t i = 0; i <= buffer.size() - 8; i++) {
        uint64_t pattern = *(uint64_t*)(&buffer[i]);
        if (pattern == 0xFEEEFEEE || pattern == 0xCDCDCDCD) {
            return true;
        }
    }
    
    return false;
}

bool MemoryMonitor::check_buffer_overflow_patterns(LPVOID address, SIZE_T size) {
    std::vector<uint8_t> buffer;
    if (!safe_read_memory(address, size, buffer)) {
        return false;
    }
    
    // 檢查緩衝區溢出模式 (連續的相同字節)
    for (size_t i = 0; i < buffer.size() - 16; i++) {
        bool is_pattern = true;
        for (size_t j = 1; j < 16; j++) {
            if (buffer[i] != buffer[i + j]) {
                is_pattern = false;
                break;
            }
        }
        if (is_pattern) {
            return true;
        }
    }
    
    return false;
}

void MemoryMonitor::report_violation(AttackType type, uint64_t address, 
                                   const std::string& description, double confidence) {
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.violations_detected++;
    }
    
    log_message("WARNING", "記憶體違規檢測: " + description + 
                " (地址: " + format_address(address) + 
                ", 置信度: " + std::to_string(confidence) + ")");
    
    if (violation_callback_) {
        violation_callback_(type, address, description, confidence);
    }
}

void MemoryMonitor::log_message(const std::string& level, const std::string& message) {
    std::string timestamp = get_timestamp();
    std::string log_entry = timestamp + " [" + level + "] " + message + "\n";
    
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        if (log_file_.is_open()) {
            log_file_ << log_entry;
            log_file_.flush();
        }
    }
    
    std::cout << log_entry;
}

std::string MemoryMonitor::get_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string MemoryMonitor::format_address(uint64_t address) const {
    std::stringstream ss;
    ss << "0x" << std::hex << std::uppercase << address;
    return ss.str();
}

bool MemoryMonitor::is_executable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_EXECUTE) != 0;
    }
    return false;
}

bool MemoryMonitor::is_readable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_READONLY) != 0 || 
               (mbi.Protect & PAGE_READWRITE) != 0 ||
               (mbi.Protect & PAGE_EXECUTE_READ) != 0 ||
               (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
    }
    return false;
}

bool MemoryMonitor::is_writable_memory(LPVOID address, SIZE_T size) const {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi))) {
        return (mbi.Protect & PAGE_READWRITE) != 0 ||
               (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
    }
    return false;
}

bool MemoryMonitor::safe_read_memory(LPVOID address, SIZE_T size, std::vector<uint8_t>& buffer) const {
    buffer.resize(size);
    
    __try {
        memcpy(buffer.data(), address, size);
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace RealMemoryDetection 