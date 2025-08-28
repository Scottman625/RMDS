#include <iostream>
#include <windows.h>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
#include <mutex>
#include <fcntl.h>
#include <io.h>
#include <conio.h>
#include <vector> // Added for corrupted_blocks
#include <cstring> // Added for memset
#include <cstdint> // Added for uintptr_t
#include <algorithm> // Added for std::accumulate
#include <numeric> // Added for std::accumulate

// 模擬器標記常量
constexpr DWORD SIMULATOR_MAGIC = 0x53494D55; // 'SIMU'

// 函數聲明
bool verify_memory_content(LPVOID address, size_t size);
std::string get_current_process_name();
void log_message(const char* level, const char* message);

// 動態標記註冊函數
void register_simulator_flag() {
    LPVOID flag_addr = VirtualAlloc(nullptr, 4, MEM_COMMIT, PAGE_READWRITE);
    if (flag_addr) {
        WriteProcessMemory(GetCurrentProcess(), flag_addr, &SIMULATOR_MAGIC, 4, nullptr);
        VirtualProtect(flag_addr, 4, PAGE_READONLY, nullptr);
        std::stringstream ss;
        ss << "Simulator flag registered at address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << (uintptr_t)flag_addr;
        std::string message = ss.str();
        log_message("DEBUG", message.c_str());
    } else {
        log_message("ERROR", "Failed to register simulator flag");
    }
}

// 全局變數
static bool g_running = false;
static std::ofstream g_log_file;
static std::mutex g_log_mutex;

// 攻擊統計
static uint64_t g_total_attacks = 0;
static uint64_t g_rop_attacks = 0;
static uint64_t g_heap_corruption_attacks = 0;
static uint64_t g_shellcode_attacks = 0;
static uint64_t g_use_after_free_attacks = 0;

// 日誌函數
void log_message(const char* level, const char* message) {
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

// 統一的增強型ROP攻擊模擬器（整合了原來的兩個函數）
void simulate_rop_attack(bool include_shellcode = false) {
    std::string attack_type = include_shellcode ? "ROP + Shellcode combination" : "ROP";
    std::string attack_msg = "Starting enhanced " + attack_type + " attack simulation";
    log_message("ATTACK", attack_msg.c_str());
    
    // 根據是否包含shellcode調整記憶體大小
    size_t mem_size = include_shellcode ? 32768 : 24576;
    LPVOID exec_mem = VirtualAlloc(NULL, mem_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }
    
    uint8_t* ptr = (uint8_t*)exec_mem;
    int offset = 0;
    
    // 第一階段：創建基礎ROP gadgets（更真實的數量）
    int gadget_count = include_shellcode ? 15 : 25;
    for (int i = 0; i < gadget_count; i++) {
        // pop eax; ret
        ptr[offset++] = 0x58;
        ptr[offset++] = 0xC3;
        
        // pop ebx; ret
        ptr[offset++] = 0x5B;
        ptr[offset++] = 0xC3;
        
        // pop ecx; ret
        ptr[offset++] = 0x59;
        ptr[offset++] = 0xC3;
        
        // pop edx; ret
        ptr[offset++] = 0x5A;
        ptr[offset++] = 0xC3;
        
        // pop esi; ret
        ptr[offset++] = 0x5E;
        ptr[offset++] = 0xC3;
        
        // pop edi; ret
        ptr[offset++] = 0x5F;
        ptr[offset++] = 0xC3;
    }
    
    // 第二階段：創建連續的ret指令（ret sled）
    int ret_sled_count = include_shellcode ? 8 : 15;
    for (int i = 0; i < ret_sled_count; i++) {
        ptr[offset++] = 0xC3; // ret
    }
    
    // 第三階段：創建複雜的ROP鏈模式
    int complex_gadget_count = include_shellcode ? 8 : 12;
    for (int i = 0; i < complex_gadget_count; i++) {
        // 模擬 stack pivot gadgets
        // xchg eax, esp; ret
        ptr[offset++] = 0x94;
        ptr[offset++] = 0xC3;
        
        // add esp, 4; ret
        ptr[offset++] = 0x83;
        ptr[offset++] = 0xC4;
        ptr[offset++] = 0x04;
        ptr[offset++] = 0xC3;
        
        // 模擬函數調用gadgets
        // call [eax]
        ptr[offset++] = 0xFF;
        ptr[offset++] = 0x10;
        ptr[offset++] = 0xC3;
        
        // 模擬算術運算gadgets
        // add eax, 4; ret
        ptr[offset++] = 0x83;
        ptr[offset++] = 0xC0;
        ptr[offset++] = 0x04;
        ptr[offset++] = 0xC3;
        
        // 模擬條件跳轉gadgets
        // test eax, eax; jnz +2; ret
        ptr[offset++] = 0x85;
        ptr[offset++] = 0xC0;
        ptr[offset++] = 0x75;
        ptr[offset++] = 0x02;
        ptr[offset++] = 0xC3;
    }
    
    // 第四階段：創建高密度的RET指令區域（模擬ROP鏈的核心）
    int high_density_ret_count = include_shellcode ? 12 : 20;
    for (int i = 0; i < high_density_ret_count; i++) {
        ptr[offset++] = 0xC3; // ret
    }
    
    // 第五階段：創建混合的gadget模式（更真實的ROP鏈）
    int mixed_gadget_count = include_shellcode ? 10 : 18;
    for (int i = 0; i < mixed_gadget_count; i++) {
        // 模擬 mov gadgets
        // mov eax, [esp]; ret
        ptr[offset++] = 0x8B;
        ptr[offset++] = 0x04;
        ptr[offset++] = 0x24;
        ptr[offset++] = 0xC3;
        
        // 模擬 push gadgets
        // push eax; ret
        ptr[offset++] = 0x50;
        ptr[offset++] = 0xC3;
        
        // 模擬 pop gadgets
        // pop eax; ret
        ptr[offset++] = 0x58;
        ptr[offset++] = 0xC3;
        
        // 模擬 lea gadgets
        // lea eax, [esp+4]; ret
        ptr[offset++] = 0x8D;
        ptr[offset++] = 0x44;
        ptr[offset++] = 0x24;
        ptr[offset++] = 0x04;
        ptr[offset++] = 0xC3;
    }
    
    // 第六階段：創建最終的連續RET序列（確保檢測觸發）
    int final_ret_count = include_shellcode ? 8 : 15;
    for (int i = 0; i < final_ret_count; i++) {
        ptr[offset++] = 0xC3; // ret
    }
    
    // 如果包含shellcode，添加shellcode payload
    if (include_shellcode) {
        // NOP sled
        for (int i = 0; i < 256; i++) {
            ptr[offset++] = 0x90; // NOP
        }
        
        // int3 sled
        for (int i = 0; i < 128; i++) {
            ptr[offset++] = 0xCC; // int3
        }
        
        // 更複雜的shellcode
        // xor eax, eax
        ptr[offset++] = 0x31;
        ptr[offset++] = 0xC0;
        
        // mov ebx, 0x12345678
        ptr[offset++] = 0xBB;
        ptr[offset++] = 0x78;
        ptr[offset++] = 0x56;
        ptr[offset++] = 0x34;
        ptr[offset++] = 0x12;
        
        // add eax, ebx
        ptr[offset++] = 0x01;
        ptr[offset++] = 0xD8;
        
        // ret
        ptr[offset++] = 0xC3;
    }
    
    // 保持記憶體分配
    static std::vector<LPVOID> rop_blocks;
    rop_blocks.push_back(exec_mem);
    
    if (rop_blocks.size() > 3) {
        VirtualFree(rop_blocks[0], 0, MEM_RELEASE);
        rop_blocks.erase(rop_blocks.begin());
    }
    
    g_rop_attacks++;
    if (include_shellcode) {
        g_shellcode_attacks++;
        g_total_attacks += 2;
    } else {
        g_total_attacks++;
    }

    // 確保記憶體內容已經完全寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, offset);
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created enhanced " << attack_type << " at base address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << " (size: " << std::dec << offset << " bytes, protection: PAGE_EXECUTE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 輸出實際的攻擊特徵位址範圍
    std::stringstream ss2;
    ss2 << "Enhanced attack pattern addresses - Start: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss2 << ", End: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + offset);
    ss2 << ", PID: " << std::dec << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 輸出關鍵特徵位址
    std::stringstream ss3;
    ss3 << "First ROP gadget at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss3 << " (pop eax; ret)";
    log_message("DEBUG", ss3.str().c_str());
    
    if (include_shellcode) {
        // 輸出shellcode起始位址
        int shellcode_offset = gadget_count * 12 + ret_sled_count + complex_gadget_count * 12 + high_density_ret_count + mixed_gadget_count * 12 + final_ret_count;
        std::stringstream ss4;
        ss4 << "Shellcode starts at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + shellcode_offset);
        ss4 << " (NOP sled)";
        log_message("DEBUG", ss4.str().c_str());
    }
    
    // 輸出統計信息
    std::stringstream ss5;
    ss5 << "Enhanced " << attack_type << " statistics - Total gadgets: " << std::dec << (gadget_count * 6 + complex_gadget_count * 5 + mixed_gadget_count * 4);
    ss5 << ", Consecutive RETs: " << std::dec << (ret_sled_count + high_density_ret_count + final_ret_count);
    if (include_shellcode) {
        ss5 << ", Shellcode size: " << std::dec << (256 + 128 + 8);
    }
    ss5 << ", Total size: " << std::dec << offset << " bytes";
    log_message("INFO", ss5.str().c_str());
    
    std::string success_msg = "Enhanced " + attack_type + " attack simulation completed";
    log_message("SUCCESS", success_msg.c_str());
}




// 堆損壞攻擊模擬
void simulate_heap_corruption() {
    log_message("ATTACK", "Starting heap corruption attack simulation");
    
    // 使用 VirtualAlloc 分配更大的記憶體，更容易被檢測引擎發現
    LPVOID ptr = VirtualAlloc(NULL, 32768, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        log_message("ERROR", "Failed to allocate memory for heap corruption");
        return;
    }
    
    // 寫入高密度的堆積破壞模式，確保達到檢測閾值
    uint32_t* heap_ptr = (uint32_t*)ptr;
    
    // 第一部分：在4KB區域內高密度寫入 0xDEADBEEF 模式
    for (int i = 0; i < 1024; i++) {
        heap_ptr[i] = 0xDEADBEEF; // 常見的堆積破壞模式
    }
    
    // 第二部分：在4KB區域內高密度寫入 0xBAADF00D 模式
    uint32_t* heap_ptr2 = (uint32_t*)((char*)ptr + 4096);
    for (int i = 0; i < 1024; i++) {
        heap_ptr2[i] = 0xBAADF00D; // 另一個常見的堆積破壞模式
    }
    
    // 第三部分：在4KB區域內高密度寫入 0xFEEEFEEE 模式
    uint32_t* heap_ptr3 = (uint32_t*)((char*)ptr + 8192);
    for (int i = 0; i < 1024; i++) {
        heap_ptr3[i] = 0xFEEEFEEE; // 額外的破壞模式
    }
    
    // 第四部分：在4KB區域內高密度寫入 0xCDCDCDCD 模式
    uint32_t* heap_ptr4 = (uint32_t*)((char*)ptr + 12288);
    for (int i = 0; i < 1024; i++) {
        heap_ptr4[i] = 0xCDCDCDCD; // 額外的破壞模式
    }
    
    // 第五部分：在4KB區域內高密度寫入 0xABABABAB 模式
    uint32_t* heap_ptr5 = (uint32_t*)((char*)ptr + 16384);
    for (int i = 0; i < 1024; i++) {
        heap_ptr5[i] = 0xABABABAB; // 額外的破壞模式
    }
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created heap corruption patterns at address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ptr;
    ss << " (size: 32768 bytes, protection: PAGE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 額外輸出記憶體區域資訊，幫助檢測引擎識別
    std::stringstream ss2;
    ss2 << "Memory region details - Base: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ptr;
    ss2 << ", Size: 32768 bytes, PID: " << GetCurrentProcessId();
    ss2 << ", Total corruption patterns: 5120 (5 regions x 1024 patterns each)";
    log_message("INFO", ss2.str().c_str());
    
    // 保持記憶體分配，不立即釋放
    // 這樣檢測引擎有時間掃描到這些模式
    static std::vector<LPVOID> corrupted_blocks;
    corrupted_blocks.push_back(ptr);
    
    // 限制保持的記憶體塊數量，避免記憶體洩漏
    if (corrupted_blocks.size() > 10) {
        VirtualFree(corrupted_blocks[0], 0, MEM_RELEASE);
        corrupted_blocks.erase(corrupted_blocks.begin());
    }
    
    g_heap_corruption_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "Heap corruption attack simulation completed");
}



// Use-After-Free攻擊模擬
void simulate_use_after_free() {
    log_message("ATTACK", "Starting Use-After-Free attack simulation");
    
    // 分配記憶體
    void* ptr = malloc(1024);
    if (ptr) {
        // 釋放記憶體
        free(ptr);
        
        // 嘗試使用已釋放的記憶體
        try {
            memset(ptr, 0xAA, 1024); // 使用已釋放的記憶體
        }
        catch (...) {
            log_message("INFO", "Use-After-Free caught by exception handler");
        }
    }
    
    g_use_after_free_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "Use-After-Free attack simulation completed");
}

// 新增：Heap Corruption + Shellcode組合攻擊模擬
void simulate_heap_corruption_with_shellcode() {
    log_message("ATTACK", "Starting Heap Corruption + Shellcode combination attack simulation");
    
    // 分配記憶體
    LPVOID heap_mem = VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!heap_mem) {
        log_message("ERROR", "Failed to allocate memory for heap corruption");
        return;
    }
    
    uint32_t* heap_ptr = (uint32_t*)heap_mem;
    
    // 第一部分：Heap corruption patterns
    for (int i = 0; i < 1024; i++) {
        heap_ptr[i] = 0xDEADBEEF; // 常見的堆積破壞模式
    }
    
    // 第二部分：Shellcode payload
    uint8_t* shellcode_ptr = (uint8_t*)(heap_ptr + 1024);
    
    // NOP sled
    for (int i = 0; i < 64; i++) {
        shellcode_ptr[i] = 0x90; // NOP
    }
    
    // int3 sled
    for (int i = 64; i < 96; i++) {
        shellcode_ptr[i] = 0xCC; // int3
    }
    
    // 簡單的shellcode
    shellcode_ptr[96] = 0x31; // xor eax, eax
    shellcode_ptr[97] = 0xC0; // xor eax, eax
    shellcode_ptr[98] = 0xC3; // ret
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created Heap Corruption + Shellcode combination at address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << heap_mem;
    ss << " (size: 8192 bytes, protection: PAGE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 額外輸出記憶體區域資訊，幫助檢測引擎識別
    std::stringstream ss2;
    ss2 << "Memory region details - Base: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << heap_mem;
    ss2 << ", Size: 8192 bytes, PID: " << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 保持記憶體分配
    static std::vector<LPVOID> heap_shellcode_blocks;
    heap_shellcode_blocks.push_back(heap_mem);
    
    if (heap_shellcode_blocks.size() > 3) {
        VirtualFree(heap_shellcode_blocks[0], 0, MEM_RELEASE);
        heap_shellcode_blocks.erase(heap_shellcode_blocks.begin());
    }
    
    g_heap_corruption_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;
    
    log_message("SUCCESS", "Heap Corruption + Shellcode combination attack simulation completed");
}



// 新增：分散式ROP攻擊模擬器（更符合真實情況）
void simulate_scattered_rop_attack(bool include_shellcode = false) {
    std::string attack_type = include_shellcode ? "Scattered ROP + Shellcode" : "Scattered ROP";
    std::string attack_msg = "Starting realistic " + attack_type + " attack simulation";
    log_message("ATTACK", attack_msg.c_str());
    
    // 創建多個分散的記憶體區域來模擬真實的ROP攻擊
    std::vector<LPVOID> gadget_regions;
    std::vector<size_t> region_sizes;
    
    // 第一區域：基礎POP gadgets
    LPVOID pop_region = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pop_region) {
        gadget_regions.push_back(pop_region);
        region_sizes.push_back(4096);
        
        uint8_t* ptr = (uint8_t*)pop_region;
        int offset = 0;
        
        // 創建POP gadgets，分散在不同位置
        for (int i = 0; i < 50; i++) {
            // 在隨機位置插入POP gadgets
            int pos = (i * 64) % 4000; // 分散分佈
            if (pos + 2 < 4096) {
                ptr[pos] = 0x58 + (i % 8); // pop r32
                ptr[pos + 1] = 0xC3; // ret
            }
        }
        
        FlushInstructionCache(GetCurrentProcess(), pop_region, 4096);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // 第二區域：Stack pivot gadgets
    LPVOID pivot_region = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pivot_region) {
        gadget_regions.push_back(pivot_region);
        region_sizes.push_back(2048);
        
        uint8_t* ptr = (uint8_t*)pivot_region;
        
        // xchg eax, esp; ret
        ptr[0] = 0x94;
        ptr[1] = 0xC3;
        
        // add esp, 4; ret
        ptr[64] = 0x83;
        ptr[65] = 0xC4;
        ptr[66] = 0x04;
        ptr[67] = 0xC3;
        
        // add esp, 8; ret
        ptr[128] = 0x83;
        ptr[129] = 0xC4;
        ptr[130] = 0x08;
        ptr[131] = 0xC3;
        
        FlushInstructionCache(GetCurrentProcess(), pivot_region, 2048);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // 第三區域：算術運算gadgets
    LPVOID arithmetic_region = VirtualAlloc(NULL, 3072, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (arithmetic_region) {
        gadget_regions.push_back(arithmetic_region);
        region_sizes.push_back(3072);
        
        uint8_t* ptr = (uint8_t*)arithmetic_region;
        
        // add eax, 4; ret
        ptr[0] = 0x83;
        ptr[1] = 0xC0;
        ptr[2] = 0x04;
        ptr[3] = 0xC3;
        
        // add ebx, 4; ret
        ptr[64] = 0x83;
        ptr[65] = 0xC3;
        ptr[66] = 0x04;
        ptr[67] = 0xC3;
        
        // sub eax, 4; ret
        ptr[128] = 0x83;
        ptr[129] = 0xE8;
        ptr[130] = 0x04;
        ptr[131] = 0xC3;
        
        FlushInstructionCache(GetCurrentProcess(), arithmetic_region, 3072);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // 第四區域：MOV gadgets
    LPVOID mov_region = VirtualAlloc(NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mov_region) {
        gadget_regions.push_back(mov_region);
        region_sizes.push_back(2048);
        
        uint8_t* ptr = (uint8_t*)mov_region;
        
        // mov eax, [esp]; ret
        ptr[0] = 0x8B;
        ptr[1] = 0x04;
        ptr[2] = 0x24;
        ptr[3] = 0xC3;
        
        // mov ebx, [esp+4]; ret
        ptr[64] = 0x8B;
        ptr[65] = 0x5C;
        ptr[66] = 0x24;
        ptr[67] = 0x04;
        ptr[68] = 0xC3;
        
        FlushInstructionCache(GetCurrentProcess(), mov_region, 2048);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // 第五區域：RET sled（用於ROP鏈跳轉）
    LPVOID ret_sled_region = VirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (ret_sled_region) {
        gadget_regions.push_back(ret_sled_region);
        region_sizes.push_back(1024);
        
        uint8_t* ptr = (uint8_t*)ret_sled_region;
        
        // 創建RET sled
        for (int i = 0; i < 256; i++) {
            ptr[i] = 0xC3; // ret
        }
        
        FlushInstructionCache(GetCurrentProcess(), ret_sled_region, 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    // 如果包含shellcode，創建shellcode區域
    if (include_shellcode) {
        LPVOID shellcode_region = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (shellcode_region) {
            gadget_regions.push_back(shellcode_region);
            region_sizes.push_back(4096);
            
            uint8_t* ptr = (uint8_t*)shellcode_region;
            int offset = 0;
            
            // NOP sled
            for (int i = 0; i < 512; i++) {
                ptr[offset++] = 0x90; // NOP
            }
            
            // 簡單的shellcode
            // xor eax, eax
            ptr[offset++] = 0x31;
            ptr[offset++] = 0xC0;
            
            // mov ebx, 0x12345678
            ptr[offset++] = 0xBB;
            ptr[offset++] = 0x78;
            ptr[offset++] = 0x56;
            ptr[offset++] = 0x34;
            ptr[offset++] = 0x12;
            
            // add eax, ebx
            ptr[offset++] = 0x01;
            ptr[offset++] = 0xD8;
            
            // ret
            ptr[offset++] = 0xC3;
            
            FlushInstructionCache(GetCurrentProcess(), shellcode_region, 4096);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    // 保持記憶體分配
    static std::vector<LPVOID> scattered_rop_blocks;
    for (auto region : gadget_regions) {
        scattered_rop_blocks.push_back(region);
    }
    
    if (scattered_rop_blocks.size() > 10) {
        for (int i = 0; i < 5; i++) {
            VirtualFree(scattered_rop_blocks[0], 0, MEM_RELEASE);
            scattered_rop_blocks.erase(scattered_rop_blocks.begin());
        }
    }
    
    g_rop_attacks++;
    if (include_shellcode) {
        g_shellcode_attacks++;
        g_total_attacks += 2;
    } else {
        g_total_attacks++;
    }
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created realistic " << attack_type << " with " << gadget_regions.size() << " scattered regions";
    log_message("DEBUG", ss.str().c_str());
    
    // 輸出每個區域的地址
    for (size_t i = 0; i < gadget_regions.size(); i++) {
        std::stringstream ss2;
        ss2 << "Region " << (i + 1) << ": Base=0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << gadget_regions[i];
        ss2 << ", Size=" << std::dec << region_sizes[i] << " bytes";
        log_message("DEBUG", ss2.str().c_str());
    }
    
    // 輸出統計信息
    std::stringstream ss3;
    ss3 << "Scattered ROP statistics - Total regions: " << std::dec << gadget_regions.size();
    ss3 << ", Total size: " << std::dec << std::accumulate(region_sizes.begin(), region_sizes.end(), 0) << " bytes";
    if (include_shellcode) {
        ss3 << ", Includes shellcode payload";
    }
    log_message("INFO", ss3.str().c_str());
    
    std::string success_msg = "Realistic " + attack_type + " attack simulation completed";
    log_message("SUCCESS", success_msg.c_str());
}

// 真實的 ROP + Shellcode 攻擊模擬（展示真實限制）
void simulate_realistic_rop_shellcode_attack() {
    log_message("ATTACK", "Starting realistic ROP + Shellcode attack simulation");
    
    // 第一步：分配不可執行的記憶體（模擬真實環境）
    LPVOID data_mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data_mem) {
        log_message("ERROR", "Failed to allocate data memory");
        return;
    }
    
    // 第二步：在不可執行記憶體中放置 shellcode
    uint8_t* shellcode_ptr = (uint8_t*)data_mem;
    int shellcode_offset = 0;
    
    // 創建 shellcode payload
    // xor eax, eax
    shellcode_ptr[shellcode_offset++] = 0x31;
    shellcode_ptr[shellcode_offset++] = 0xC0;
    
    // mov ebx, 0x12345678
    shellcode_ptr[shellcode_offset++] = 0xBB;
    shellcode_ptr[shellcode_offset++] = 0x78;
    shellcode_ptr[shellcode_offset++] = 0x56;
    shellcode_ptr[shellcode_offset++] = 0x34;
    shellcode_ptr[shellcode_offset++] = 0x12;
    
    // add eax, ebx
    shellcode_ptr[shellcode_offset++] = 0x01;
    shellcode_ptr[shellcode_offset++] = 0xD8;
    
    // ret
    shellcode_ptr[shellcode_offset++] = 0xC3;
    
    // 第三步：分配可執行記憶體（模擬 ROP 鏈繞過 DEP）
    LPVOID exec_mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        VirtualFree(data_mem, 0, MEM_RELEASE);
        return;
    }
    
    // 第四步：創建 ROP 鏈來複製 shellcode（模擬真實攻擊）
    uint8_t* rop_ptr = (uint8_t*)exec_mem;
    int rop_offset = 0;
    
    // 模擬 ROP 鏈：複製 shellcode 到可執行記憶體
    // 這裡簡化為直接複製，真實環境需要複雜的 ROP gadgets
    
    // 複製 shellcode
    memcpy(rop_ptr, shellcode_ptr, shellcode_offset);
    rop_offset = shellcode_offset;
    
    // 添加一些 ROP gadgets 來模擬真實攻擊
    for (int i = 0; i < 10; i++) {
        // pop eax; ret
        rop_ptr[rop_offset++] = 0x58;
        rop_ptr[rop_offset++] = 0xC3;
        
        // pop ebx; ret
        rop_ptr[rop_offset++] = 0x5B;
        rop_ptr[rop_offset++] = 0xC3;
        
        // ret
        rop_ptr[rop_offset++] = 0xC3;
    }
    
    // 等待記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細信息
    std::stringstream ss;
    ss << "Realistic ROP + Shellcode attack created:";
    ss << "\n  - Data memory (non-executable): 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << data_mem;
    ss << "\n  - Executable memory: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << "\n  - Shellcode size: " << std::dec << shellcode_offset << " bytes";
    ss << "\n  - Total ROP chain size: " << std::dec << rop_offset << " bytes";
    log_message("DEBUG", ss.str().c_str());
    
    // 保持記憶體分配
    static std::vector<LPVOID> realistic_blocks;
    realistic_blocks.push_back(data_mem);
    realistic_blocks.push_back(exec_mem);
    
    if (realistic_blocks.size() > 6) {
        VirtualFree(realistic_blocks[0], 0, MEM_RELEASE);
        realistic_blocks.erase(realistic_blocks.begin());
    }
    
    g_rop_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;
    
    log_message("SUCCESS", "Realistic ROP + Shellcode attack simulation completed");
}

// 顯示狀態
void show_status() {
    std::cout << "\n=== Attack Simulator Status ===\n";
    std::cout << "Total attacks: " << g_total_attacks << "\n";
    std::cout << "ROP attacks: " << g_rop_attacks << "\n";
    std::cout << "Heap corruption attacks: " << g_heap_corruption_attacks << "\n";
    std::cout << "Shellcode injection attacks: " << g_shellcode_attacks << "\n";
    std::cout << "Use-After-Free attacks: " << g_use_after_free_attacks << "\n";
    std::cout << "========================\n";
}

// 攻擊循環
void attack_loop() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 6); // 改為1-6，保留現實攻擊類型
    
    int attack_count = 0;
    while (g_running) {
        int attack_type = dis(gen);
        
        switch (attack_type) {
            case 1:
                simulate_heap_corruption();
                break;
            case 2:
                simulate_use_after_free();
                break;
            case 3:
                simulate_rop_attack(true); // ROP + Shellcode Combination
                break;
            case 4:
                simulate_heap_corruption_with_shellcode();
                break;
            case 5:
                simulate_scattered_rop_attack(); // Scattered ROP Attack (Realistic)
                break;
            case 6:
                simulate_realistic_rop_shellcode_attack(); // Realistic ROP + Shellcode (DEP Bypass)
                break;
        }
        
        attack_count++;
        
        // 每10次攻擊顯示一次狀態
        if (attack_count % 10 == 0) {
            show_status();
        }
        
        // 進一步縮短延遲，更頻繁地執行攻擊
        std::uniform_int_distribution<> delay_dis(200, 1000);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_dis(gen)));
    }
}

// 驗證記憶體內容
bool verify_memory_content(LPVOID address, size_t size) {
    try {
        uint8_t* ptr = (uint8_t*)address;
        uint8_t test_byte = ptr[0]; // 嘗試讀取第一個字節
        test_byte = ptr[size-1];    // 嘗試讀取最後一個字節
        return true;
    }
    catch (...) {
        return false;
    }
}

// 獲取當前進程名稱
std::string get_current_process_name() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string full_path = buffer;
    size_t pos = full_path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return full_path.substr(pos + 1);
    }
    return full_path;
}

// 主函數
int main() {
    std::cout << "=== Memory Attack Simulator ===" << std::endl;
    // 顯示當前進程名稱
    std::string process_name = get_current_process_name();
    std::cout << "Process name: " << process_name << std::endl;
    std::cout << "Process ID: " << GetCurrentProcessId() << std::endl;
    std::cout << "Available attacks (Realistic):" << std::endl;
    std::cout << "1. Heap Corruption Attack" << std::endl;
    std::cout << "2. Use-After-Free Attack" << std::endl;
    std::cout << "3. ROP + Shellcode Combination" << std::endl;
    std::cout << "4. Heap Corruption + Shellcode Combination" << std::endl;
    std::cout << "5. Scattered ROP Attack (Realistic)" << std::endl;
    std::cout << "6. Realistic ROP + Shellcode (DEP Bypass)" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Enter attack number (0-6): ";
    
    // 確保 logs 目錄存在
    CreateDirectoryA("logs", NULL);
    
    // 初始化日誌檔案
    g_log_file.open("logs/simple_attack_simulator.log", std::ios::app);
    
    // 註冊模擬器標記
    register_simulator_flag();

    int choice;
    while (true) {
        std::cout << "\nEnter attack number (0-6): ";
        std::cin >> choice;
        
        switch (choice) {
            case 0:
                std::cout << "Exiting attack simulator..." << std::endl;
                if (g_log_file.is_open()) {
                    g_log_file.close();
                }
                return 0;
            case 1:
                simulate_heap_corruption();
                break;
            case 2:
                simulate_use_after_free();
                break;
            case 3:
                simulate_rop_attack(true); // ROP + Shellcode Combination
                break;
            case 4:
                simulate_heap_corruption_with_shellcode();
                break;
            case 5:
                simulate_scattered_rop_attack(); // Scattered ROP Attack (Realistic)
                break;
            case 6:
                simulate_realistic_rop_shellcode_attack(); // Realistic ROP + Shellcode (DEP Bypass)
                break;
            default:
                std::cout << "Invalid choice. Please enter 0-6." << std::endl;
                break;
        }
        
        // 顯示當前狀態
        show_status();
    }
    
    return 0;
} 