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
static uint64_t g_buffer_overflow_attacks = 0;
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
    std::ofstream detection_log("detection_engine.log", std::ios::app);
    if (detection_log.is_open()) {
        detection_log << log_entry;
        detection_log.flush();
        detection_log.close();
    }
    
    std::cout << log_entry;
}

// 在 simulate_rop_attack() 中添加更明顯的ROP特徵
void simulate_rop_attack() {
    log_message("ATTACK", "Starting enhanced ROP attack simulation");
    
    // 創建一個大的ROP gadget區域
    LPVOID exec_mem = VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }
    
    uint8_t* ptr = (uint8_t*)exec_mem;
    int offset = 0;
    
    // 創建非常明顯的ROP gadget模式
    // 連續的 pop + ret 組合
    for (int i = 0; i < 100; i++) {
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
    }
    
    // 創建連續的ret指令（ret sled）
    for (int i = 0; i < 50; i++) {
        ptr[offset++] = 0xC3; // ret
    }
    
    // 確保記憶體真的被寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, offset);
    
    // 確保記憶體內容已經完全寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, offset);
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息，包括基址和實際特徵位址
    std::stringstream ss;
    ss << "Created ROP gadgets at base address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << " (size: " << std::dec << offset << " bytes, protection: PAGE_EXECUTE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 輸出實際的ROP特徵位址範圍
    std::stringstream ss2;
    ss2 << "ROP pattern addresses - Start: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss2 << ", End: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + offset);
    ss2 << ", PID: " << std::dec << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 輸出關鍵特徵位址（例如第一個pop+ret的位置）
    std::stringstream ss3;
    ss3 << "First ROP gadget at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss3 << " (pop eax; ret)";
    log_message("DEBUG", ss3.str().c_str());
    
    // 保持記憶體更長時間
    static std::vector<LPVOID> rop_blocks;
    rop_blocks.push_back(exec_mem);
    
    // 等待一段時間讓檢測引擎有機會掃描
    std::this_thread::sleep_for(std::chrono::seconds(5));
    
    g_rop_attacks++;
    g_total_attacks++;
}


// 緩衝區溢出攻擊模擬
void simulate_buffer_overflow() {
    log_message("ATTACK", "Starting buffer overflow attack simulation");
    
    // 創建一個小的緩衝區
    char buffer[16];
    char large_string[64];
    
    // 填充大字符串，超過緩衝區大小
    memset(large_string, 'A', sizeof(large_string) - 1);
    large_string[sizeof(large_string) - 1] = '\0';
    
    // 嘗試複製到大緩衝區（這會導致溢出）
    __try {
        strcpy(buffer, large_string); // 這會觸發緩衝區溢出
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        log_message("INFO", "Buffer overflow caught by exception handler");
    }
    
    g_buffer_overflow_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "Buffer overflow attack simulation completed");
}

// 堆損壞攻擊模擬
void simulate_heap_corruption() {
    log_message("ATTACK", "Starting heap corruption attack simulation");
    
    // 使用 VirtualAlloc 分配記憶體，更容易被檢測引擎發現
    LPVOID ptr = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) {
        log_message("ERROR", "Failed to allocate memory for heap corruption");
        return;
    }
    
    // 寫入常見的堆積破壞模式
    uint32_t* heap_ptr = (uint32_t*)ptr;
    for (int i = 0; i < 1024; i++) {
        heap_ptr[i] = 0xDEADBEEF; // 常見的堆積破壞模式
    }
    
    // 寫入更多破壞模式
    uint32_t* heap_ptr2 = (uint32_t*)((char*)ptr + 2048);
    for (int i = 0; i < 512; i++) {
        heap_ptr2[i] = 0xBAADF00D; // 另一個常見的堆積破壞模式
    }
    
    // 寫入額外的破壞模式
    uint32_t* heap_ptr3 = (uint32_t*)((char*)ptr + 3072);
    for (int i = 0; i < 256; i++) {
        heap_ptr3[i] = 0xFEEEFEEE; // 額外的破壞模式
    }
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created heap corruption patterns at address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ptr;
    ss << " (size: 4096 bytes, protection: PAGE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 額外輸出記憶體區域資訊，幫助檢測引擎識別
    std::stringstream ss2;
    ss2 << "Memory region details - Base: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ptr;
    ss2 << ", Size: 4096 bytes, PID: " << GetCurrentProcessId();
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

// Shellcode注入攻擊模擬
void simulate_shellcode_injection() {
    log_message("ATTACK", "Starting shellcode injection attack simulation");
    
    // 分配可執行記憶體
    LPVOID exec_mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }
    
    // 創建更明顯的shellcode（更長的NOP sled + 簡單的指令）
    uint8_t shellcode[512];
    
    // 更長的NOP sled (0x90) - 讓偵測更容易
    for (int i = 0; i < 256; i++) {
        shellcode[i] = 0x90; // NOP
    }
    
    // 添加一些int3 sled (0xCC) - 另一種常見的shellcode特徵
    for (int i = 256; i < 384; i++) {
        shellcode[i] = 0xCC; // int3
    }
    
    // 簡單的shellcode（返回0）
    shellcode[384] = 0x31; // xor eax, eax
    shellcode[385] = 0xC0; // xor eax, eax
    shellcode[386] = 0xC3; // ret
    
    // 將shellcode寫入可執行記憶體
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    
    // 確保記憶體內容已經完全寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, sizeof(shellcode));
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息，包括基址和實際特徵位址
    std::stringstream ss;
    ss << "Created shellcode at base address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << " (size: " << std::dec << sizeof(shellcode) << " bytes, protection: PAGE_EXECUTE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 輸出實際的shellcode特徵位址範圍
    std::stringstream ss2;
    ss2 << "Shellcode pattern addresses - Start: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss2 << ", End: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + sizeof(shellcode));
    ss2 << ", PID: " << std::dec << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 輸出關鍵特徵位址
    std::stringstream ss3;
    ss3 << "NOP sled starts at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss3 << " (256 bytes)";
    log_message("DEBUG", ss3.str().c_str());
    
    // 輸出實際shellcode位址
    std::stringstream ss4;
    ss4 << "Actual shellcode at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + 384);
    ss4 << " (xor eax, eax; ret)";
    log_message("DEBUG", ss4.str().c_str());
    
    // 保持記憶體分配，不立即釋放
    // 這樣檢測引擎有時間掃描到這些模式
    static std::vector<LPVOID> shellcode_blocks;
    shellcode_blocks.push_back(exec_mem);
    
    // 限制保持的記憶體塊數量，避免記憶體洩漏
    if (shellcode_blocks.size() > 5) {
        VirtualFree(shellcode_blocks[0], 0, MEM_RELEASE);
        shellcode_blocks.erase(shellcode_blocks.begin());
    }
    
    g_shellcode_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "Shellcode injection attack simulation completed");
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
        __try {
            memset(ptr, 0xAA, 1024); // 使用已釋放的記憶體
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            log_message("INFO", "Use-After-Free caught by exception handler");
        }
    }
    
    g_use_after_free_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "Use-After-Free attack simulation completed");
}

// 新增：ROP + Shellcode組合攻擊模擬
void simulate_rop_with_shellcode() {
    log_message("ATTACK", "Starting ROP + Shellcode combination attack simulation");
    
    // 創建一個大的可執行記憶體區域
    LPVOID exec_mem = VirtualAlloc(NULL, 16384, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }
    
    uint8_t* ptr = (uint8_t*)exec_mem;
    int offset = 0;
    
    // 第一部分：ROP gadgets
    // 連續的 pop + ret 組合
    for (int i = 0; i < 50; i++) {
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
    }
    
    // 第二部分：Shellcode payload
    // NOP sled
    for (int i = 0; i < 128; i++) {
        ptr[offset++] = 0x90; // NOP
    }
    
    // int3 sled
    for (int i = 0; i < 64; i++) {
        ptr[offset++] = 0xCC; // int3
    }
    
    // 簡單的shellcode（返回0）
    ptr[offset++] = 0x31; // xor eax, eax
    ptr[offset++] = 0xC0; // xor eax, eax
    ptr[offset++] = 0xC3; // ret
    
    // 保持記憶體分配
    static std::vector<LPVOID> rop_shellcode_blocks;
    rop_shellcode_blocks.push_back(exec_mem);
    
    if (rop_shellcode_blocks.size() > 3) {
        VirtualFree(rop_shellcode_blocks[0], 0, MEM_RELEASE);
        rop_shellcode_blocks.erase(rop_shellcode_blocks.begin());
    }
    
    g_rop_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;

    // 確保記憶體內容已經完全寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, offset);
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息，包括基址和實際特徵位址
    std::stringstream ss;
    ss << "Created ROP + Shellcode combination at base address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << " (size: " << std::dec << offset << " bytes, protection: PAGE_EXECUTE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 輸出實際的攻擊特徵位址範圍
    std::stringstream ss2;
    ss2 << "Attack pattern addresses - Start: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss2 << ", End: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + offset);
    ss2 << ", PID: " << std::dec << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 輸出關鍵特徵位址
    std::stringstream ss3;
    ss3 << "First ROP gadget at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss3 << " (pop eax; ret)";
    log_message("DEBUG", ss3.str().c_str());
    
    // 輸出shellcode起始位址
    std::stringstream ss4;
    ss4 << "Shellcode starts at: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << ((uintptr_t)exec_mem + 400); // 400 = 50*8 (ROP gadgets)
    ss4 << " (NOP sled)";
    log_message("DEBUG", ss4.str().c_str());
    
    log_message("SUCCESS", "ROP + Shellcode combination attack simulation completed");
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

// 新增：Buffer Overflow + Shellcode組合攻擊模擬
void simulate_buffer_overflow_with_shellcode() {
    log_message("ATTACK", "Starting Buffer Overflow + Shellcode combination attack simulation");
    
    // 分配可執行記憶體
    LPVOID exec_mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }
    
    uint8_t* ptr = (uint8_t*)exec_mem;
    
    // 第一部分：Buffer overflow pattern (大量'A'字符)
    for (int i = 0; i < 1024; i++) {
        ptr[i] = 'A';
    }
    
    // 第二部分：Shellcode payload
    // NOP sled
    for (int i = 1024; i < 1280; i++) {
        ptr[i] = 0x90; // NOP
    }
    
    // int3 sled
    for (int i = 1280; i < 1344; i++) {
        ptr[i] = 0xCC; // int3
    }
    
    // 簡單的shellcode
    ptr[1344] = 0x31; // xor eax, eax
    ptr[1345] = 0xC0; // xor eax, eax
    ptr[1346] = 0xC3; // ret
    
    // 確保記憶體內容已經完全寫入
    FlushInstructionCache(GetCurrentProcess(), exec_mem, 4096);
    
    // 等待一小段時間讓記憶體佈局穩定
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // 輸出詳細的調試信息
    std::stringstream ss;
    ss << "Created Buffer Overflow + Shellcode combination at address: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss << " (size: 4096 bytes, protection: PAGE_EXECUTE_READWRITE)";
    log_message("DEBUG", ss.str().c_str());
    
    // 額外輸出記憶體區域資訊，幫助檢測引擎識別
    std::stringstream ss2;
    ss2 << "Memory region details - Base: 0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(16) << exec_mem;
    ss2 << ", Size: 4096 bytes, PID: " << GetCurrentProcessId();
    log_message("INFO", ss2.str().c_str());
    
    // 保持記憶體分配
    static std::vector<LPVOID> buffer_shellcode_blocks;
    buffer_shellcode_blocks.push_back(exec_mem);
    
    if (buffer_shellcode_blocks.size() > 3) {
        VirtualFree(buffer_shellcode_blocks[0], 0, MEM_RELEASE);
        buffer_shellcode_blocks.erase(buffer_shellcode_blocks.begin());
    }
    
    g_buffer_overflow_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;
    
    log_message("SUCCESS", "Buffer Overflow + Shellcode combination attack simulation completed");
}

// 顯示狀態
void show_status() {
    std::cout << "\n=== Attack Simulator Status ===\n";
    std::cout << "Total attacks: " << g_total_attacks << "\n";
    std::cout << "ROP attacks: " << g_rop_attacks << "\n";
    std::cout << "Buffer overflow attacks: " << g_buffer_overflow_attacks << "\n";
    std::cout << "Heap corruption attacks: " << g_heap_corruption_attacks << "\n";
    std::cout << "Shellcode injection attacks: " << g_shellcode_attacks << "\n";
    std::cout << "Use-After-Free attacks: " << g_use_after_free_attacks << "\n";
    std::cout << "========================\n";
}

// 攻擊循環
void attack_loop() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 6); // 改為1-6，移除獨立shellcode
    
    int attack_count = 0;
    while (g_running) {
        int attack_type = dis(gen);
        
        switch (attack_type) {
            case 1:
                simulate_rop_attack();
                break;
            case 2:
                simulate_buffer_overflow();
                break;
            case 3:
                simulate_heap_corruption();
                break;
            case 4:
                simulate_use_after_free();
                break;
            case 5:
                simulate_rop_with_shellcode();
                break;
            case 6:
                simulate_heap_corruption_with_shellcode();
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
    __try {
        uint8_t* ptr = (uint8_t*)address;
        uint8_t test_byte = ptr[0]; // 嘗試讀取第一個字節
        test_byte = ptr[size-1];    // 嘗試讀取最後一個字節
        return true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
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
    std::cout << "Available attacks:" << std::endl;
    std::cout << "1. ROP Attack" << std::endl;
    std::cout << "2. Buffer Overflow Attack" << std::endl;
    std::cout << "3. Heap Corruption Attack" << std::endl;
    std::cout << "4. Use-After-Free Attack" << std::endl;
    std::cout << "5. ROP + Shellcode Combination" << std::endl;
    std::cout << "6. Heap Corruption + Shellcode Combination" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Enter attack number (0-6): ";
    
    // 初始化日誌檔案
    g_log_file.open("simple_attack_simulator.log", std::ios::app);
    
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
                simulate_rop_attack();
                break;
            case 2:
                simulate_buffer_overflow();
                break;
            case 3:
                simulate_heap_corruption();
                break;
            case 4:
                simulate_use_after_free();
                break;
            case 5:
                simulate_rop_with_shellcode();
                break;
            case 6:
                simulate_heap_corruption_with_shellcode();
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