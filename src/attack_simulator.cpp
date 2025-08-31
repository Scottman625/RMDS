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

// === Instrumentation 控制參數 ===
#define ASM_USE_RW_TO_RX_TRANSITION   1      // 1: 先 RW 後 RX
#define ASM_USE_DOUBLE_STAGE          1      // 1: 兩階段寫入 (加強 Write 次數)
#define ASM_WRITE_SLEEP_MS            20     // 寫後到 VirtualProtect 的延遲 (測 RW→RX Gap)
#define ASM_SECOND_STAGE_SLEEP_MS     40     // 第二階段與最終保護切換間延遲
#define ASM_PROTECT_EXEC_MODE         0      // 0: PAGE_EXECUTE_READ, 1: PAGE_EXECUTE_READWRITE
#define ASM_PAD_SIGNATURE             1
#define ASM_SIGNATURE_TEXT            "SIMROP"
#define ASM_LOG_ADDR_PREFIX           "[SIMADDR]"  // 日誌標記，檢測器可以 grep
#define ASM_SCATTER_SEGMENTS_MAX      8

// 統一列印 64-bit 地址
static inline std::string fmt_addr(const void* p) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setfill('0')
        << std::setw(16) << (uintptr_t)p;
    return oss.str();
}

static inline void sleep_ms(int ms){
    if(ms>0) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}



// 模擬器標記常量
constexpr DWORD SIMULATOR_MAGIC = 0x53494D55; // 'SIMU'

// 函數聲明
bool verify_memory_content(LPVOID address, size_t size);
std::string get_current_process_name();
void log_message(const char* level, const char* message);

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

// 封裝：分配 RW，第一階段寫入 → (可選第二階段) → 轉成可執行
struct RWXBlock {
    void* base = nullptr;
    size_t size = 0;
    bool executable = false;
};

bool allocate_rw_block(RWXBlock& blk, size_t sz) {
    blk.base = VirtualAlloc(nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    blk.size = sz;
    if(!blk.base) {
        log_message("ERROR", "VirtualAlloc RW 失敗");
        return false;
    }
    std::string m = std::string("Allocated RW block @ ")+fmt_addr(blk.base)+
        " size="+std::to_string(sz);
    log_message("DEBUG", m.c_str());
    return true;
}

bool write_stage(const RWXBlock& blk, const std::vector<uint8_t>& buf, size_t offset=0) {
    if(offset + buf.size() > blk.size) return false;
    SIZE_T written = 0;
    if(!WriteProcessMemory(GetCurrentProcess(),
        (uint8_t*)blk.base + offset, buf.data(), buf.size(), &written) || written != buf.size()) {
        log_message("ERROR", "WriteProcessMemory 失敗 (stage)");
        return false;
    }
    std::string m = std::string("WriteProcessMemory block=")+fmt_addr(blk.base)+
        " off="+std::to_string(offset)+" len="+std::to_string(buf.size());
    log_message("DEBUG", m.c_str());
    return true;
}

bool protect_exec(RWXBlock& blk) {
#if ASM_PROTECT_EXEC_MODE==0
    DWORD oldProt;
    if(!VirtualProtect(blk.base, blk.size, PAGE_EXECUTE_READ, &oldProt)) {
        log_message("ERROR", "VirtualProtect -> RX 失敗");
        return false;
    }
#else
    DWORD oldProt;
    if(!VirtualProtect(blk.base, blk.size, PAGE_EXECUTE_READWRITE, &oldProt)) {
        log_message("ERROR", "VirtualProtect -> RWX 失敗");
        return false;
    }
#endif
    FlushInstructionCache(GetCurrentProcess(), blk.base, blk.size);
    blk.executable = true;
    std::string m = std::string("VirtualProtect EXEC OK block=")+fmt_addr(blk.base);
    log_message("INFO", m.c_str());
    return true;
}

// 產生 Gadget / Shellcode 緩衝
std::vector<uint8_t> build_rop_block(int gadget_sets, int ret_sled, int complex_sets, bool add_shellcode) {
    std::vector<uint8_t> v;
    auto append = [&](std::initializer_list<uint8_t> l){ v.insert(v.end(), l); };

    // 基本 POP/RET Gadgets
    for(int i=0;i<gadget_sets;i++){
        append({0x58,0xC3}); // pop eax; ret
        append({0x5B,0xC3});
        append({0x59,0xC3});
        append({0x5A,0xC3});
        append({0x5E,0xC3});
        append({0x5F,0xC3});
    }
    // ret sled
    for(int i=0;i<ret_sled;i++) append({0xC3});
    // 複雜 gadgets
    for(int i=0;i<complex_sets;i++){
        append({0x94,0xC3});                      // xchg eax,esp;ret
        append({0x83,0xC4,0x04,0xC3});            // add esp,4;ret
        append({0xFF,0x10,0xC3});                 // call [eax];ret
        append({0x83,0xC0,0x04,0xC3});            // add eax,4;ret
        append({0x85,0xC0,0x75,0x02,0xC3});       // test eax,eax;jnz +2;ret
    }
    // 混合
    for(int i=0;i< (gadget_sets/2); i++){
        append({0x8B,0x04,0x24,0xC3});            // mov eax,[esp];ret
        append({0x50,0xC3});                      // push eax;ret
        append({0x58,0xC3});                      // pop eax;ret
        append({0x8D,0x44,0x24,0x04,0xC3});       // lea eax,[esp+4];ret
    }
    // 再來一些 ret
    for(int i=0;i< (ret_sled/2); i++) append({0xC3});

    if(add_shellcode){
        // NOP sled
        v.insert(v.end(), 128, 0x90);
        // int3 sled
        v.insert(v.end(), 64, 0xCC);
        // 小 shellcode
        append({0x31,0xC0,              // xor eax,eax
                0xBB,0x78,0x56,0x34,0x12, // mov ebx,12345678h
                0x01,0xD8,              // add eax,ebx
                0xC3});                 // ret
    }

#if ASM_PAD_SIGNATURE
    // 加簽名
    const char sig[] = ASM_SIGNATURE_TEXT;
    v.insert(v.end(), sig, sig + sizeof(sig)-1);
#endif
    return v;
}

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

// 統一的增強型ROP攻擊模擬器（整合了原來的兩個函數）
void simulate_rop_attack(bool include_shellcode = false) {
    log_message("ATTACK", include_shellcode ?
        "ROP + Shellcode (RW->RX Instrumented)" :
        "ROP (RW->RX Instrumented)");

    // 構建 Byte Buffer
    int gadget_sets = include_shellcode ? 15 : 25;
    int ret_sled = include_shellcode ? 8 : 15;
    int complex_sets = include_shellcode ? 8 : 12;

    auto buf_stage1 = build_rop_block(gadget_sets, ret_sled, complex_sets, include_shellcode);

    RWXBlock blk;
    if(!allocate_rw_block(blk, buf_stage1.size()+256)) return;

#if ASM_USE_DOUBLE_STAGE
    // 第一階段只寫前 60%
    size_t first_len = (size_t)(buf_stage1.size()*0.6);
    std::vector<uint8_t> part1(buf_stage1.begin(), buf_stage1.begin()+first_len);
    write_stage(blk, part1, 0);
    sleep_ms(ASM_WRITE_SLEEP_MS);

    // 第二階段寫剩餘 40%
    std::vector<uint8_t> part2(buf_stage1.begin()+first_len, buf_stage1.end());
    write_stage(blk, part2, first_len);
    sleep_ms(ASM_SECOND_STAGE_SLEEP_MS);
#else
    write_stage(blk, buf_stage1, 0);
    sleep_ms(ASM_WRITE_SLEEP_MS);
#endif

#if ASM_USE_RW_TO_RX_TRANSITION
    protect_exec(blk);
#else
    // 若不轉換，也可用 VirtualProtect 先變 RWX (若 alloc RWX)
#endif

    std::ostringstream oss;
    oss << ASM_LOG_ADDR_PREFIX << " ROP block base=" << fmt_addr(blk.base)
        << " size=" << blk.size
        << " gadgets=" << gadget_sets
        << " ret_sled=" << ret_sled
        << " complex_sets=" << complex_sets;
    log_message("INFO", oss.str().c_str());

    g_rop_attacks++;
    if(include_shellcode) g_shellcode_attacks++;
    g_total_attacks += include_shellcode ? 2 : 1;
}




// 堆損壞攻擊模擬
void simulate_heap_corruption() {
    log_message("ATTACK", "Heap Corruption (Instrumented)");

    size_t total = 32768;
    RWXBlock blk;
    if(!allocate_rw_block(blk, total)) return;

    auto pattern_write = [&](size_t off, uint32_t val){
        std::vector<uint32_t> tmp(1024, val);
        std::vector<uint8_t> bytes((uint8_t*)tmp.data(), (uint8_t*)tmp.data()+tmp.size()*4);
        write_stage(blk, bytes, off);
    };

    // 多次寫入不同模式
    pattern_write(0, 0xDEADBEEF);
    sleep_ms(ASM_WRITE_SLEEP_MS);
    pattern_write(4096, 0xBAADF00D);
    sleep_ms(ASM_WRITE_SLEEP_MS);
    pattern_write(8192, 0xFEEEFEEE);
    sleep_ms(ASM_WRITE_SLEEP_MS);
    pattern_write(12288, 0xCDCDCDCD);
    sleep_ms(ASM_WRITE_SLEEP_MS);
    pattern_write(16384, 0xABABABAB);

#if ASM_USE_RW_TO_RX_TRANSITION
    sleep_ms(ASM_SECOND_STAGE_SLEEP_MS);
    protect_exec(blk);
#endif

    std::ostringstream oss;
    oss << ASM_LOG_ADDR_PREFIX << " HEAP block=" << fmt_addr(blk.base)
        << " patterns=5";
    log_message("INFO", oss.str().c_str());

    g_heap_corruption_attacks++;
    g_total_attacks++;
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
    log_message("ATTACK", "Heap Corruption + Shellcode (Instrumented)");

    RWXBlock blk;
    if(!allocate_rw_block(blk, 8192)) return;

    // 第一階段：Heap corruption patterns
    std::vector<uint32_t> heap_pattern(1024, 0xDEADBEEF);
    std::vector<uint8_t> heap_bytes((uint8_t*)heap_pattern.data(), (uint8_t*)heap_pattern.data()+heap_pattern.size()*4);
    write_stage(blk, heap_bytes, 0);
    sleep_ms(ASM_WRITE_SLEEP_MS);

    // 第二階段：Shellcode payload
    auto shellcode = build_rop_block(2, 4, 2, true);
    write_stage(blk, shellcode, 4096);
    sleep_ms(ASM_SECOND_STAGE_SLEEP_MS);

#if ASM_USE_RW_TO_RX_TRANSITION
    protect_exec(blk);
#endif

    std::ostringstream oss;
    oss << ASM_LOG_ADDR_PREFIX << " HEAP+SHELL block=" << fmt_addr(blk.base)
        << " heap_patterns=1024 shellcode=" << shellcode.size();
    log_message("INFO", oss.str().c_str());

    g_heap_corruption_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;
}



// 新增：分散式ROP攻擊模擬器（更符合真實情況）
void simulate_scattered_rop_attack(bool include_shellcode=false) {
    log_message("ATTACK", include_shellcode ?
        "Scattered ROP + Shellcode (Instrumented)" :
        "Scattered ROP (Instrumented)");

    int segments = include_shellcode ? 6 : 5;
    if(segments > ASM_SCATTER_SEGMENTS_MAX) segments = ASM_SCATTER_SEGMENTS_MAX;

    std::vector<RWXBlock> blocks;
    for(int i=0;i<segments;i++){
        // 每段大小變化
        size_t seg_size = 2048 + i*512;
        auto payload = build_rop_block(4 + i, 4 + (i%3), 3, (include_shellcode && i==segments-1));
        RWXBlock blk;
        if(!allocate_rw_block(blk, (seg_size > payload.size()+64) ? seg_size : payload.size()+64)) continue;

        write_stage(blk, payload, 0);
        sleep_ms(ASM_WRITE_SLEEP_MS + (i*5));

        if(ASM_USE_RW_TO_RX_TRANSITION) protect_exec(blk);

        blocks.push_back(blk);

        std::ostringstream oss;
        oss << ASM_LOG_ADDR_PREFIX << " SCATTER seg#" << i+1
            << " base=" << fmt_addr(blk.base)
            << " payload=" << payload.size();
        log_message("DEBUG", oss.str().c_str());
    }

    g_rop_attacks++;
    if(include_shellcode) g_shellcode_attacks++;
    g_total_attacks += include_shellcode ? 2 : 1;

    std::ostringstream sum;
    sum << "Scattered segments=" << blocks.size();
    log_message("INFO", sum.str().c_str());
}

// 真實的 ROP + Shellcode 攻擊模擬（展示真實限制）
void simulate_realistic_rop_shellcode_attack() {
    log_message("ATTACK", "Realistic ROP + Shellcode (RW->RX Instrumented)");

    // 第一步：分配不可執行的記憶體（模擬真實環境）
    RWXBlock data_blk;
    if(!allocate_rw_block(data_blk, 4096)) return;

    // 第二步：在不可執行記憶體中放置 shellcode
    auto shellcode = build_rop_block(2, 4, 2, true);
    write_stage(data_blk, shellcode, 0);
    sleep_ms(ASM_WRITE_SLEEP_MS);

    // 第三步：分配可執行記憶體（模擬 ROP 鏈繞過 DEP）
    RWXBlock exec_blk;
    if(!allocate_rw_block(exec_blk, 4096)) return;

    // 第四步：創建 ROP 鏈來複製 shellcode（模擬真實攻擊）
    auto rop_chain = build_rop_block(8, 6, 4, false);
    write_stage(exec_blk, rop_chain, 0);
    sleep_ms(ASM_WRITE_SLEEP_MS);

    // 複製 shellcode 到可執行記憶體
    write_stage(exec_blk, shellcode, rop_chain.size());
    sleep_ms(ASM_SECOND_STAGE_SLEEP_MS);

#if ASM_USE_RW_TO_RX_TRANSITION
    protect_exec(exec_blk);
#endif

    std::ostringstream oss;
    oss << ASM_LOG_ADDR_PREFIX << " REALISTIC data=" << fmt_addr(data_blk.base)
        << " exec=" << fmt_addr(exec_blk.base)
        << " shellcode=" << shellcode.size()
        << " rop_chain=" << rop_chain.size();
    log_message("INFO", oss.str().c_str());

    g_rop_attacks++;
    g_shellcode_attacks++;
    g_total_attacks += 2;
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
    std::cout << "[Instrumented Mode] 所有攻擊將觸發 WriteProcessMemory + VirtualProtect 事件" << std::endl;
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