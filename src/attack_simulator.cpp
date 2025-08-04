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

// 函數聲明
bool verify_memory_content(LPVOID address, size_t size);
std::string get_current_process_name();

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
    
    if (g_log_file.is_open()) {
        g_log_file << log_entry;
        g_log_file.flush();
    }
    
    std::cout << log_entry;
}

// ROP攻擊模擬
void simulate_rop_attack() {
    log_message("ATTACK", "Starting ROP attack simulation");
    
    // 分配更大的可執行記憶體
    LPVOID exec_mem = VirtualAlloc(NULL, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        log_message("ERROR", "Failed to allocate executable memory");
        return;
    }

    // 記錄分配的地址
    std::stringstream ss;
    ss << "Allocated executable memory at address: 0x" << std::hex << exec_mem;
    log_message("DEBUG", ss.str().c_str());
    
    uint8_t* chain_ptr = (uint8_t*)exec_mem;
    
    // 創建更多的 ROP gadgets
    int gadgets_written = 0;
    for (int i = 0; i < 100; i++) {
        // pop + ret 組合
        chain_ptr[i * 8] = 0x5B;     // pop ebx
        chain_ptr[i * 8 + 1] = 0xC3; // ret
        chain_ptr[i * 8 + 2] = 0x5A; // pop edx
        chain_ptr[i * 8 + 3] = 0xC3; // ret
        chain_ptr[i * 8 + 4] = 0x59; // pop ecx
        chain_ptr[i * 8 + 5] = 0xC3; // ret
        chain_ptr[i * 8 + 6] = 0x58; // pop eax
        chain_ptr[i * 8 + 7] = 0xC3; // ret
    }

    // 驗證寫入的內容
    int ret_count = 0;
    for (int i = 0; i < 800; i++) {
        if (chain_ptr[i] == 0xC3) {
            ret_count++;
        }
    }

    ss.str("");
    ss << "Written " << gadgets_written << " gadgets with " << ret_count << " ret instructions";
    log_message("DEBUG", ss.str().c_str());
    
    // 創建一個假的堆疊，包含指向我們gadgets的地址
    uint64_t fake_stack[10];
    fake_stack[0] = (uint64_t)chain_ptr;        // 指向第一個gadget
    fake_stack[1] = (uint64_t)(chain_ptr + 8);  // 指向第二個gadget
    fake_stack[2] = (uint64_t)(chain_ptr + 16); // 指向第三個gadget
    fake_stack[3] = 0x4141414141414141;         // 假的返回地址
    fake_stack[4] = 0x4242424242424242;         // 假的返回地址
    
    // 將假的堆疊寫入記憶體
    memcpy(chain_ptr + 800, fake_stack, sizeof(fake_stack));
    
    // 保持記憶體分配，不立即釋放
    // 這樣檢測引擎有時間掃描到這些模式
    static std::vector<LPVOID> rop_blocks;
    rop_blocks.push_back(exec_mem);

    // 驗證記憶體是否可訪問
    if (verify_memory_content(exec_mem, 8192)) {
        log_message("DEBUG", "Memory content verified - accessible");
    } else {
        log_message("ERROR", "Memory content NOT accessible!");
    }

    ss.str("");
    ss << "Current ROP blocks in memory: " << rop_blocks.size();
    log_message("DEBUG", ss.str().c_str());
    
    // 限制保持的記憶體塊數量，避免記憶體洩漏
    if (rop_blocks.size() > 5) {
        VirtualFree(rop_blocks[0], 0, MEM_RELEASE);
        rop_blocks.erase(rop_blocks.begin());
    }
    
    g_rop_attacks++;
    g_total_attacks++;
    
    log_message("SUCCESS", "ROP attack simulation completed");
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
    
    // 分配記憶體並寫入破壞模式
    void* ptr = malloc(1024);
    if (!ptr) {
        log_message("ERROR", "Failed to allocate memory for heap corruption");
        return;
    }
    
    // 寫入常見的堆積破壞模式
    uint32_t* heap_ptr = (uint32_t*)ptr;
    for (int i = 0; i < 256; i++) {
        heap_ptr[i] = 0xDEADBEEF; // 常見的堆積破壞模式
    }
    
    // 寫入更多破壞模式
    uint32_t* heap_ptr2 = (uint32_t*)((char*)ptr + 512);
    for (int i = 0; i < 128; i++) {
        heap_ptr2[i] = 0xBAADF00D; // 另一個常見的堆積破壞模式
    }
    
    // 保持記憶體分配，不立即釋放
    // 這樣檢測引擎有時間掃描到這些模式
    static std::vector<void*> corrupted_blocks;
    corrupted_blocks.push_back(ptr);
    
    // 限制保持的記憶體塊數量，避免記憶體洩漏
    if (corrupted_blocks.size() > 10) {
        free(corrupted_blocks[0]);
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
    std::uniform_int_distribution<> dis(1, 5);
    
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
                simulate_shellcode_injection();
                break;
            case 5:
                simulate_use_after_free();
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
    std::cout << "4. Shellcode Injection Attack" << std::endl;
    std::cout << "5. Use-After-Free Attack" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << "Enter attack number (0-5): ";
    
    // 初始化日誌檔案
    g_log_file.open("simple_attack_simulator.log", std::ios::app);
    
    int choice;
    while (true) {
        std::cout << "\nEnter attack number (0-5): ";
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
                simulate_shellcode_injection();
                break;
            case 5:
                simulate_use_after_free();
                break;
            default:
                std::cout << "Invalid choice. Please enter 0-5." << std::endl;
                break;
        }
        
        // 顯示當前狀態
        show_status();
    }
    
    return 0;
} 