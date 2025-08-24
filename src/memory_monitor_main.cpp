#include "../include/memory_detection_monitor.hpp"
#include "../include/memory_detection_types.hpp"
#include <iostream>
#include <conio.h>
#include <thread>
#include <chrono>

using namespace RealMemoryDetection;

// 記憶體違規回調函數
void on_memory_violation(AttackType type, uint64_t address, const std::string& description, double confidence, DWORD process_id) {
    std::cout << "\n[警告] 檢測到記憶體違規:\n";
    std::cout << "類型: ";
    
    switch (type) {
        case AttackType::ROP_CHAIN:
            std::cout << "ROP鏈攻擊";
            break;
        case AttackType::JOP_CHAIN:
            std::cout << "JOP鏈攻擊";
            break;
        case AttackType::BUFFER_OVERFLOW:
            std::cout << "緩衝區溢出";
            break;
        case AttackType::HEAP_CORRUPTION:
            std::cout << "堆損壞";
            break;
        case AttackType::STACK_OVERFLOW:
            std::cout << "堆疊溢出";
            break;
        case AttackType::USE_AFTER_FREE:
            std::cout << "Use-After-Free";
            break;
        case AttackType::SHELLCODE_INJECTION:
            std::cout << "Shellcode注入";
            break;
        default:
            std::cout << "未知攻擊";
            break;
    }
    
    std::cout << "\n地址: 0x" << std::hex << address << std::dec;
    std::cout << "\n描述: " << description;
    std::cout << "\n置信度: " << confidence;
    std::cout << "\n進程ID: " << process_id;
    std::cout << "\n" << std::endl;
}

int main() {
    std::cout << "=== 記憶體監控器 ===\n";
    std::cout << "按 'q' 退出，按 's' 顯示狀態，按 'h' 顯示幫助\n\n";
    
    // 配置記憶體監控器
    MemoryMonitorConfig config;
    config.scan_interval_ms = 100;
    config.max_regions_per_scan = 500;
    config.enable_heap_monitoring = true;
    config.enable_stack_monitoring = true;
    config.enable_executable_monitoring = true;
    config.enable_shared_memory_monitoring = true;
    config.suspicious_pattern_threshold = 5;
    config.log_file = "logs/memory_monitor.log";
    
    // 創建記憶體監控器
    MemoryMonitor monitor(config);
    
    // 設置違規回調
    monitor.set_violation_callback(on_memory_violation);
    
    // 啟動監控器
    if (!monitor.start()) {
        std::cerr << "無法啟動記憶體監控器\n";
        return 1;
    }
    
    std::cout << "記憶體監控器已啟動\n";
    std::cout << "正在監控系統記憶體...\n\n";
    
    char input;
    while (monitor.is_running()) {
        if (_kbhit()) {
            input = _getch();
            
            switch (input) {
                case 'q':
                case 'Q':
                    std::cout << "正在停止記憶體監控器...\n";
                    monitor.stop();
                    break;
                    
                case 's':
                case 'S':
                    {
                        auto stats = monitor.get_stats();
                        std::cout << "\n=== 記憶體監控器狀態 ===\n";
                        std::cout << "總掃描次數: " << stats.total_scans << "\n";
                        std::cout << "掃描區域數: " << stats.regions_scanned << "\n";
                        std::cout << "違規檢測數: " << stats.violations_detected << "\n";
                        std::cout << "堆損壞檢測: " << stats.heap_corruptions << "\n";
                        std::cout << "堆疊損壞檢測: " << stats.stack_corruptions << "\n";
                        std::cout << "可執行記憶體違規: " << stats.executable_violations << "\n";
                        
                        auto last_scan = stats.last_scan;
                        auto now = std::chrono::system_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_scan);
                        std::cout << "最後掃描時間: " << duration.count() << " 秒前\n";
                        std::cout << "========================\n\n";
                    }
                    break;
                    
                case 'h':
                case 'H':
                    std::cout << "\n=== 幫助 ===\n";
                    std::cout << "q - 退出程式\n";
                    std::cout << "s - 顯示狀態\n";
                    std::cout << "h - 顯示此幫助\n";
                    std::cout << "==========\n\n";
                    break;
                    
                case '1':
                    monitor.enable_heap_monitoring(true);
                    std::cout << "已啟用堆監控\n";
                    break;
                    
                case '2':
                    monitor.enable_heap_monitoring(false);
                    std::cout << "已禁用堆監控\n";
                    break;
                    
                case '3':
                    monitor.enable_stack_monitoring(true);
                    std::cout << "已啟用堆疊監控\n";
                    break;
                    
                case '4':
                    monitor.enable_stack_monitoring(false);
                    std::cout << "已禁用堆疊監控\n";
                    break;
                    
                case '5':
                    monitor.enable_executable_monitoring(true);
                    std::cout << "已啟用可執行記憶體監控\n";
                    break;
                    
                case '6':
                    monitor.enable_executable_monitoring(false);
                    std::cout << "已禁用可執行記憶體監控\n";
                    break;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "\n記憶體監控器已停止\n";
    return 0;
} 