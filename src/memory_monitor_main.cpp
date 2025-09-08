#include "../include/memory_detection_monitor.hpp"
#include "../include/memory_detection_types.hpp"
#include "../include/event_handler.hpp"
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

// int main() {
//     std::cout << "=== 記憶體監控器 ===\n";
//     std::cout << "按 'q' 退出，按 's' 顯示狀態，按 'h' 顯示幫助\n\n";
    
//     // 配置記憶體監控器
//     MemoryMonitorConfig config;
//     config.scan_interval_ms = 100;
//     config.max_regions_per_scan = 500;
//     config.enable_heap_monitoring = true;
//     config.enable_stack_monitoring = true;
//     config.enable_executable_monitoring = true;
//     config.enable_shared_memory_monitoring = true;
//     config.suspicious_pattern_threshold = 5;
//     config.log_file = "logs/memory_monitor.log";
    
//     // 創建記憶體監控器
//     EventHandler monitor(config);
    
//     // 設置違規回調
//     monitor.set_violation_callback(on_memory_violation);
    
//     // 啟動監控器
//     // start() returns void
//     monitor.start();
    
//     std::cout << "記憶體監控器已啟動\n";
//     std::cout << "正在監控系統記憶體...\n\n";
    
//     char input;
//     while (monitor.is_running()) {
//         if (_kbhit()) {
//             input = _getch();
            
//             switch (input) {
//                 case 'q':
//                 case 'Q':
//                     std::cout << "正在停止記憶體監控器...\n";
//                     monitor.stop();
//                     break;
                    
//                 case 's':
//                 case 'S':
//                     {
//                         const auto &stats = monitor.get_stats(); // avoid copy (copy ctor deleted)
//                         std::cout << "\n=== 記憶體監控器狀態 ===\n";
//                         std::cout << "總事件數: " << stats.events_in.load() << "\n";
//                         std::cout << "事件被丟棄: " << stats.events_dropped.load()
//                                   << " (高優先被丟棄: " << stats.events_dropped_high.load() << ")\n";
//                         std::cout << "掃描次數: " << stats.scan_runs.load() << "\n";
//                         std::cout << "可疑區域分析次數: " << stats.suspicious_regions_analyzed.load() << "\n";
//                         std::cout << "已確認發現數: " << stats.confirmed_findings.load() << "\n";
//                         // 注意：EventStats 內沒有 heap_corruptions/stack_corruptions/executable_violations/last_scan 欄位，
//                         // 若需要請改為在 EventStats 加入對應欄位或從 DetectionEngine 查詢。
//                         std::cout << "========================\n\n";
//                     }
//                     break;
                    
//                 case 'h':
//                 case 'H':
//                     std::cout << "\n=== 幫助 ===\n";
//                     std::cout << "q - 退出程式\n";
//                     std::cout << "s - 顯示狀態\n";
//                     std::cout << "h - 顯示此幫助\n";
//                     std::cout << "==========\n\n";
//                     break;
                    
//                 case '1':
//                     monitor.enable_heap_monitoring(true);
//                     std::cout << "已啟用堆監控\n";
//                     break;
                    
//                 case '2':
//                     monitor.enable_heap_monitoring(false);
//                     std::cout << "已禁用堆監控\n";
//                     break;
                    
//                 case '3':
//                     monitor.enable_stack_monitoring(true);
//                     std::cout << "已啟用堆疊監控\n";
//                     break;
                    
//                 case '4':
//                     monitor.enable_stack_monitoring(false);
//                     std::cout << "已禁用堆疊監控\n";
//                     break;
                    
//                 case '5':
//                     monitor.enable_executable_monitoring(true);
//                     std::cout << "已啟用可執行記憶體監控\n";
//                     break;
                    
//                 case '6':
//                     monitor.enable_executable_monitoring(false);
//                     std::cout << "已禁用可執行記憶體監控\n";
//                     break;
//             }
//         }
        
//         std::this_thread::sleep_for(std::chrono::milliseconds(100));
//     }
    
//     std::cout << "\n記憶體監控器已停止\n";
//     return 0;
// }