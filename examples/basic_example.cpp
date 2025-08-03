#include "memory_detection_engine.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace MemoryDetectionEngine;

int main() {
    std::cout << "=== Real-Time Memory Attack Detection Engine - Basic Example ===" << std::endl;
    std::cout << "Version: " << MemoryDetectionEngine::get_version() << std::endl;
    
    // 配置引擎
    EngineConfig config;
    config.enable_mte = true;
    config.enable_llvm_instrumentation = true;
    config.enable_pattern_matching = true;
    config.enable_performance_monitoring = true;
    config.detection_threshold = 80;
    config.max_latency_us = 3;
    config.detection_interval_ms = 100;
    config.log_level = "INFO";
    
    std::cout << "\n1. Creating Memory Detection Engine..." << std::endl;
    
    // 創建引擎實例
    auto engine = std::make_unique<MemoryDetectionEngine>(config);
    
    std::cout << "2. Starting the engine..." << std::endl;
    
    // 啟動引擎
    if (!engine->start()) {
        std::cerr << "Failed to start the engine!" << std::endl;
        return 1;
    }
    
    std::cout << "3. Engine is running. Monitoring for 10 seconds..." << std::endl;
    
    // 模擬運行一段時間
    for (int i = 0; i < 10; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "   Monitoring... " << (i + 1) << "/10 seconds" << std::endl;
        
        // 獲取統計信息
        auto stats = engine->get_stats();
        std::cout << "   - Total detections: " << stats.total_detections << std::endl;
        std::cout << "   - Average detection time: " << stats.average_detection_time_us << " us" << std::endl;
    }
    
    std::cout << "\n4. Stopping the engine..." << std::endl;
    
    // 停止引擎
    engine->stop();
    
    std::cout << "5. Engine stopped successfully." << std::endl;
    
    // 顯示最終統計
    auto final_stats = engine->get_stats();
    std::cout << "\n=== Final Statistics ===" << std::endl;
    std::cout << "Total detections: " << final_stats.total_detections << std::endl;
    std::cout << "Total false positives: " << final_stats.total_false_positives << std::endl;
    std::cout << "Average detection time: " << final_stats.average_detection_time_us << " us" << std::endl;
    std::cout << "Uptime: " << final_stats.uptime_seconds << " seconds" << std::endl;
    
    std::cout << "\n=== Example completed successfully! ===" << std::endl;
    
    return 0;
} 