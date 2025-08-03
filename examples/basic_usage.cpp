#include "memory_detection_engine.hpp"
#include <iostream>
#include <chrono>
#include <thread>

using namespace MemoryDetectionEngine;

int main() {
    std::cout << "實時內存攻擊檢測引擎範例" << std::endl;
    std::cout << "版本: " << MemoryDetectionEngine::get_version() << std::endl;

    // 配置引擎
    EngineConfig config;
    config.enable_mte = true;
    config.enable_llvm_instrumentation = true;
    config.enable_pattern_matching = true;
    config.enable_performance_monitoring = true;
    config.detection_threshold = 80;
    config.max_latency_us = 3;
    config.log_level = "INFO";

    // 創建引擎實例
    auto engine = create_engine(config);

    // 註冊檢測回調函數
    engine->register_detection_callback([](const DetectionResult& result) {
        std::cout << "檢測到攻擊!" << std::endl;
        std::cout << "類型: " << static_cast<int>(result.type) << std::endl;
        std::cout << "地址: 0x" << std::hex << result.address << std::dec << std::endl;
        std::cout << "描述: " << result.description << std::endl;
        std::cout << "置信度: " << result.confidence << std::endl;
        std::cout << "時間戳: " << result.timestamp << std::endl;
        std::cout << "是否誤報: " << (result.is_false_positive ? "是" : "否") << std::endl;
        std::cout << "------------------------" << std::endl;
    });

    // 初始化引擎
    if (!engine->initialize()) {
        std::cerr << "引擎初始化失敗!" << std::endl;
        return 1;
    }

    std::cout << "引擎初始化成功" << std::endl;

    // 添加自定義攻擊模式
    std::vector<uint8_t> rop_pattern = {0xC3, 0x90, 0x90, 0x90}; // ret + nop
    engine->add_custom_pattern(rop_pattern, AttackType::ROP);

    std::vector<uint8_t> jop_pattern = {0xFF, 0xE0, 0x90, 0x90}; // jmp eax + nop
    engine->add_custom_pattern(jop_pattern, AttackType::JOP);

    // 啟動引擎
    if (!engine->start()) {
        std::cerr << "引擎啟動失敗!" << std::endl;
        return 1;
    }

    std::cout << "引擎已啟動，開始檢測..." << std::endl;

    // 運行一段時間
    const int run_duration_seconds = 30;
    std::cout << "將運行 " << run_duration_seconds << " 秒..." << std::endl;

    auto start_time = std::chrono::steady_clock::now();
    
    while (std::chrono::steady_clock::now() - start_time < std::chrono::seconds(run_duration_seconds)) {
        // 每5秒顯示一次性能統計
        static auto last_stats_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        
        if (now - last_stats_time >= std::chrono::seconds(5)) {
            auto stats = engine->get_performance_stats();
            std::cout << "\n性能統計:" << std::endl;
            std::cout << "總檢測數: " << stats.total_detections << std::endl;
            std::cout << "誤報數: " << stats.false_positives << std::endl;
            std::cout << "平均延遲: " << stats.average_latency_us << " μs" << std::endl;
            std::cout << "最大延遲: " << stats.max_latency_us << " μs" << std::endl;
            std::cout << "最小延遲: " << stats.min_latency_us << " μs" << std::endl;
            std::cout << "記憶體使用: " << stats.memory_usage_bytes << " bytes" << std::endl;
            std::cout << "------------------------" << std::endl;
            
            last_stats_time = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 停止引擎
    engine->stop();
    std::cout << "引擎已停止" << std::endl;

    // 顯示最終統計
    auto final_stats = engine->get_performance_stats();
    std::cout << "\n最終統計:" << std::endl;
    std::cout << "總檢測數: " << final_stats.total_detections << std::endl;
    std::cout << "誤報數: " << final_stats.false_positives << std::endl;
    std::cout << "平均延遲: " << final_stats.average_latency_us << " μs" << std::endl;
    std::cout << "記憶體使用: " << final_stats.memory_usage_bytes << " bytes" << std::endl;

    return 0;
} 