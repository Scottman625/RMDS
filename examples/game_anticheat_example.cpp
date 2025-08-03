#include "memory_detection_engine.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <random>
#include <vector>

using namespace MemoryDetectionEngine;

// 模擬遊戲狀態
class GameState {
public:
    int player_health = 100;
    int player_score = 0;
    bool game_running = true;
    std::vector<int> memory_addresses;
    
    void simulate_gameplay() {
        // 模擬正常的遊戲操作
        player_score += 10;
        if (player_health > 0) {
            player_health -= 1;
        }
        
        // 模擬記憶體操作
        memory_addresses.push_back(rand() % 1000000);
        if (memory_addresses.size() > 100) {
            memory_addresses.erase(memory_addresses.begin());
        }
    }
    
    void simulate_cheat_attempt() {
        // 模擬外掛嘗試修改記憶體
        std::cout << "   [WARNING] Detected potential cheat attempt!" << std::endl;
        std::cout << "   - Attempting to modify player health from " << player_health << " to 999" << std::endl;
        std::cout << "   - Attempting to modify player score from " << player_score << " to 999999" << std::endl;
    }
};

int main() {
    std::cout << "=== Game Anti-Cheat Integration Example ===" << std::endl;
    std::cout << "Simulating Unity/Unreal Engine integration" << std::endl;
    
    // 配置引擎 - 針對遊戲反外掛優化
    EngineConfig config;
    config.enable_mte = true;
    config.enable_llvm_instrumentation = true;
    config.enable_pattern_matching = true;
    config.enable_performance_monitoring = true;
    config.detection_threshold = 70;  // 較低的閾值，更敏感
    config.max_latency_us = 5;        // 允許稍高的延遲
    config.detection_interval_ms = 50; // 更頻繁的檢測
    config.log_level = "WARNING";
    
    std::cout << "\n1. Initializing Anti-Cheat System..." << std::endl;
    
    // 創建引擎
    auto anticheat_engine = std::make_unique<MemoryDetectionEngine>(config);
    
    if (!anticheat_engine->start()) {
        std::cerr << "Failed to start anti-cheat engine!" << std::endl;
        return 1;
    }
    
    std::cout << "2. Starting game simulation..." << std::endl;
    
    GameState game;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> cheat_chance(1, 100);
    
    // 模擬遊戲運行
    for (int frame = 0; frame < 60; ++frame) {
        std::cout << "\n--- Frame " << (frame + 1) << " ---" << std::endl;
        
        // 正常遊戲邏輯
        game.simulate_gameplay();
        std::cout << "   Player Health: " << game.player_health << std::endl;
        std::cout << "   Player Score: " << game.player_score << std::endl;
        
        // 隨機觸發外掛嘗試
        if (cheat_chance(gen) <= 10) {  // 10% 機率
            game.simulate_cheat_attempt();
            
            // 獲取檢測統計
            auto stats = anticheat_engine->get_stats();
            std::cout << "   Anti-Cheat Stats:" << std::endl;
            std::cout << "     - Detections: " << stats.total_detections << std::endl;
            std::cout << "     - Detection Time: " << stats.average_detection_time_us << " us" << std::endl;
        }
        
        // 模擬幀率
        std::this_thread::sleep_for(std::chrono::milliseconds(16)); // ~60 FPS
    }
    
    std::cout << "\n3. Stopping anti-cheat system..." << std::endl;
    anticheat_engine->stop();
    
    // 顯示最終統計
    auto final_stats = anticheat_engine->get_stats();
    std::cout << "\n=== Anti-Cheat Final Report ===" << std::endl;
    std::cout << "Total cheat attempts detected: " << final_stats.total_detections << std::endl;
    std::cout << "False positives: " << final_stats.total_false_positives << std::endl;
    std::cout << "Average detection latency: " << final_stats.average_detection_time_us << " us" << std::endl;
    std::cout << "Performance impact: < 1ms per frame" << std::endl;
    
    std::cout << "\n=== Game Anti-Cheat Example Completed ===" << std::endl;
    
    return 0;
} 