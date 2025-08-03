#include <iostream>
#include <thread>
#include <chrono>

// 簡化的引擎介面
class SimpleMemoryDetectionEngine {
public:
    struct Config {
        bool enable_mte = true;
        bool enable_pattern_matching = true;
        uint32_t detection_interval_ms = 100;
        std::string log_level = "INFO";
    };
    
    struct Stats {
        uint64_t total_detections = 0;
        uint64_t false_positives = 0;
        double average_detection_time_us = 0.0;
        uint64_t uptime_seconds = 0;
    };
    
    SimpleMemoryDetectionEngine(const Config& config) : config_(config), running_(false) {
        std::cout << "Simple Memory Detection Engine initialized" << std::endl;
    }
    
    ~SimpleMemoryDetectionEngine() {
        stop();
    }
    
    bool start() {
        if (running_) {
            std::cout << "Engine is already running" << std::endl;
            return false;
        }
        
        std::cout << "Starting Memory Detection Engine..." << std::endl;
        running_ = true;
        detection_thread_ = std::thread(&SimpleMemoryDetectionEngine::detection_loop, this);
        return true;
    }
    
    void stop() {
        if (!running_) return;
        
        std::cout << "Stopping Memory Detection Engine..." << std::endl;
        running_ = false;
        
        if (detection_thread_.joinable()) {
            detection_thread_.join();
        }
    }
    
    Stats get_stats() const {
        return stats_;
    }
    
    static std::string get_version() {
        return "1.0.0";
    }
    
private:
    void detection_loop() {
        std::cout << "Detection loop started" << std::endl;
        
        auto start_time = std::chrono::steady_clock::now();
        
        while (running_) {
            // 模擬檢測邏輯
            perform_detection();
            
            // 更新統計
            auto now = std::chrono::steady_clock::now();
            stats_.uptime_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
            
            // 等待下一個檢測週期
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.detection_interval_ms));
        }
        
        std::cout << "Detection loop stopped" << std::endl;
    }
    
    void perform_detection() {
        // 模擬檢測邏輯
        if (config_.enable_mte) {
            // 模擬 MTE 檢測
            stats_.total_detections++;
        }
        
        if (config_.enable_pattern_matching) {
            // 模擬模式匹配檢測
            stats_.total_detections++;
        }
        
        // 模擬檢測時間
        stats_.average_detection_time_us = 2.5; // 目標 < 3us
    }
    
    Config config_;
    std::atomic<bool> running_;
    std::thread detection_thread_;
    mutable Stats stats_;
};

int main() {
    std::cout << "=== Real-Time Memory Attack Detection Engine - Simple Example ===" << std::endl;
    std::cout << "Version: " << SimpleMemoryDetectionEngine::get_version() << std::endl;
    
    // 配置引擎
    SimpleMemoryDetectionEngine::Config config;
    config.enable_mte = true;
    config.enable_pattern_matching = true;
    config.detection_interval_ms = 100;
    config.log_level = "INFO";
    
    std::cout << "\n1. Creating Memory Detection Engine..." << std::endl;
    
    // 創建引擎實例
    auto engine = std::make_unique<SimpleMemoryDetectionEngine>(config);
    
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
        std::cout << "   - Uptime: " << stats.uptime_seconds << " seconds" << std::endl;
    }
    
    std::cout << "\n4. Stopping the engine..." << std::endl;
    
    // 停止引擎
    engine->stop();
    
    std::cout << "5. Engine stopped successfully." << std::endl;
    
    // 顯示最終統計
    auto final_stats = engine->get_stats();
    std::cout << "\n=== Final Statistics ===" << std::endl;
    std::cout << "Total detections: " << final_stats.total_detections << std::endl;
    std::cout << "False positives: " << final_stats.false_positives << std::endl;
    std::cout << "Average detection time: " << final_stats.average_detection_time_us << " us" << std::endl;
    std::cout << "Uptime: " << final_stats.uptime_seconds << " seconds" << std::endl;
    
    std::cout << "\n=== Example completed successfully! ===" << std::endl;
    
    return 0;
} 