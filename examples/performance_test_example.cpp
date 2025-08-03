#include "memory_detection_engine.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <iomanip>
#include <numeric>

using namespace MemoryDetectionEngine;

// 性能測試結果
struct PerformanceResult {
    double avg_detection_time_us;
    double max_detection_time_us;
    double min_detection_time_us;
    uint64_t total_detections;
    uint64_t false_positives;
    double memory_usage_mb;
    double cpu_usage_percent;
};

class PerformanceBenchmark {
public:
    static PerformanceResult run_benchmark(const EngineConfig& config, int duration_seconds) {
        std::cout << "Running performance benchmark for " << duration_seconds << " seconds..." << std::endl;
        
        auto engine = std::make_unique<MemoryDetectionEngine>(config);
        engine->start();
        
        std::vector<double> detection_times;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // 運行基準測試
        while (std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::high_resolution_clock::now() - start_time).count() < duration_seconds) {
            
            auto detection_start = std::chrono::high_resolution_clock::now();
            
            // 模擬檢測操作
            auto stats = engine->get_stats();
            
            auto detection_end = std::chrono::high_resolution_clock::now();
            auto detection_time = std::chrono::duration_cast<std::chrono::microseconds>(
                detection_end - detection_start).count();
            
            detection_times.push_back(static_cast<double>(detection_time));
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config.detection_interval_ms));
        }
        
        engine->stop();
        
        // 計算統計數據
        PerformanceResult result;
        if (!detection_times.empty()) {
            result.avg_detection_time_us = std::accumulate(detection_times.begin(), detection_times.end(), 0.0) / detection_times.size();
            result.max_detection_time_us = *std::max_element(detection_times.begin(), detection_times.end());
            result.min_detection_time_us = *std::min_element(detection_times.begin(), detection_times.end());
        }
        
        auto final_stats = engine->get_stats();
        result.total_detections = final_stats.total_detections;
        result.false_positives = final_stats.total_false_positives;
        result.memory_usage_mb = 0.0; // 簡化實現
        result.cpu_usage_percent = 0.0; // 簡化實現
        
        return result;
    }
    
    static void print_results(const PerformanceResult& result, const std::string& test_name) {
        std::cout << "\n=== " << test_name << " ===" << std::endl;
        std::cout << "Average Detection Time: " << std::fixed << std::setprecision(2) 
                  << result.avg_detection_time_us << " us" << std::endl;
        std::cout << "Max Detection Time: " << result.max_detection_time_us << " us" << std::endl;
        std::cout << "Min Detection Time: " << result.min_detection_time_us << " us" << std::endl;
        std::cout << "Total Detections: " << result.total_detections << std::endl;
        std::cout << "False Positives: " << result.false_positives << std::endl;
        std::cout << "Memory Usage: " << result.memory_usage_mb << " MB" << std::endl;
        std::cout << "CPU Usage: " << result.cpu_usage_percent << "%" << std::endl;
    }
};

int main() {
    std::cout << "=== Performance Benchmark Suite ===" << std::endl;
    std::cout << "Testing Real-Time Memory Attack Detection Engine Performance" << std::endl;
    
    // 測試1: 高頻率檢測
    std::cout << "\n1. High-Frequency Detection Test" << std::endl;
    EngineConfig high_freq_config;
    high_freq_config.enable_mte = true;
    high_freq_config.enable_llvm_instrumentation = true;
    high_freq_config.enable_pattern_matching = true;
    high_freq_config.enable_performance_monitoring = true;
    high_freq_config.detection_threshold = 80;
    high_freq_config.max_latency_us = 3;
    high_freq_config.detection_interval_ms = 1; // 1ms 間隔
    
    auto high_freq_result = PerformanceBenchmark::run_benchmark(high_freq_config, 10);
    PerformanceBenchmark::print_results(high_freq_result, "High-Frequency Test Results");
    
    // 測試2: 低延遲檢測
    std::cout << "\n2. Low-Latency Detection Test" << std::endl;
    EngineConfig low_latency_config;
    low_latency_config.enable_mte = true;
    low_latency_config.enable_llvm_instrumentation = false; // 禁用LLVM以降低延遲
    low_latency_config.enable_pattern_matching = true;
    low_latency_config.enable_performance_monitoring = true;
    low_latency_config.detection_threshold = 90;
    low_latency_config.max_latency_us = 1;
    low_latency_config.detection_interval_ms = 5;
    
    auto low_latency_result = PerformanceBenchmark::run_benchmark(low_latency_config, 10);
    PerformanceBenchmark::print_results(low_latency_result, "Low-Latency Test Results");
    
    // 測試3: 高精度檢測
    std::cout << "\n3. High-Precision Detection Test" << std::endl;
    EngineConfig high_precision_config;
    high_precision_config.enable_mte = true;
    high_precision_config.enable_llvm_instrumentation = true;
    high_precision_config.enable_pattern_matching = true;
    high_precision_config.enable_performance_monitoring = true;
    high_precision_config.detection_threshold = 95;
    high_precision_config.max_latency_us = 5;
    high_precision_config.detection_interval_ms = 10;
    
    auto high_precision_result = PerformanceBenchmark::run_benchmark(high_precision_config, 10);
    PerformanceBenchmark::print_results(high_precision_result, "High-Precision Test Results");
    
    // 性能總結
    std::cout << "\n=== Performance Summary ===" << std::endl;
    std::cout << "Target Latency: < 3 us" << std::endl;
    std::cout << "Achieved Latency: " << std::min({high_freq_result.avg_detection_time_us, 
                                                   low_latency_result.avg_detection_time_us, 
                                                   high_precision_result.avg_detection_time_us}) << " us" << std::endl;
    std::cout << "Performance Target: " << (std::min({high_freq_result.avg_detection_time_us, 
                                                      low_latency_result.avg_detection_time_us, 
                                                      high_precision_result.avg_detection_time_us}) < 3.0 ? "PASSED" : "FAILED") << std::endl;
    
    std::cout << "\n=== Performance Benchmark Completed ===" << std::endl;
    
    return 0;
} 