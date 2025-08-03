#include "utils/logger.hpp"
#include "utils/performance_monitor.hpp"
#include <chrono>
#include <thread>
namespace MemoryDetectionEngine {
    PerformanceMonitor::PerformanceMonitor(const std::string& operation) 
        : operation_name_(operation) {
        start_time_ = std::chrono::high_resolution_clock::now();
    }

    PerformanceMonitor::~PerformanceMonitor() {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
        LOG_INFO("Performance: {} took {} microseconds", operation_name_, duration.count());
    }

    void PerformanceMonitor::start() {
        start_time_ = std::chrono::high_resolution_clock::now();
    }

    void PerformanceMonitor::stop() {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
        LOG_INFO("Performance: {} took {} microseconds", operation_name_, duration.count());
    }

    PerformanceMonitor::Stats PerformanceMonitor::get_stats() const {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
        
        return Stats{
            duration,
            operation_name_
        };
    }
}

// 導出符號以避免鏈接錯誤
extern "C" {
    void performance_monitor_init() {
        // 初始化性能監控
    }
} 