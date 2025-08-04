#include "../include/utils/performance_monitor.hpp"
#include <iostream>

namespace MemoryDetectionEngine {

PerformanceMonitor::PerformanceMonitor(const std::string& operation)
    : operation_name_(operation) {
    start_time_ = std::chrono::high_resolution_clock::now();
}

PerformanceMonitor::~PerformanceMonitor() {
    stop();
}

void PerformanceMonitor::start() {
    start_time_ = std::chrono::high_resolution_clock::now();
}

void PerformanceMonitor::stop() {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
    
    std::cout << "Performance: " << operation_name_ << " took " 
              << duration.count() << " microseconds" << std::endl;
}

PerformanceMonitor::Stats PerformanceMonitor::get_stats() const {
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time_);
    
    return {duration, operation_name_};
}

} // namespace MemoryDetectionEngine 