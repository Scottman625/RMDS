#pragma once
#include <string>
#include <chrono>
#include <memory>

namespace MemoryDetectionEngine {

class PerformanceMonitor {
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::string operation_name_;

public:
    PerformanceMonitor(const std::string& operation);
    ~PerformanceMonitor();
    
    // 添加缺失的方法
    void start();
    void stop();
    struct Stats {
        std::chrono::microseconds duration;
        std::string operation_name;
    };
    Stats get_stats() const;
};

} // namespace MemoryDetectionEngine 