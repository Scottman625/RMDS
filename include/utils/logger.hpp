#pragma once
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace MemoryDetectionEngine {

// Logger類別定義
class Logger {
public:
    enum class Level {
        INFO,
        WARNING,
        ERROR
    };

    static void info(const std::string& message);
    static void warning(const std::string& message);
    static void error(const std::string& message);
    static void warn(const std::string& message); // 添加warn方法
    
    template<typename... Args>
    static void info(const std::string& format, Args... args) {
        info(format); // 簡化實現
    }
    
    template<typename... Args>
    static void warning(const std::string& format, Args... args) {
        warning(format); // 簡化實現
    }
    
    template<typename... Args>
    static void error(const std::string& format, Args... args) {
        error(format); // 簡化實現
    }
    
    template<typename... Args>
    static void warn(const std::string& format, Args... args) {
        warn(format); // 簡化實現
    }

private:
    static std::string get_timestamp();
    static void log(Level level, const std::string& message);
};

} // namespace MemoryDetectionEngine

// 簡化的日誌函數（向後兼容）
void LOG_INFO(const std::string& message);
void LOG_WARNING(const std::string& message);
void LOG_ERROR(const std::string& message);

// 格式化日誌函數（簡化版本）
template<typename... Args>
void LOG_INFO(const std::string& format, Args... args) {
    LOG_INFO(format); // 簡化實現
}

template<typename... Args>
void LOG_WARNING(const std::string& format, Args... args) {
    LOG_WARNING(format); // 簡化實現
}

template<typename... Args>
void LOG_ERROR(const std::string& format, Args... args) {
    LOG_ERROR(format); // 簡化實現
} 