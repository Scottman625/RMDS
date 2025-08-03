#include "utils/logger.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace MemoryDetectionEngine {
    // Logger類別實現
    std::string Logger::get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    void Logger::log(Level level, const std::string& message) {
        std::string timestamp = get_timestamp();
        std::string level_str;
        
        switch (level) {
            case Level::INFO:
                level_str = "INFO";
                break;
            case Level::WARNING:
                level_str = "WARNING";
                break;
            case Level::ERROR:
                level_str = "ERROR";
                break;
        }
        
        std::cout << "[" << level_str << "][" << timestamp << "] " << message << std::endl;
    }

    void Logger::info(const std::string& message) {
        log(Level::INFO, message);
    }

    void Logger::warning(const std::string& message) {
        log(Level::WARNING, message);
    }

    void Logger::error(const std::string& message) {
        log(Level::ERROR, message);
    }

    void Logger::warn(const std::string& message) {
        log(Level::WARNING, message);
    }

    // 向後兼容的函數
    void LOG_INFO(const std::string& message) {
        Logger::info(message);
    }

    void LOG_WARNING(const std::string& message) {
        Logger::warning(message);
    }

    void LOG_ERROR(const std::string& message) {
        Logger::error(message);
    } 
}