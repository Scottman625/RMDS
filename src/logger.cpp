#include "../include/utils/logger.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace MemoryDetectionEngine {

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
    
    std::cout << timestamp << " [" << level_str << "] " << message << std::endl;
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

} // namespace MemoryDetectionEngine 