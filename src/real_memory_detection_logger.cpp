#include "../include/real_memory_detection_utils.hpp"
#include <iostream>

namespace RealMemoryDetection {

Logger::Logger(const std::string& log_file, int level)
    : log_level_(level) {
    log_file_.open(log_file, std::ios::app);
}

Logger::~Logger() {
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

void Logger::log(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::string timestamp = DetectionUtils::get_timestamp();
    std::string full_message = timestamp + " [" + level + "] " + message;
    
    std::cout << full_message << std::endl;
    if (log_file_.is_open()) {
        log_file_ << full_message << std::endl;
    }
}

void Logger::set_log_level(int level) {
    log_level_ = level;
}

void Logger::info(const std::string& message) {
    log("INFO", message);
}

void Logger::warning(const std::string& message) {
    log("WARNING", message);
}

void Logger::error(const std::string& message) {
    log("ERROR", message);
}

void Logger::debug(const std::string& message) {
    log("DEBUG", message);
}

} // namespace RealMemoryDetection 