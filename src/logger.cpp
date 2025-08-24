#include "../include/utils/logger.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <fstream>
#include <mutex>
#include <map>

namespace MemoryDetectionEngine {

// 全局日誌控制變數
static std::map<std::string, std::chrono::steady_clock::time_point> last_log_output_;
static std::map<std::string, int> log_output_count_;
static std::mutex log_control_mutex_;

// 日誌文件輸出
static std::ofstream log_file_;
static std::mutex log_file_mutex_;

void Logger::info(const std::string& message) {
    log(LogLevel::INFO, message);
}

void Logger::warning(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::error(const std::string& message) {
    log(LogLevel::ERROR, message);
}

void Logger::warn(const std::string& message) {
    log(LogLevel::WARNING, message);
}

void Logger::log(LogLevel level, const std::string& message) {
    std::string timestamp = get_timestamp();
    std::string level_str;
    
    switch (level) {
        case LogLevel::INFO:
            level_str = "INFO";
            break;
        case LogLevel::WARNING:
            level_str = "WARNING";
            break;
        case LogLevel::ERROR:
            level_str = "ERROR";
            break;
        case LogLevel::DEBUG:
            level_str = "DEBUG";
            break;
    }
    
    std::string full_message = timestamp + " [" + level_str + "] " + message;
    std::cout << full_message << std::endl;
    
    // 同時寫入日誌文件
    {
        std::lock_guard<std::mutex> lock(log_file_mutex_);
        if (log_file_.is_open()) {
            log_file_ << full_message << std::endl;
        }
    }
}

// 新增：從 detection_engine.cpp 提取的日誌函數
void log_message(const std::string& level, const std::string& message) {
    std::lock_guard<std::mutex> lock(log_file_mutex_);
    std::string timestamp = Logger::get_timestamp();
    std::string full_message = timestamp + " [" + level + "] " + message;
    
    std::cout << full_message << std::endl;
    if (log_file_.is_open()) {
        log_file_ << full_message << std::endl;
    }
}

void log_critical(const std::string& message) {
    try {
        log_message("CRITICAL", message);
    } catch (...) {
        std::cerr << "Error in log_critical" << std::endl;
    }
}

void log_important(const std::string& message) {
    try {
        log_message("ALERT", message);
    } catch (...) {
        std::cerr << "Error in log_important" << std::endl;
    }
}

void log_warning(const std::string& message) {
    try {
        log_message("WARNING", message);
    } catch (...) {
        std::cerr << "Error in log_warning" << std::endl;
    }
}

void log_success(const std::string& message) {
    try {
        log_message("SUCCESS", message);
    } catch (...) {
        std::cerr << "Error in log_success" << std::endl;
    }
}

void log_info(const std::string& message) {
    try {
        log_message("INFO", message);
    } catch (...) {
        std::cerr << "Error in log_info" << std::endl;
    }
}

// 日誌輸出控制函數
bool should_output_log(const std::string& log_key, int max_count, int interval_seconds) {
    std::lock_guard<std::mutex> lock(log_control_mutex_);
    auto now = std::chrono::steady_clock::now();
    
    auto it = last_log_output_.find(log_key);
    if (it != last_log_output_.end()) {
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (time_diff.count() < interval_seconds) {
            return false;
        }
    }
    
    auto count_it = log_output_count_.find(log_key);
    if (count_it != log_output_count_.end()) {
        if (count_it->second >= max_count) {
            return false;
        }
        count_it->second++;
    } else {
        log_output_count_[log_key] = 1;
    }
    
    last_log_output_[log_key] = now;
    return true;
}

void controlled_log_output(const std::string& log_key, const std::string& message, 
                          int max_count, int interval_seconds, const std::string& level) {
    if (should_output_log(log_key, max_count, interval_seconds)) {
        log_message(level, message);
    }
}

void controlled_console_output(const std::string& log_key, const std::string& message, 
                              int max_count, int interval_seconds, const std::string& level) {
    if (should_output_log(log_key, max_count, interval_seconds)) {
        std::cout << "[" << level << "] " << message << std::endl;
    }
}

// 初始化日誌文件
void init_log_file(const std::string& log_file_path) {
    std::lock_guard<std::mutex> lock(log_file_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
    log_file_.open(log_file_path, std::ios::app);
}

// 關閉日誌文件
void close_log_file() {
    std::lock_guard<std::mutex> lock(log_file_mutex_);
    if (log_file_.is_open()) {
        log_file_.close();
    }
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 全局時間戳函數
std::string get_timestamp() {
    return Logger::get_timestamp();
}

} // namespace MemoryDetectionEngine 