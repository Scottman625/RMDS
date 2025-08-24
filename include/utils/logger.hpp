#pragma once
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

// 取消可能衝突的宏定義
#ifdef ERROR
#undef ERROR
#endif

namespace MemoryDetectionEngine {

class Logger {
public:
    enum class LogLevel {
        INFO,
        WARNING,
        ERROR,
        DEBUG
    };

    static void info(const std::string& message);
    static void warning(const std::string& message);
    static void error(const std::string& message);
    static void warn(const std::string& message);

private:
    static void log(LogLevel level, const std::string& message);

public:
    static std::string get_timestamp();
};

// 從 detection_engine.cpp 提取的日誌函數
void log_message(const std::string& level, const std::string& message);
void log_critical(const std::string& message);
void log_important(const std::string& message);
void log_warning(const std::string& message);
void log_success(const std::string& message);
void log_info(const std::string& message);

// 日誌輸出控制函數
bool should_output_log(const std::string& log_key, int max_count = 5, int interval_seconds = 30);
void controlled_log_output(const std::string& log_key, const std::string& message, 
                          int max_count, int interval_seconds, const std::string& level = "INFO");
void controlled_console_output(const std::string& log_key, const std::string& message, 
                              int max_count, int interval_seconds, const std::string& level = "INFO");

// 日誌文件管理
void init_log_file(const std::string& log_file_path);
void close_log_file();

} // namespace MemoryDetectionEngine
