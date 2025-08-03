#pragma once

#include <string>
#include <memory>
#include <mutex>
#include <fstream>

namespace MemoryDetectionEngine {

/**
 * @brief 日誌級別
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR,
    FATAL
};

/**
 * @brief 日誌記錄器類
 */
class Logger {
public:
    explicit Logger(const std::string& level = "INFO", const std::string& filename = "");
    ~Logger();

    // 禁用複製構造和賦值
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    /**
     * @brief 記錄調試信息
     */
    template<typename... Args>
    void debug(const std::string& format, Args&&... args) {
        log(LogLevel::DEBUG, format, std::forward<Args>(args)...);
    }

    /**
     * @brief 記錄一般信息
     */
    template<typename... Args>
    void info(const std::string& format, Args&&... args) {
        log(LogLevel::INFO, format, std::forward<Args>(args)...);
    }

    /**
     * @brief 記錄警告信息
     */
    template<typename... Args>
    void warn(const std::string& format, Args&&... args) {
        log(LogLevel::WARN, format, std::forward<Args>(args)...);
    }

    /**
     * @brief 記錄錯誤信息
     */
    template<typename... Args>
    void error(const std::string& format, Args&&... args) {
        log(LogLevel::ERROR, format, std::forward<Args>(args)...);
    }

    /**
     * @brief 記錄致命錯誤信息
     */
    template<typename... Args>
    void fatal(const std::string& format, Args&&... args) {
        log(LogLevel::FATAL, format, std::forward<Args>(args)...);
    }

    /**
     * @brief 設置日誌級別
     */
    void set_level(LogLevel level);

    /**
     * @brief 獲取日誌級別
     */
    LogLevel get_level() const;

    /**
     * @brief 設置輸出文件
     */
    void set_output_file(const std::string& filename);

    /**
     * @brief 啟用/禁用控制台輸出
     */
    void set_console_output(bool enabled);

    /**
     * @brief 啟用/禁用文件輸出
     */
    void set_file_output(bool enabled);

private:
    template<typename... Args>
    void log(LogLevel level, const std::string& format, Args&&... args) {
        if (level >= level_) {
            std::string message = format_message(format, std::forward<Args>(args)...);
            write_log(level, message);
        }
    }

    template<typename... Args>
    std::string format_message(const std::string& format, Args&&... args) {
        // 簡單的格式化實現
        std::string result = format;
        // 這裡可以實現更複雜的格式化邏輯
        return result;
    }

    void write_log(LogLevel level, const std::string& message);
    std::string get_level_string(LogLevel level);
    std::string get_timestamp();

    LogLevel level_;
    std::string filename_;
    std::ofstream file_stream_;
    std::mutex mutex_;
    bool console_output_;
    bool file_output_;
};

} // namespace MemoryDetectionEngine 