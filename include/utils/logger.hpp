#pragma once
#include <string>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace MemoryDetectionEngine {

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
    static void warn(const std::string& message);

private:
    static void log(Level level, const std::string& message);
    static std::string get_timestamp();
};

} // namespace MemoryDetectionEngine 