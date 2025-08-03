#include "pattern_matcher.hpp"
#include "utils/logger.hpp"

namespace MemoryDetectionEngine {

// PatternMatcher實現
PatternMatcher::PatternMatcher() {
    LOG_INFO("Pattern Matcher initialized");
}

PatternMatcher::~PatternMatcher() {
    LOG_INFO("Pattern Matcher destroyed");
}

bool PatternMatcher::initialize() {
    LOG_INFO("Pattern Matcher: Initializing");
    return true;
}

void PatternMatcher::cleanup() {
    LOG_INFO("Pattern Matcher: Cleaning up");
}

bool PatternMatcher::is_enabled() const {
    return true;
}

void PatternMatcher::set_enabled(bool enabled) {
    LOG_INFO("Pattern Matcher: Setting enabled to {}", enabled);
}

} // namespace MemoryDetectionEngine

// 導出符號以避免鏈接錯誤
extern "C" {
    void pattern_matcher_init() {
        // 初始化模式匹配器
    }
} 