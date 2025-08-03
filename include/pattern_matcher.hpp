#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <unordered_map>

namespace MemoryDetectionEngine {

/**
 * @brief 模式類型
 */
enum class PatternType {
    ROP_GADGET,      // ROP小工具
    JOP_GADGET,      // JOP小工具
    CALLOP_GADGET,   // CALLOP小工具
    STACK_PIVOT,     // 堆棧轉向
    RET2LIBC,        // Ret2libc攻擊
    SHELLCODE,       // Shellcode
    CUSTOM           // 自定義模式
};

/**
 * @brief 模式匹配算法
 */
enum class MatchingAlgorithm {
    EXACT_MATCH,     // 精確匹配
    FUZZY_MATCH,     // 模糊匹配
    SIGNATURE_MATCH, // 簽名匹配
    HEURISTIC_MATCH, // 啟發式匹配
    MACHINE_LEARNING // 機器學習
};

/**
 * @brief 模式配置結構
 */
struct PatternConfig {
    bool enable_rop_detection = true;
    bool enable_jop_detection = true;
    bool enable_callop_detection = true;
    bool enable_stack_pivot_detection = true;
    bool enable_ret2libc_detection = true;
    bool enable_shellcode_detection = true;
    uint32_t min_pattern_length = 4;
    uint32_t max_pattern_length = 1024;
    double confidence_threshold = 0.8;
    uint32_t max_matches_per_scan = 100;
    std::string log_level = "INFO";
};

/**
 * @brief 攻擊模式結構
 */
struct AttackPattern {
    std::string name;
    PatternType type;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> mask;
    double confidence;
    std::string description;
    std::vector<std::string> tags;
    uint32_t min_occurrences;
    uint32_t max_occurrences;
};

/**
 * @brief 匹配結果結構
 */
struct MatchResult {
    std::string pattern_name;
    PatternType type;
    uint64_t address;
    uint64_t offset;
    double confidence;
    std::vector<uint8_t> matched_data;
    std::string description;
    uint64_t timestamp;
    bool is_false_positive;
};

/**
 * @brief 模式統計信息
 */
struct PatternStats {
    uint64_t total_patterns;
    uint64_t total_matches;
    uint64_t rop_matches;
    uint64_t jop_matches;
    uint64_t callop_matches;
    uint64_t stack_pivot_matches;
    uint64_t ret2libc_matches;
    uint64_t shellcode_matches;
    uint64_t false_positives;
    double average_confidence;
    double average_scan_time_us;
};

/**
 * @brief 模式匹配器類
 * 負責ROP/JOP攻擊模式匹配和檢測
 */
class PatternMatcher {
public:
    PatternMatcher();
    ~PatternMatcher();
    
    bool initialize();
    void cleanup();
    
    // 添加缺失的方法
    bool is_enabled() const;
    void set_enabled(bool enabled);
    
    // 禁用複製構造和賦值
    PatternMatcher(const PatternMatcher&) = delete;
    PatternMatcher& operator=(const PatternMatcher&) = delete;
};

} // namespace MemoryDetectionEngine 