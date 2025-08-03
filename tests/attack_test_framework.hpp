#pragma once

#include "memory_detection_engine.hpp"
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <chrono>
#include <random>

namespace MemoryDetectionEngine {

// 攻擊結果結構
struct AttackResult {
    AttackType type;
    bool detected;
    uint64_t detection_time_us;
    std::string description;
    double confidence;
    bool false_positive;
};

// 攻擊測試配置
struct AttackTestConfig {
    bool enable_rop_tests = true;
    bool enable_jop_tests = true;
    bool enable_memory_corruption_tests = true;
    bool enable_heap_tests = true;
    uint32_t test_duration_ms = 1000;
    uint32_t attack_interval_ms = 100;
    bool verbose_output = true;
};

// 攻擊測試基類
class AttackTest {
public:
    virtual ~AttackTest() = default;
    
    virtual std::string get_name() const = 0;
    virtual AttackType get_type() const = 0;
    virtual std::string get_description() const = 0;
    virtual bool execute() = 0;
    virtual bool should_be_detected() const = 0;
    
    // 獲取攻擊統計
    virtual uint64_t get_attack_count() const { return attack_count_; }
    virtual uint64_t get_success_count() const { return success_count_; }
    virtual double get_success_rate() const {
        return attack_count_ > 0 ? (double)success_count_ / attack_count_ : 0.0;
    }

protected:
    uint64_t attack_count_ = 0;
    uint64_t success_count_ = 0;
};

// 攻擊測試管理器
class AttackTestManager {
public:
    AttackTestManager(const AttackTestConfig& config);
    ~AttackTestManager();
    
    // 添加攻擊測試
    void add_test(std::unique_ptr<AttackTest> test);
    
    // 運行所有測試
    std::vector<AttackResult> run_all_tests();
    
    // 運行特定類型測試
    std::vector<AttackResult> run_tests_by_type(AttackType type);
    
    // 生成測試報告
    void generate_report(const std::vector<AttackResult>& results);
    
    // 獲取測試統計
    struct TestStats {
        uint64_t total_attacks;
        uint64_t detected_attacks;
        uint64_t false_positives;
        double detection_rate;
        double false_positive_rate;
        double average_detection_time_us;
    };
    
    TestStats get_stats(const std::vector<AttackResult>& results) const;

private:
    AttackTestConfig config_;
    std::vector<std::unique_ptr<AttackTest>> tests_;
    std::random_device rd_;
    std::mt19937 gen_;
};

// 前向聲明測試類
class ROPChainTest;
class JOPChainTest;
class MemoryCorruptionTest;
class BufferOverflowTest;
class UseAfterFreeTest;
class DoubleFreeTest;

} // namespace MemoryDetectionEngine 