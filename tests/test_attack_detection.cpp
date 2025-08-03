#include "attack_test_framework.hpp"
#include <iostream>
#include <memory>
#include <thread>
#include <chrono>

using namespace MemoryDetectionEngine;

int main() {
    std::cout << "=== 實時記憶體攻擊檢測引擎 - 攻擊測試套件 ===" << std::endl;
    std::cout << "測試引擎對抗各種攻擊向量" << std::endl;
    
    // 配置攻擊測試
    AttackTestConfig test_config;
    test_config.enable_rop_tests = true;
    test_config.enable_jop_tests = true;
    test_config.enable_memory_corruption_tests = true;
    test_config.enable_heap_tests = true;
    test_config.test_duration_ms = 2000;
    test_config.attack_interval_ms = 100;
    test_config.verbose_output = true;
    
    // 創建攻擊測試管理器
    auto attack_manager = std::make_unique<AttackTestManager>(test_config);
    
    // 添加各種攻擊測試
    std::cout << "\n1. 設置攻擊測試..." << std::endl;
    
    // ROP 攻擊測試
    attack_manager->add_test(std::make_unique<ROPChainTest>());
    
    // JOP 攻擊測試
    attack_manager->add_test(std::make_unique<JOPChainTest>());
    
    // 記憶體破壞測試
    attack_manager->add_test(std::make_unique<MemoryCorruptionTest>());
    
    // 緩衝區溢出測試
    attack_manager->add_test(std::make_unique<BufferOverflowTest>());
    
    // Use-After-Free 測試
    attack_manager->add_test(std::make_unique<UseAfterFreeTest>());
    
    // Double Free 測試
    attack_manager->add_test(std::make_unique<DoubleFreeTest>());
    
    std::cout << "2. 執行攻擊測試..." << std::endl;
    
    // 運行所有攻擊測試
    auto results = attack_manager->run_all_tests();
    
    std::cout << "3. 生成測試報告..." << std::endl;
    
    // 生成測試報告
    attack_manager->generate_report(results);
    
    // 分析結果
    auto stats = attack_manager->get_stats(results);
    
    std::cout << "\n=== 性能分析 ===" << std::endl;
    
    // 評估檢測引擎性能
    if (stats.detection_rate >= 0.95) {
        std::cout << "✅ 優秀檢測率: " << (stats.detection_rate * 100) << "%" << std::endl;
    } else if (stats.detection_rate >= 0.90) {
        std::cout << "✅ 良好檢測率: " << (stats.detection_rate * 100) << "%" << std::endl;
    } else if (stats.detection_rate >= 0.80) {
        std::cout << "⚠️  一般檢測率: " << (stats.detection_rate * 100) << "%" << std::endl;
    } else {
        std::cout << "❌ 較差檢測率: " << (stats.detection_rate * 100) << "%" << std::endl;
    }
    
    if (stats.false_positive_rate <= 0.01) {
        std::cout << "✅ 優秀誤報率: " << (stats.false_positive_rate * 100) << "%" << std::endl;
    } else if (stats.false_positive_rate <= 0.05) {
        std::cout << "✅ 良好誤報率: " << (stats.false_positive_rate * 100) << "%" << std::endl;
    } else if (stats.false_positive_rate <= 0.10) {
        std::cout << "⚠️  一般誤報率: " << (stats.false_positive_rate * 100) << "%" << std::endl;
    } else {
        std::cout << "❌ 較差誤報率: " << (stats.false_positive_rate * 100) << "%" << std::endl;
    }
    
    if (stats.average_detection_time_us <= 3) {
        std::cout << "✅ 優秀檢測時間: " << stats.average_detection_time_us << " μs" << std::endl;
    } else if (stats.average_detection_time_us <= 5) {
        std::cout << "✅ 良好檢測時間: " << stats.average_detection_time_us << " μs" << std::endl;
    } else if (stats.average_detection_time_us <= 10) {
        std::cout << "⚠️  一般檢測時間: " << stats.average_detection_time_us << " μs" << std::endl;
    } else {
        std::cout << "❌ 較差檢測時間: " << stats.average_detection_time_us << " μs" << std::endl;
    }
    
    // 總體評估
    std::cout << "\n=== 總體評估 ===" << std::endl;
    
    int score = 0;
    if (stats.detection_rate >= 0.90) score += 40;
    else if (stats.detection_rate >= 0.80) score += 30;
    else if (stats.detection_rate >= 0.70) score += 20;
    else score += 10;
    
    if (stats.false_positive_rate <= 0.05) score += 30;
    else if (stats.false_positive_rate <= 0.10) score += 20;
    else if (stats.false_positive_rate <= 0.20) score += 10;
    
    if (stats.average_detection_time_us <= 5) score += 30;
    else if (stats.average_detection_time_us <= 10) score += 20;
    else if (stats.average_detection_time_us <= 20) score += 10;
    
    std::cout << "安全評分: " << score << "/100" << std::endl;
    
    if (score >= 90) {
        std::cout << "🏆 優秀 - 引擎已準備好投入生產！" << std::endl;
    } else if (score >= 80) {
        std::cout << "✅ 良好 - 引擎表現良好，需要小幅改進" << std::endl;
    } else if (score >= 70) {
        std::cout << "⚠️  一般 - 引擎在投入生產前需要優化" << std::endl;
    } else if (score >= 60) {
        std::cout << "❌ 較差 - 引擎需要重大改進" << std::endl;
    } else {
        std::cout << "🚨 嚴重 - 引擎需要重大重構" << std::endl;
    }
    
    std::cout << "\n=== 攻擊測試套件完成 ===" << std::endl;
    
    return 0;
} 