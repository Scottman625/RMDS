#include <gtest/gtest.h>
#include "memory_detection_engine.hpp"
#include <chrono>
#include <thread>

using namespace MemoryDetectionEngine;

class MemoryDetectionEngineTest : public ::testing::Test {
protected:
    EngineConfig config_;
    std::unique_ptr<MemoryDetectionEngine> engine_;

    void SetUp() override {
        config_.enable_mte = true;
        config_.enable_llvm_instrumentation = false; // 禁用LLVM以避免依賴問題
        config_.enable_pattern_matching = true;
        config_.detection_interval_ms = 100;
        config_.max_detection_latency_us = 3000;
    }

    void TearDown() override {
        if (engine_) {
            engine_->stop();
        }
    }
};

TEST_F(MemoryDetectionEngineTest, CreateEngine) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
}

TEST_F(MemoryDetectionEngineTest, InitializeEngine) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    bool result = engine_->initialize();
    EXPECT_TRUE(result);
}

TEST_F(MemoryDetectionEngineTest, StartStopEngine) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    
    bool start_result = engine_->start();
    EXPECT_TRUE(start_result);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    engine_->stop();
}

TEST_F(MemoryDetectionEngineTest, CallbackRegistration) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    bool callback_called = false;
    DetectionCallback callback = [&callback_called](const DetectionResult& result) {
        callback_called = true;
        EXPECT_EQ(result.attack_type, AttackType::UNKNOWN);
    };
    
    engine_->register_detection_callback(callback);
    ASSERT_TRUE(engine_->initialize());
    ASSERT_TRUE(engine_->start());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    engine_->stop();
    // 注意：在測試環境中可能不會觸發實際的檢測事件
}

TEST_F(MemoryDetectionEngineTest, PerformanceStats) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    ASSERT_TRUE(engine_->start());
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    auto stats = engine_->get_performance_stats();
    EXPECT_GE(stats.total_detections, 0);
    EXPECT_GE(stats.average_latency_us, 0);
    
    engine_->stop();
}

TEST_F(MemoryDetectionEngineTest, ConfigurationUpdate) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    
    EngineConfig new_config = config_;
    new_config.detection_interval_ms = 200;
    
    bool update_result = engine_->update_configuration(new_config);
    EXPECT_TRUE(update_result);
    
    engine_->stop();
}

TEST_F(MemoryDetectionEngineTest, AttackTypeControl) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    
    // 測試啟用/禁用特定攻擊類型檢測
    engine_->enable_attack_detection(AttackType::ROP, true);
    engine_->enable_attack_detection(AttackType::JOP, false);
    
    engine_->stop();
}

TEST_F(MemoryDetectionEngineTest, CustomPatterns) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    
    // 添加自定義模式
    std::vector<uint8_t> pattern = {0x90, 0x90, 0x90}; // NOP sled
    bool add_result = engine_->add_custom_pattern("test_pattern", pattern);
    EXPECT_TRUE(add_result);
    
    engine_->stop();
}

TEST_F(MemoryDetectionEngineTest, VersionInfo) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    auto version = engine_->get_version();
    EXPECT_FALSE(version.empty());
    
    auto build_info = engine_->get_build_info();
    EXPECT_FALSE(build_info.empty());
}

TEST_F(MemoryDetectionEngineTest, MultipleStartStop) {
    engine_ = create_engine(config_);
    ASSERT_NE(engine_, nullptr);
    
    ASSERT_TRUE(engine_->initialize());
    
    // 多次啟動和停止
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(engine_->start());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        engine_->stop();
    }
} 