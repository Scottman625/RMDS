#include "attack_test_framework.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <cstring>
#include <vector>
#include <string>

using namespace MemoryDetectionEngine;

// ============================================================================
// ROP 攻擊測試
// ============================================================================

class ROPChainTest : public AttackTest {
public:
    std::string get_name() const override { return "ROP Chain Attack"; }
    AttackType get_type() const override { return AttackType::ROP_CHAIN; }
    std::string get_description() const override { 
        return "Simulates Return-Oriented Programming chain execution"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 模擬 ROP 鏈攻擊
        std::vector<uint64_t> rop_chain = {
            0x401000, 0x401010, 0x401020, 0x401030, 0x401040,
            0x401050, 0x401060, 0x401070, 0x401080, 0x401090
        };
        
        // 模擬堆棧溢出
        char buffer[64];
        std::memset(buffer, 'A', sizeof(buffer));
        
        // 模擬覆蓋返回地址
        uint64_t* ret_addr = reinterpret_cast<uint64_t*>(buffer + 64);
        for (size_t i = 0; i < rop_chain.size(); ++i) {
            ret_addr[i] = rop_chain[i];
        }
        
        // 模擬執行 ROP 鏈
        for (uint64_t addr : rop_chain) {
            // 模擬 gadget 執行
            simulate_gadget_execution(addr);
        }
        
        success_count_++;
        return true;
    }
    
private:
    void simulate_gadget_execution(uint64_t addr) {
        // 模擬 gadget 執行邏輯
        volatile uint64_t dummy = addr;
        (void)dummy; // 避免編譯器警告
    }
};

// ============================================================================
// JOP 攻擊測試
// ============================================================================

class JOPChainTest : public AttackTest {
public:
    std::string get_name() const override { return "JOP Chain Attack"; }
    AttackType get_type() const override { return AttackType::JOP_CHAIN; }
    std::string get_description() const override { 
        return "Simulates Jump-Oriented Programming chain execution"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 模擬 JOP 鏈攻擊
        std::vector<uint64_t> jop_chain = {
            0x402000, 0x402010, 0x402020, 0x402030, 0x402040,
            0x402050, 0x402060, 0x402070, 0x402080, 0x402090
        };
        
        // 模擬間接跳轉
        for (uint64_t addr : jop_chain) {
            simulate_indirect_jump(addr);
        }
        
        success_count_++;
        return true;
    }
    
private:
    void simulate_indirect_jump(uint64_t addr) {
        // 模擬間接跳轉邏輯
        volatile uint64_t jump_target = addr;
        (void)jump_target;
    }
};

// ============================================================================
// 記憶體破壞測試
// ============================================================================

class MemoryCorruptionTest : public AttackTest {
public:
    std::string get_name() const override { return "Memory Corruption Attack"; }
    AttackType get_type() const override { return AttackType::MEMORY_CORRUPTION; }
    std::string get_description() const override { 
        return "Simulates memory corruption attack"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 分配記憶體
        char* buffer = new char[1024];
        
        // 模擬記憶體破壞
        for (int i = 0; i < 1024; ++i) {
            buffer[i] = static_cast<char>(i % 256);
        }
        
        // 模擬越界寫入
        for (int i = 1024; i < 2048; ++i) {
            buffer[i] = 0x41; // 'A'
        }
        
        // 模擬破壞堆結構
        uint64_t* heap_meta = reinterpret_cast<uint64_t*>(buffer - 16);
        heap_meta[0] = 0xDEADBEEF;
        heap_meta[1] = 0xCAFEBABE;
        
        delete[] buffer;
        success_count_++;
        return true;
    }
};

// ============================================================================
// 緩衝區溢出測試
// ============================================================================

class BufferOverflowTest : public AttackTest {
public:
    std::string get_name() const override { return "Buffer Overflow Attack"; }
    AttackType get_type() const override { return AttackType::BUFFER_OVERFLOW; }
    std::string get_description() const override { 
        return "Simulates buffer overflow attack"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 創建小緩衝區
        char small_buffer[16];
        
        // 模擬緩衝區溢出
        std::string large_string = "This is a very long string that will overflow the buffer";
        std::strcpy(small_buffer, large_string.c_str());
        
        // 模擬覆蓋相鄰記憶體
        uint64_t* adjacent_var = reinterpret_cast<uint64_t*>(small_buffer + 16);
        *adjacent_var = 0x4141414141414141;
        
        success_count_++;
        return true;
    }
};

// ============================================================================
// Use-After-Free 測試
// ============================================================================

class UseAfterFreeTest : public AttackTest {
public:
    std::string get_name() const override { return "Use-After-Free Attack"; }
    AttackType get_type() const override { return AttackType::USE_AFTER_FREE; }
    std::string get_description() const override { 
        return "Simulates use-after-free attack"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 分配記憶體
        char* ptr = new char[256];
        std::memset(ptr, 0x42, 256);
        
        // 釋放記憶體
        delete[] ptr;
        
        // 模擬使用已釋放的記憶體
        ptr[0] = 0x41;
        ptr[1] = 0x42;
        ptr[2] = 0x43;
        
        // 模擬讀取已釋放的記憶體
        volatile char dummy = ptr[0];
        (void)dummy;
        
        success_count_++;
        return true;
    }
};

// ============================================================================
// Double Free 測試
// ============================================================================

class DoubleFreeTest : public AttackTest {
public:
    std::string get_name() const override { return "Double Free Attack"; }
    AttackType get_type() const override { return AttackType::DOUBLE_FREE; }
    std::string get_description() const override { 
        return "Simulates double free attack"; 
    }
    bool should_be_detected() const override { return true; }
    
    bool execute() override {
        attack_count_++;
        
        // 分配記憶體
        char* ptr = new char[128];
        std::memset(ptr, 0x43, 128);
        
        // 第一次釋放
        delete[] ptr;
        
        // 第二次釋放（Double Free）
        delete[] ptr;
        
        success_count_++;
        return true;
    }
};

// ============================================================================
// 攻擊測試管理器實現
// ============================================================================

AttackTestManager::AttackTestManager(const AttackTestConfig& config)
    : config_(config), gen_(rd_()) {
}

AttackTestManager::~AttackTestManager() = default;

void AttackTestManager::add_test(std::unique_ptr<AttackTest> test) {
    tests_.push_back(std::move(test));
}

std::vector<AttackResult> AttackTestManager::run_all_tests() {
    std::vector<AttackResult> results;
    
    for (const auto& test : tests_) {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        bool executed = test->execute();
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        
        AttackResult result;
        result.type = test->get_type();
        result.detected = executed && test->should_be_detected();
        result.detection_time_us = duration.count();
        result.description = test->get_description();
        result.confidence = test->get_success_rate();
        result.false_positive = executed && !test->should_be_detected();
        
        results.push_back(result);
        
        if (config_.verbose_output) {
            std::cout << "Executed: " << test->get_name() 
                      << " - Detected: " << (result.detected ? "YES" : "NO")
                      << " - Time: " << result.detection_time_us << " us" << std::endl;
        }
    }
    
    return results;
}

std::vector<AttackResult> AttackTestManager::run_tests_by_type(AttackType type) {
    std::vector<AttackResult> results;
    
    for (const auto& test : tests_) {
        if (test->get_type() == type) {
            auto start_time = std::chrono::high_resolution_clock::now();
            
            bool executed = test->execute();
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            
            AttackResult result;
            result.type = test->get_type();
            result.detected = executed && test->should_be_detected();
            result.detection_time_us = duration.count();
            result.description = test->get_description();
            result.confidence = test->get_success_rate();
            result.false_positive = executed && !test->should_be_detected();
            
            results.push_back(result);
        }
    }
    
    return results;
}

void AttackTestManager::generate_report(const std::vector<AttackResult>& results) {
    auto stats = get_stats(results);
    
    std::cout << "\n=== Attack Test Report ===" << std::endl;
    std::cout << "Total Attacks: " << stats.total_attacks << std::endl;
    std::cout << "Detected Attacks: " << stats.detected_attacks << std::endl;
    std::cout << "False Positives: " << stats.false_positives << std::endl;
    std::cout << "Detection Rate: " << (stats.detection_rate * 100) << "%" << std::endl;
    std::cout << "False Positive Rate: " << (stats.false_positive_rate * 100) << "%" << std::endl;
    std::cout << "Average Detection Time: " << stats.average_detection_time_us << " us" << std::endl;
    
    std::cout << "\n=== Detailed Results ===" << std::endl;
    for (const auto& result : results) {
        std::cout << "- " << result.description 
                  << " (Detected: " << (result.detected ? "YES" : "NO")
                  << ", Time: " << result.detection_time_us << " us)" << std::endl;
    }
}

AttackTestManager::TestStats AttackTestManager::get_stats(const std::vector<AttackResult>& results) const {
    TestStats stats = {};
    
    for (const auto& result : results) {
        stats.total_attacks++;
        
        if (result.detected) {
            stats.detected_attacks++;
        }
        
        if (result.false_positive) {
            stats.false_positives++;
        }
        
        stats.average_detection_time_us += result.detection_time_us;
    }
    
    if (stats.total_attacks > 0) {
        stats.detection_rate = (double)stats.detected_attacks / stats.total_attacks;
        stats.false_positive_rate = (double)stats.false_positives / stats.total_attacks;
        stats.average_detection_time_us /= stats.total_attacks;
    }
    
    return stats;
} 