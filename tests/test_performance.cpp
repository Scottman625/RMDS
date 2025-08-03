#include <gtest/gtest.h>
#include <chrono>
#include <thread>

TEST(PerformanceTest, BasicTiming) {
    auto start = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    EXPECT_GT(duration.count(), 0);
} 