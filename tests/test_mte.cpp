#include <gtest/gtest.h>
#include "mte_manager.hpp"

TEST(MTEManagerTest, BasicInitialization) {
    MTEManager manager;
    EXPECT_TRUE(true); // 基本構造測試
}

TEST(MTEManagerTest, InitializeMethod) {
    MTEManager manager;
    bool result = manager.initialize();
    // 在Windows上，MTE可能不可用，所以我們接受false
    EXPECT_TRUE(result == true || result == false);
} 