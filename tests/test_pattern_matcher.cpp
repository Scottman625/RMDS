#include <gtest/gtest.h>
#include "pattern_matcher.hpp"

TEST(PatternMatcherTest, BasicInitialization) {
    PatternMatcher matcher;
    EXPECT_TRUE(true); // 基本構造測試
}

TEST(PatternMatcherTest, InitializeMethod) {
    PatternMatcher matcher;
    bool result = matcher.initialize();
    EXPECT_TRUE(result);
} 