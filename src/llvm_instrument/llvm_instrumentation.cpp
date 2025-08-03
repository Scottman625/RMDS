#include "llvm_instrumentation.hpp"
#include "utils/logger.hpp"

namespace MemoryDetectionEngine {

// LLVMInstrumentation實現
LLVMInstrumentation::LLVMInstrumentation() {
    LOG_INFO("LLVM Instrumentation initialized");
}

LLVMInstrumentation::~LLVMInstrumentation() {
    LOG_INFO("LLVM Instrumentation destroyed");
}

bool LLVMInstrumentation::initialize() {
    LOG_INFO("LLVM Instrumentation: Initializing");
    // 在Windows上，LLVM插樁可能不可用
    return false;
}

void LLVMInstrumentation::cleanup() {
    LOG_INFO("LLVM Instrumentation: Cleaning up");
}

bool LLVMInstrumentation::is_enabled() const {
    return false;
}

void LLVMInstrumentation::set_enabled(bool enabled) {
    LOG_INFO("LLVM Instrumentation: Setting enabled to {}", enabled);
}

} // namespace MemoryDetectionEngine

// 導出符號以避免鏈接錯誤
extern "C" {
    void llvm_instrumentation_init() {
        // 初始化LLVM插樁
    }
} 