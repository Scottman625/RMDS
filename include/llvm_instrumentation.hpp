#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <functional>

namespace MemoryDetectionEngine {

// LLVM前向聲明
namespace llvm {
    class Module;
    class Function;
    class BasicBlock;
    class Instruction;
    class Pass;
    class LLVMContext;
}

/**
 * @brief 插樁類型
 */
enum class InstrumentationType {
    STACK_POINTER_TRACKING,  // 堆棧指針追蹤
    RETURN_ADDRESS_TRACKING, // 返回地址追蹤
    CALL_SITE_TRACKING,      // 調用點追蹤
    MEMORY_ACCESS_TRACKING,  // 內存訪問追蹤
    CONTROL_FLOW_TRACKING    // 控制流追蹤
};

/**
 * @brief 插樁配置結構
 */
struct InstrumentationConfig {
    bool enable_stack_tracking = true;
    bool enable_return_tracking = true;
    bool enable_call_tracking = true;
    bool enable_memory_tracking = true;
    bool enable_control_flow_tracking = true;
    uint32_t max_tracking_depth = 1000;
    bool enable_optimization = true;
    std::string output_file = "";
    std::string log_level = "INFO";
};

/**
 * @brief 追蹤事件類型
 */
enum class TrackingEventType {
    FUNCTION_ENTER,      // 函數進入
    FUNCTION_EXIT,       // 函數退出
    STACK_ALLOCATION,   // 堆棧分配
    STACK_DEALLOCATION, // 堆棧釋放
    RETURN_ADDRESS_READ, // 返回地址讀取
    CALL_SITE_EXECUTE,  // 調用點執行
    MEMORY_ACCESS,      // 內存訪問
    CONTROL_FLOW_CHANGE // 控制流改變
};

/**
 * @brief 追蹤事件信息
 */
struct TrackingEvent {
    TrackingEventType type;
    uint64_t timestamp;
    uint64_t address;
    uint64_t stack_pointer;
    uint64_t return_address;
    std::string function_name;
    std::string module_name;
    uint32_t thread_id;
    std::string additional_info;
};

/**
 * @brief 插樁統計信息
 */
struct InstrumentationStats {
    uint64_t total_events;
    uint64_t function_entries;
    uint64_t function_exits;
    uint64_t stack_allocations;
    uint64_t memory_accesses;
    uint64_t control_flow_changes;
    double average_processing_time_us;
    uint64_t memory_usage_bytes;
};

/**
 * @brief LLVM插樁管理器類
 * 負責基於LLVM的動態插樁和堆棧指針追蹤
 */
class LLVMInstrumentation {
public:
    LLVMInstrumentation();
    ~LLVMInstrumentation();
    
    bool initialize();
    void cleanup();
    
    // 添加缺失的方法
    bool is_enabled() const;
    void set_enabled(bool enabled);
    
    // 禁用複製構造和賦值
    LLVMInstrumentation(const LLVMInstrumentation&) = delete;
    LLVMInstrumentation& operator=(const LLVMInstrumentation&) = delete;
};

} // namespace MemoryDetectionEngine 