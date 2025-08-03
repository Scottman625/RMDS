#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <string>
#include <functional>

// 前向聲明
class MTEError;
class MTEStats;
class MTETagInfo;

namespace MemoryDetectionEngine {

/**
 * @brief MTE標籤類型
 */
enum class MTETagType {
    ALLOCATION,  // 分配標籤
    STACK,       // 堆棧標籤
    HEAP,        // 堆標籤
    CODE,        // 代碼標籤
    DATA         // 數據標籤
};

/**
 * @brief MTE配置結構
 */
struct MTEConfig {
    bool enable_mte = true;
    bool enable_tag_validation = true;
    bool enable_synchronous_mode = true;
    bool enable_asynchronous_mode = false;
    uint32_t tag_bits = 4;
    uint32_t max_tags = 16;
    std::string log_level = "INFO";
};

/**
 * @brief MTE標籤信息
 */
struct MTETagInfo {
    uint32_t tag_id;
    MTETagType type;
    uint64_t base_address;
    size_t size;
    bool is_valid;
    uint64_t creation_time;
};

/**
 * @brief MTE錯誤類型
 */
enum class MTEErrorType {
    TAG_MISMATCH,      // 標籤不匹配
    INVALID_TAG,       // 無效標籤
    TAG_OVERFLOW,      // 標籤溢出
    ACCESS_VIOLATION,  // 訪問違規
    UNKNOWN_ERROR      // 未知錯誤
};

/**
 * @brief MTE錯誤信息
 */
struct MTEError {
    MTEErrorType type;
    uint64_t address;
    uint32_t expected_tag;
    uint32_t actual_tag;
    uint64_t timestamp;
    std::string description;
};

/**
 * @brief MTE統計信息
 */
struct MTEStats {
    uint64_t total_allocations;
    uint64_t total_deallocations;
    uint64_t total_tag_validations;
    uint64_t total_errors;
    uint64_t memory_usage_bytes;
    double average_validation_time_us;
};

/**
 * @brief MTE管理器類
 * 負責管理硬件內存標籤擴展功能
 */
class MTEManager {
public:
    MTEManager();
    ~MTEManager();
    
    bool initialize();
    void cleanup();
    
    // 內存標籤相關功能
    bool enable_memory_tagging();
    bool disable_memory_tagging();
    bool is_memory_tagging_enabled() const;
    
    // 添加缺失的方法
    static bool is_supported();
    void register_error_callback(std::function<void(const MTEError&)> callback);
    MTEStats get_stats() const;
    
private:
    // 移除PIMPL，直接定義成員變數
    bool initialized_;
    bool memory_tagging_enabled_;
};

} // namespace MemoryDetectionEngine 