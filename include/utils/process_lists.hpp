#pragma once
#include <vector>
#include <string>

namespace MemoryDetectionEngine {

// 進程分類枚舉
enum class ProcessCategory {
    SYSTEM_PROCESS,
    USER_PROCESS,
    ATTACK_SIMULATOR,
    HIGH_RISK_PROCESS
};

// 進程列表管理類
class ProcessLists {
public:
    // 獲取高風險進程列表
    static const std::vector<std::string>& get_high_risk_processes();
    
    // 獲取白名單進程列表
    static const std::vector<std::string>& get_whitelist_processes();
    
    // 獲取系統進程列表
    static const std::vector<std::string>& get_system_processes();
    
    // 檢查進程是否在高風險列表中
    static bool is_high_risk_process(const std::string& process_name);
    
    // 檢查進程是否在白名單中
    static bool is_whitelisted_process(const std::string& process_name);
    
    // 檢查進程是否為系統進程
    static bool is_system_process(const std::string& process_name);
    
    // 分類進程
    static ProcessCategory classify_process(const std::string& process_name);
    
    // 轉換進程名稱為小寫
    static std::string to_lower(const std::string& str);

private:
    // 高風險進程列表
    static const std::vector<std::string> high_risk_processes_;
    
    // 白名單進程列表（完全忽略檢測）
    static const std::vector<std::string> whitelist_processes_;
    
    // 系統進程列表（擴展）
    static const std::vector<std::string> system_processes_;
};

} // namespace MemoryDetectionEngine
