#include "../include/utils/process_lists.hpp"
#include <algorithm>
#include <cctype>

namespace MemoryDetectionEngine {

// 高風險進程列表
const std::vector<std::string> ProcessLists::high_risk_processes_ = {
    "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe",
    "java.exe", "javaw.exe", "python.exe", "node.exe"
};

// 白名單進程列表（完全忽略檢測）
const std::vector<std::string> ProcessLists::whitelist_processes_ = {
    "ipf_uf.exe", "ipf_ufd.exe", "ipf_ufw.exe", "ipf_ufs.exe",
    "rundll32.exe", "dllhost.exe", "svchost.exe", "lsass.exe",
    "winlogon.exe", "services.exe", "wininit.exe", "csrss.exe",
    "smss.exe", "ntoskrnl.exe", "explorer.exe", "taskmgr.exe",
    "cmd.exe", "powershell.exe", "ssh-agent.exe", "ssh.exe",
    "git.exe", "wsl.exe", "bash.exe", "conhost.exe", "dwm.exe",
    "ctfmon.exe", "spoolsv.exe", "openvpnserv.exe", "openvpn.exe",
    "nvcontainer.exe", "nvcpl.exe", "nvxdsync.exe",
    "nvidia-smi.exe", "nvbackend.exe", "nvwgf2umx.dll", "nvapi64.dll",
    "fnplicensingservice.exe", "httpd.exe", "sqlwriter.exe", "vmnat.exe",
    "killeranalyticsservice.exe","ipfsvc.exe",
    "KillerAnalyticsService.exe", "KillerAnalyticsService64.exe"
};

// 系統進程列表（擴展）
const std::vector<std::string> ProcessLists::system_processes_ = {
    "svchost.exe", "lsass.exe", "winlogon.exe", "services.exe",
    "wininit.exe", "csrss.exe", "smss.exe", "ntoskrnl.exe",
    "explorer.exe", "taskmgr.exe", "cmd.exe", "powershell.exe",
    "ssh-agent.exe", "ssh.exe", "git.exe", "wsl.exe", "bash.exe",
    "conhost.exe", "dwm.exe", "ctfmon.exe", "spoolsv.exe",
    "rundll32.exe", "dllhost.exe", "fnplicensingservice.exe"
};

const std::vector<std::string>& ProcessLists::get_high_risk_processes() {
    return high_risk_processes_;
}

const std::vector<std::string>& ProcessLists::get_whitelist_processes() {
    return whitelist_processes_;
}

const std::vector<std::string>& ProcessLists::get_system_processes() {
    return system_processes_;
}

bool ProcessLists::is_high_risk_process(const std::string& process_name) {
    std::string lower_name = to_lower(process_name);
    
    for (const auto& high_risk : high_risk_processes_) {
        if (lower_name.find(high_risk) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool ProcessLists::is_whitelisted_process(const std::string& process_name) {
    std::string lower_name = to_lower(process_name);
    
    for (const auto& whitelist : whitelist_processes_) {
        if (lower_name.find(whitelist) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool ProcessLists::is_system_process(const std::string& process_name) {
    std::string lower_name = to_lower(process_name);
    
    for (const auto& system_proc : system_processes_) {
        if (lower_name.find(system_proc) != std::string::npos) {
            return true;
        }
    }
    return false;
}

ProcessCategory ProcessLists::classify_process(const std::string& process_name) {
    std::string lower_name = to_lower(process_name);
    
    // 更精確的攻擊模擬器識別
    if (lower_name.find("attack") != std::string::npos ||
        lower_name.find("simulator") != std::string::npos ||
        lower_name.find("attack_simulator") != std::string::npos ||
        lower_name.find("simple_attack") != std::string::npos ||
        lower_name.find("real_detection_engine") != std::string::npos) {
        return ProcessCategory::ATTACK_SIMULATOR;
    }
    
    // 高風險進程識別
    if (is_high_risk_process(process_name)) {
        return ProcessCategory::HIGH_RISK_PROCESS;
    }
    
    // 系統進程識別
    if (is_system_process(process_name)) {
        return ProcessCategory::SYSTEM_PROCESS;
    }
    
    // 默認為用戶進程
    return ProcessCategory::USER_PROCESS;
}

std::string ProcessLists::to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

} // namespace MemoryDetectionEngine
