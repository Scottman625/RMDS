#pragma once

#include <windows.h>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include "memory_detection_utils.hpp"
#include "memory_detection_veh.hpp"
#include "memory_detection_monitor.hpp"

namespace RealMemoryDetection {

// 真實記憶體攻擊檢測引擎類
class RealMemoryDetectionEngine {
public:
    using AttackCallback = std::function<void(const DetectionResult&)>;
    
    // 構造函數
    explicit RealMemoryDetectionEngine(const EngineConfig& config = EngineConfig{});
    
    // 析構函數
    virtual ~RealMemoryDetectionEngine();
    
    // 啟動引擎
    virtual bool start();
    
    // 停止引擎
    virtual void stop();
    
    // 檢查是否正在運行
    bool is_running() const;
    
    // 顯示狀態
    void show_status();
    
    // 獲取統計信息
    EngineStats get_stats() const;
    
    // 獲取檢測結果
    std::vector<DetectionResult> get_detection_results() const;
    
    // 設置攻擊回調
    void set_attack_callback(AttackCallback callback);
    
    // 模擬攻擊檢測（用於測試）
    void simulate_attack_detection(AttackType type, uint64_t address, 
                                 const std::string& description, double confidence);
    
    // 啟用DEP
    bool enable_dep();
    
    // 啟用ASLR
    bool enable_aslr();
    
    // 檢查系統安全設置
    bool check_system_security_settings();
    
    // 生成報告
    void generate_report(const std::string& filename);
    
    // 導出檢測結果
    void export_detection_results(const std::string& filename);
    
    // 清理舊的檢測結果
    void cleanup_old_detection_results(std::chrono::hours max_age = std::chrono::hours(24));
    
    // 重置統計
    void reset_stats();
    
    // 獲取配置
    EngineConfig get_config() const;
    
    // 更新配置
    void update_config(const EngineConfig& config);

private:
    // 檢測迴圈
    void detection_loop();
    
    // 初始化組件
    bool initialize_components();
    
    // 清理組件
    void cleanup_components();
    
    // 處理攻擊檢測
    void handle_attack_detection(const DetectionResult& result);
    
    // 記錄檢測結果
    void log_detection_result(const DetectionResult& result);
    
    // 更新統計
    void update_stats(const DetectionResult& result);
    
    // 檢查系統資源
    void check_system_resources();
    
    // 執行定期維護
    void perform_maintenance();
    
    // 組件指針
    std::unique_ptr<VEHHandler> veh_handler_;
    //std::unique_ptr<MemoryMonitor> memory_monitor_;
    std::unique_ptr<Logger> logger_;
    
    // 配置
    EngineConfig config_;
    
    // 運行標誌
    std::atomic<bool> running_;
    
    // 檢測線程
    std::thread detection_thread_;
    
    // 攻擊回調
    AttackCallback attack_callback_;
    
    // 檢測結果
    std::vector<DetectionResult> detection_results_;
    
    // 統計信息
    EngineStats stats_;
    
    // 互斥鎖
    mutable std::mutex results_mutex_;
    mutable std::mutex stats_mutex_;
    
    // 最後維護時間
    std::chrono::system_clock::time_point last_maintenance_;
    
    // 維護間隔
    std::chrono::minutes maintenance_interval_;
};

// 工廠函數
std::unique_ptr<RealMemoryDetectionEngine> create_engine(const EngineConfig& config = EngineConfig{});

} // namespace RealMemoryDetection 