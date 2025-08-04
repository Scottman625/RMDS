#pragma once

#include <windows.h>
#include <functional>
#include <memory>
#include <vector>
#include <string>
#include "real_memory_detection_utils.hpp"

namespace RealMemoryDetection {

// Vectored Exception Handler類
class VEHHandler {
public:
    using ExceptionCallback = std::function<void(PEXCEPTION_POINTERS)>;
    
    VEHHandler();
    ~VEHHandler();
    
    // 安裝VEH
    bool install();
    
    // 卸載VEH
    void uninstall();
    
    // 設置異常回調
    void set_exception_callback(ExceptionCallback callback);
    
    // 處理訪問違規
    void handle_access_violation(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 處理堆疊溢出
    void handle_stack_overflow(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 處理保護頁違規
    void handle_guard_page_violation(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 處理非法指令
    void handle_illegal_instruction(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 處理除零錯誤
    void handle_divide_by_zero(PCONTEXT ctx, PEXCEPTION_POINTERS ExceptionInfo);
    
    // 檢測ROP攻擊
    bool detect_rop_attack(PCONTEXT ctx);
    
    // 檢測JOP攻擊
    bool detect_jop_attack(PCONTEXT ctx);
    
    // 檢測緩衝區溢出
    bool detect_buffer_overflow(PCONTEXT ctx);
    
    // 檢測堆積損壞
    bool detect_heap_corruption(PCONTEXT ctx);
    
    // 檢測shellcode注入
    bool detect_shellcode_injection(PCONTEXT ctx);
    
    // 獲取調用堆疊
    std::vector<uint64_t> get_call_stack(PCONTEXT ctx);
    
    // 分析記憶體區域
    MemoryRegion analyze_memory_region(LPVOID address);
    
    // 檢查記憶體保護
    bool check_memory_protection(LPVOID address, DWORD expected_protection);
    
    // 記錄異常信息
    void log_exception_info(PEXCEPTION_POINTERS ExceptionInfo, const std::string& description);
    
    // 生成檢測報告
    DetectionResult generate_detection_report(AttackType type, uint64_t address, 
                                           const std::string& description, double confidence);

private:
    static LONG WINAPI vectored_exception_handler(PEXCEPTION_POINTERS ExceptionInfo);
    
    // 靜態實例指針
    static VEHHandler* instance_;
    
    // 異常回調函數
    ExceptionCallback exception_callback_;
    
    // VEH句柄
    PVOID veh_handle_;
    
    // 是否已安裝
    bool installed_;
    
    // 日誌記錄器
    std::unique_ptr<Logger> logger_;
    
    // 檢測統計
    EngineStats stats_;
    
    // 配置
    EngineConfig config_;
};

} // namespace RealMemoryDetection 