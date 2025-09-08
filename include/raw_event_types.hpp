#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <chrono>

namespace RealMemoryDetection {

// 原始事件來源枚舉
enum class RawEventSource : uint8_t {
    API_HOOK = 0,    // 來自 API Hook
    ETW = 1,         // 來自 ETW 事件
    KERNEL = 2,      // 來自內核回調
    FALLBACK_SCAN = 3 // 來自後備掃描
};

// 原始事件類型枚舉
enum class RawEventKind : uint8_t {
    ALLOC = 0,           // 記憶體分配
    PROTECT = 1,         // 保護變更
    WRITE = 2,           // 記憶體寫入
    REMOTE_THREAD = 3,   // 遠程線程創建
    IMAGE_LOAD = 4,      // 映像載入
    PROCESS_CREATE = 5,  // 進程創建
    PROCESS_EXIT = 6,    // 進程退出
    FREE = 7,            // 記憶體釋放
    CUSTOM = 8           // 自定義事件
};

// 原始事件結構 - 設計為固定大小以支持無鎖操作
struct RawEvent {
    RawEventSource source;
    RawEventKind kind;
    uint32_t pid;
    uint32_t tid;
    uint64_t base;
    uint64_t size;
    uint32_t old_protect;
    uint32_t new_protect;
    uint64_t aux;          // 可放 startAddress / bytesWritten / hash
    uint64_t ts_qpc;       // 高精度時間戳 (QueryPerformanceCounter)
    uint32_t stack_hash;   // call stack hash
    uint8_t flags;         // bit: cross_process, suspicious_hint...
    uint8_t reserved[3];   // 對齊到 64 字節邊界
    
    // 靜態方法：創建各種類型的事件
    static RawEvent make_alloc(uint32_t pid, uint64_t base, uint64_t size, uint32_t protect, uint64_t ts_qpc) {
        RawEvent ev{};
        ev.source = RawEventSource::API_HOOK;
        ev.kind = RawEventKind::ALLOC;
        ev.pid = pid;
        ev.base = base;
        ev.size = size;
        ev.new_protect = protect;
        ev.ts_qpc = ts_qpc;
        return ev;
    }
    
    static RawEvent make_protect(uint32_t pid, uint64_t base, uint64_t size, uint32_t old_protect, uint32_t new_protect, uint64_t ts_qpc) {
        RawEvent ev{};
        ev.source = RawEventSource::API_HOOK;
        ev.kind = RawEventKind::PROTECT;
        ev.pid = pid;
        ev.base = base;
        ev.size = size;
        ev.old_protect = old_protect;
        ev.new_protect = new_protect;
        ev.ts_qpc = ts_qpc;
        return ev;
    }
    
    static RawEvent make_write(uint32_t pid, uint64_t base, uint64_t size, uint64_t bytes_written, uint64_t ts_qpc) {
        RawEvent ev{};
        ev.source = RawEventSource::API_HOOK;
        ev.kind = RawEventKind::WRITE;
        ev.pid = pid;
        ev.base = base;
        ev.size = size;
        ev.aux = bytes_written;
        ev.ts_qpc = ts_qpc;
        return ev;
    }
    
    static RawEvent make_remote_thread(uint32_t source_pid, uint32_t target_pid, uint64_t start_address, uint64_t ts_qpc) {
        RawEvent ev{};
        ev.source = RawEventSource::API_HOOK;
        ev.kind = RawEventKind::REMOTE_THREAD;
        ev.pid = source_pid;
        ev.tid = target_pid;  // 重用 tid 欄位存儲目標 PID
        ev.aux = start_address;
        ev.ts_qpc = ts_qpc;
        ev.flags = 1;  // 標記為跨進程
        return ev;
    }
};

// 頁面狀態結構
struct PageState {
    uint64_t base;
    uint32_t pid;
    uint32_t last_protect;
    uint64_t first_seen_qpc;
    uint64_t last_write_qpc;
    uint64_t exec_transition_qpc;
    uint32_t write_count;
    uint8_t flags; // bit0: seen_write, bit1: seen_exec, bit2: integrity_done
    uint32_t pre_exec_hash;
    
    PageState() : base(0), pid(0), last_protect(0), first_seen_qpc(0), 
                  last_write_qpc(0), exec_transition_qpc(0), write_count(0), 
                  flags(0), pre_exec_hash(0) {}
};

// 頁面轉換事件
struct PageTransitionEvent {
    uint32_t pid;
    uint64_t base;
    uint32_t old_protect;
    uint32_t new_protect;
    uint64_t timestamp_qpc;
    bool is_suspicious;
    uint32_t suspicion_score;
    
    PageTransitionEvent() : pid(0), base(0), old_protect(0), new_protect(0), 
                           timestamp_qpc(0), is_suspicious(false), suspicion_score(0) {}
};

// 跨進程寫入事件
struct CrossProcessWriteEvent {
    uint32_t source_pid;
    uint32_t target_pid;
    uint64_t base;
    uint64_t size;
    uint64_t timestamp_qpc;
    bool is_suspicious;
    
    CrossProcessWriteEvent() : source_pid(0), target_pid(0), base(0), size(0), 
                              timestamp_qpc(0), is_suspicious(false) {}
};

// 遠程執行鏈事件
struct RemoteExecutionChainEvent {
    uint32_t source_pid;
    uint32_t target_pid;
    uint64_t start_address;
    uint64_t timestamp_qpc;
    bool is_suspicious;
    uint32_t suspicion_score;
    
    RemoteExecutionChainEvent() : source_pid(0), target_pid(0), start_address(0), 
                                 timestamp_qpc(0), is_suspicious(false), suspicion_score(0) {}
};

// 暗執行事件（發現 EXEC page 無 prior events）
struct DarkExecEvent {
    uint32_t pid;
    uint64_t base;
    uint64_t size;
    uint64_t timestamp_qpc;
    uint32_t suspicion_score;
    
    DarkExecEvent() : pid(0), base(0), size(0), timestamp_qpc(0), suspicion_score(0) {}
};

// 工具函數
namespace RawEventUtils {
    // 獲取高精度時間戳
    inline uint64_t get_timestamp_qpc() {
        LARGE_INTEGER li;
        QueryPerformanceCounter(&li);
        return li.QuadPart;
    }
    
    // 計算簡單的 call stack hash
    inline uint32_t calculate_stack_hash(uint32_t max_depth = 6) {
        void* stack[10];
        WORD frames = CaptureStackBackTrace(0, max_depth, stack, nullptr);
        uint32_t hash = 0x811c9dc5; // FNV-1a 初始值
        for (WORD i = 0; i < frames; i++) {
            hash ^= (uint32_t)((uint64_t)stack[i] & 0xFFFFFFFF);
            hash *= 0x01000193; // FNV-1a 質數
        }
        return hash;
    }
    
    // 檢查是否為可疑的保護轉換
    inline bool is_suspicious_protection_transition(uint32_t old_protect, uint32_t new_protect) {
        // RW -> RX 轉換
        if ((old_protect & PAGE_READWRITE) && (new_protect & PAGE_EXECUTE_READ)) {
            return true;
        }
        // 直接分配 RWX
        if (new_protect == PAGE_EXECUTE_READWRITE) {
            return true;
        }
        return false;
    }
}

} // namespace RealMemoryDetection
