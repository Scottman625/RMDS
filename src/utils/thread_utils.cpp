#include "utils/logger.hpp"
#include <windows.h>
#include <thread>

class ThreadUtils {
public:
    static DWORD get_current_thread_id() {
        return GetCurrentThreadId();
    }

    static void sleep_ms(int milliseconds) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }
};

// 導出符號以避免鏈接錯誤
extern "C" {
    void thread_utils_init() {
        // 初始化線程工具
    }
} 