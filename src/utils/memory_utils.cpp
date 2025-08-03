#include "utils/logger.hpp"
#include <windows.h>

class MemoryUtils {
public:
    static void* allocate_memory(size_t size) {
        void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (ptr) {
            LOG_INFO("Memory allocated: {} bytes at {}", size, ptr);
        } else {
            LOG_ERROR("Failed to allocate memory: {} bytes", size);
        }
        return ptr;
    }

    static void free_memory(void* ptr) {
        if (ptr) {
            VirtualFree(ptr, 0, MEM_RELEASE);
            LOG_INFO("Memory freed at {}", ptr);
        }
    }
};

// 導出符號以避免鏈接錯誤
extern "C" {
    void memory_utils_init() {
        // 初始化內存工具
    }
} 