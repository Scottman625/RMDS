#pragma once

#include <atomic>
#include <cstdint>
#include <cassert>
#include "raw_event_types.hpp"

namespace RealMemoryDetection {

// 無鎖 RingBuffer 模板類
template<typename T, size_t Capacity>
class LockFreeRingBuffer {
    static_assert(Capacity > 0 && (Capacity & (Capacity - 1)) == 0, 
                  "Capacity must be a power of 2 for efficient modulo operation");
    
private:
    T buffer_[Capacity];
    std::atomic<uint64_t> head_{0};  // 寫入位置
    std::atomic<uint64_t> tail_{0};  // 讀取位置
    
    // 用於統計
    std::atomic<uint64_t> push_count_{0};
    std::atomic<uint64_t> pop_count_{0};
    std::atomic<uint64_t> overflow_count_{0};
    
public:
    static constexpr size_t capacity = Capacity;
    static constexpr size_t mask = Capacity - 1;
    
    LockFreeRingBuffer() = default;
    ~LockFreeRingBuffer() = default;
    
    // 禁用複製
    LockFreeRingBuffer(const LockFreeRingBuffer&) = delete;
    LockFreeRingBuffer& operator=(const LockFreeRingBuffer&) = delete;
    
    // 嘗試推入一個元素
    bool try_push(const T& item) {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_acquire);
        
        // 檢查是否滿
        if (head - tail >= Capacity) {
            overflow_count_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        
        // 寫入元素
        buffer_[head & mask] = item;
        
        // 更新頭部指針
        head_.store(head + 1, std::memory_order_release);
        push_count_.fetch_add(1, std::memory_order_relaxed);
        
        return true;
    }
    
    // 嘗試彈出一個元素
    bool try_pop(T& item) {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t head = head_.load(std::memory_order_acquire);
        
        // 檢查是否空
        if (tail >= head) {
            return false;
        }
        
        // 讀取元素
        item = buffer_[tail & mask];
        
        // 更新尾部指針
        tail_.store(tail + 1, std::memory_order_release);
        pop_count_.fetch_add(1, std::memory_order_relaxed);
        
        return true;
    }
    
    // 批量彈出元素
    template<typename Container>
    size_t try_pop_batch(Container& items, size_t max_count) {
        size_t count = 0;
        T item;
        
        while (count < max_count && try_pop(item)) {
            items.push_back(item);
            count++;
        }
        
        return count;
    }
    
    // 檢查是否為空
    bool empty() const {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t head = head_.load(std::memory_order_relaxed);
        return tail >= head;
    }
    
    // 檢查是否為滿
    bool full() const {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        return head - tail >= Capacity;
    }
    
    // 獲取當前大小
    size_t size() const {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        return static_cast<size_t>(head - tail);
    }
    
    // 獲取可用空間
    size_t available() const {
        return Capacity - size();
    }
    
    // 清空緩衝區
    void clear() {
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
    }
    
    // 獲取統計信息
    struct Stats {
        uint64_t push_count;
        uint64_t pop_count;
        uint64_t overflow_count;
        size_t current_size;
        size_t available_space;
    };
    
    Stats get_stats() const {
        Stats stats;
        stats.push_count = push_count_.load(std::memory_order_relaxed);
        stats.pop_count = pop_count_.load(std::memory_order_relaxed);
        stats.overflow_count = overflow_count_.load(std::memory_order_relaxed);
        stats.current_size = size();
        stats.available_space = available();
        return stats;
    }
    
    // 重置統計信息
    void reset_stats() {
        push_count_.store(0, std::memory_order_relaxed);
        pop_count_.store(0, std::memory_order_relaxed);
        overflow_count_.store(0, std::memory_order_relaxed);
    }
};

// 專門用於 RawEvent 的 RingBuffer 類型別名
using RawEventRingBuffer = LockFreeRingBuffer<RawEvent, 65536>; // 64K 事件容量

// 多生產者單消費者 RingBuffer（使用 CAS 操作）
template<typename T, size_t Capacity>
class MPSCRingBuffer {
    static_assert(Capacity > 0 && (Capacity & (Capacity - 1)) == 0, 
                  "Capacity must be a power of 2");
    
private:
    T buffer_[Capacity];
    std::atomic<uint64_t> head_{0};
    std::atomic<uint64_t> tail_{0};
    
    // 統計
    std::atomic<uint64_t> push_count_{0};
    std::atomic<uint64_t> pop_count_{0};
    std::atomic<uint64_t> overflow_count_{0};
    
public:
    static constexpr size_t capacity = Capacity;
    static constexpr size_t mask = Capacity - 1;
    
    MPSCRingBuffer() = default;
    ~MPSCRingBuffer() = default;
    
    // 多生產者推入（使用 CAS）
    bool try_push(const T& item) {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_acquire);
        
        if (head - tail >= Capacity) {
            overflow_count_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        
        // 使用 CAS 確保原子性
        uint64_t new_head = head + 1;
        if (!head_.compare_exchange_weak(head, new_head, std::memory_order_release)) {
            return false; // 競爭失敗，重試
        }
        
        buffer_[head & mask] = item;
        push_count_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    
    // 單消費者彈出
    bool try_pop(T& item) {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t head = head_.load(std::memory_order_acquire);
        
        if (tail >= head) {
            return false;
        }
        
        item = buffer_[tail & mask];
        tail_.store(tail + 1, std::memory_order_release);
        pop_count_.fetch_add(1, std::memory_order_relaxed);
        
        return true;
    }
    
    // 其他方法與 LockFreeRingBuffer 相同
    bool empty() const {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t head = head_.load(std::memory_order_relaxed);
        return tail >= head;
    }
    
    bool full() const {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        return head - tail >= Capacity;
    }
    
    size_t size() const {
        uint64_t head = head_.load(std::memory_order_relaxed);
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        return static_cast<size_t>(head - tail);
    }
    
    size_t available() const {
        return Capacity - size();
    }
    
    void clear() {
        head_.store(0, std::memory_order_relaxed);
        tail_.store(0, std::memory_order_relaxed);
    }
    
    struct Stats {
        uint64_t push_count;
        uint64_t pop_count;
        uint64_t overflow_count;
        size_t current_size;
        size_t available_space;
    };
    
    Stats get_stats() const {
        Stats stats;
        stats.push_count = push_count_.load(std::memory_order_relaxed);
        stats.pop_count = pop_count_.load(std::memory_order_relaxed);
        stats.overflow_count = overflow_count_.load(std::memory_order_relaxed);
        stats.current_size = size();
        stats.available_space = available();
        return stats;
    }
    
    void reset_stats() {
        push_count_.store(0, std::memory_order_relaxed);
        pop_count_.store(0, std::memory_order_relaxed);
        overflow_count_.store(0, std::memory_order_relaxed);
    }
};

// 專門用於 RawEvent 的 MPSC RingBuffer
using RawEventMPSCRingBuffer = MPSCRingBuffer<RawEvent, 65536>;

} // namespace RealMemoryDetection
