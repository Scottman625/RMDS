#include <psapi.h>
#include <tlhelp32.h>
#include <cmath>
#include <deque>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <sstream>

namespace RealMemoryDetection {
    

// 統一的可執行頁面判斷函數
static inline bool is_executable_protect(DWORD p) {
    return (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// 追加：ret-like 判斷（涵蓋 ret, retf, ret imm16, iret）
static inline bool is_ret_like(uint8_t b) {
   return (b == 0xC3 /* ret */) || (b == 0xCB /* retf */) || (b == 0xC2 /* ret imm16 */) || (b == 0xCA /* retf imm16 */);
}

// 追加：burst 偵測的簡單時間窗口狀態（僅限本翻譯單元）
namespace {
   struct BurstState {
       std::deque<std::chrono::steady_clock::time_point> window;
       std::unordered_set<uint64_t> seen_pages; // 已計數過的頁面（避免重複）
       std::chrono::steady_clock::time_point last_alert_time{};
   };
   static std::mutex g_burst_mutex;
   static std::unordered_map<DWORD, BurstState> g_burst_state;
}

// 追加：在短時間內新增多個 MEM_PRIVATE+EXEC 小區域時產生 meta 事件
static void record_exec_private_small_region_burst(RealMemoryDetection::EventHandler* self,
                                                  DWORD pid, uint64_t base_page, SIZE_T region_size) {
   if (!self) return;
   // 只統計小區域（<= 16KB）
   if (region_size == 0 || region_size > 16 * 1024) return;
   const auto now = std::chrono::steady_clock::now();
   const auto window_span = std::chrono::seconds(2); // 2 秒視窗
   const size_t burst_threshold = 4; // 視窗內 4 個以上
   const auto rearm_span = std::chrono::seconds(2);  // 告警再觸發最小間隔

   std::lock_guard<std::mutex> lk(g_burst_mutex);
   BurstState& st = g_burst_state[pid];
   uint64_t page = base_page & ~0xFFFULL;
   if (!st.seen_pages.insert(page).second) {
       // 已經看過，忽略
       return;
   }
   // 入窗
   st.window.push_back(now);
   // 清理過期
   while (!st.window.empty() && (now - st.window.front()) > window_span) {
       st.window.pop_front();
   }
   if (st.window.size() >= burst_threshold) {
       // 節流：避免同一 PID 在短時間連續報警
       if (st.last_alert_time.time_since_epoch().count() == 0 ||
           (now - st.last_alert_time) > rearm_span) {
           st.last_alert_time = now;
           // 產生 meta 事件
           Event ev = Event::make_event(Event::Type::CUSTOM, pid, page, region_size);
           ev.priority = EventPriority::HIGH;
           ev.source = EventSource::DERIVED;
           std::ostringstream oss;
           oss << "[BURST] Multiple new EXEC MEM_PRIVATE small regions within "
               << std::chrono::duration_cast<std::chrono::milliseconds>(window_span).count()
               << "ms window count=" << st.window.size();
           ev.meta = oss.str();
           self->enqueue_event(ev);
           // 順帶出一條DEBUG日誌
           try {
               self->log_to_detection_engine("DEBUG", "[SCATTERED] " + ev.meta);
           } catch (...) {
               // 忽略 log 失敗
           }
       }
   }
}

EventHandler::EventHandler()
    : running_(false)
    , scheduler_running_(false)
    , memory_monitor_(nullptr)
    , detection_engine_(nullptr)
@@ void EventHandler::scan_process_memory(DWORD pid, HANDLE hProcess) {
                bool first = (info.first_seen_ts == 0);
                if (first) {
                    info.first_seen_ts = EventUtils::now_ms();
                    info.last_protect = mbi.Protect;
                    info.seen_exec = is_exec;
                    if (is_exec && mbi.Type == MEM_PRIVATE) {
                        Event sp;
                        sp.type = Event::Type::MEM_PROTECT_CHANGE;
                        sp.process_id = pid;
                        sp.process_handle = hProcess;
                        sp.address = (uint64_t)mbi.BaseAddress;
                        sp.size = mbi.RegionSize;
                        sp.timestamp_ms = info.first_seen_ts;
                        sp.meta = "Synthetic EXEC(initial)";
                        sp.priority = EventPriority::HIGH;
                        sp.source = EventSource::DERIVED;
                        enqueue_event(sp);
                        schedule_suspicious_region(pid, (uint64_t)mbi.BaseAddress);
                       // 記錄 burst（短時間多個新出現的 EXEC 私有小區域）
                       record_exec_private_small_region_burst(this, pid, (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                    }
                } else {
                    if (info.last_protect != mbi.Protect) {
                        bool was_exec = is_executable_protect(info.last_protect);
                        if (!was_exec && is_exec) {
                            Event sp;
                            sp.type = Event::Type::MEM_PROTECT_CHANGE;
                            sp.process_id = pid;
                            sp.process_handle = hProcess;
                            sp.address = (uint64_t)mbi.BaseAddress;
                            sp.size = mbi.RegionSize;
                            sp.timestamp_ms = EventUtils::now_ms();
                            sp.meta = "RW->EXEC transition";
                            sp.priority = EventPriority::HIGH;
                            sp.source = EventSource::DERIVED;
                            enqueue_event(sp);
                            schedule_suspicious_region(pid, (uint64_t)mbi.BaseAddress);
                           // 追蹤 burst
                           record_exec_private_small_region_burst(this, pid, (uint64_t)mbi.BaseAddress, mbi.RegionSize);
                        }
                        info.last_protect = mbi.Protect;
                    }
                }
            }
            scanned++;
@@ void EventHandler::detect_scattered_rop_chains(DWORD process_id, HANDLE hProcess) {
        // 掃描每個可執行區域尋找gadgets
        std::vector<ROPGadget> found_gadgets;
        
        for (const auto& region : exec_regions) {
           // 使用性能優化參數：不跳過大區域，改為掃描至多 64KB 的窗口
           SIZE_T to_scan = static_cast<SIZE_T>(std::min<uint64_t>(static_cast<uint64_t>(region.RegionSize), 64ULL * 1024ULL));
           if (to_scan == 0) continue;

           std::vector<uint8_t> buffer(to_scan);
           SIZE_T bytes_read = 0;
           
           if (!ReadProcessMemory(hProcess, region.BaseAddress, buffer.data(), to_scan, &bytes_read) || bytes_read == 0) {
               continue;
           }

           // 基本統計
           size_t ret_like_count = 0;
           size_t pop_count = 0;
           size_t pop_ret_count = 0;
           size_t pivot_count = 0;
           size_t ret_sled_max = 0, ret_sled_cur = 0;
           size_t nop_sled_max = 0, nop_sled_cur = 0;
           size_t int3_sled_max = 0, int3_sled_cur = 0;

           for (size_t i = 0; i < bytes_read; ++i) {
               uint8_t b = buffer[i];
               // sleds
               if (b == 0x90) { // NOP
                   ++nop_sled_cur; nop_sled_max = std::max(nop_sled_max, nop_sled_cur);
               } else {
                   nop_sled_cur = 0;
               }
               if (b == 0xCC) { // INT3
                   ++int3_sled_cur; int3_sled_max = std::max(int3_sled_max, int3_sled_cur);
               } else {
                   int3_sled_cur = 0;
               }
               // ret-like
               if (is_ret_like(b)) {
                   ++ret_like_count;
                   ++ret_sled_cur; ret_sled_max = std::max(ret_sled_max, ret_sled_cur);
                   // pop; ret-like
                   if (i >= 1) {
                       uint8_t prev = buffer[i - 1];
                       if (prev >= 0x58 && prev <= 0x5F) {
                           ++pop_ret_count;
                       }
                       if (prev >= 0x58 && prev <= 0x5F) {
                           // 同時計入 pop 統計
                           ++pop_count;
                       }
                       // pivot 類型：leave; ret, xchg eax,esp; ret, add esp, imm; ret
                       if (prev == 0x94 /* xchg eax, esp */ || prev == 0xC9 /* leave */) {
                           ++pivot_count;
                       }
                       // add esp, imm8/imm32 之後接 ret-like（寬鬆模式：add 在 6 bytes 內）
                       if (i >= 3 && buffer[i - 3] == 0x83 && buffer[i - 2] == 0xC4) {
                           ++pivot_count;
                       } else if (i >= 6 && buffer[i - 6] == 0x81 && buffer[i - 5] == 0xC4) {
                           ++pivot_count;
                       }
                   }
                   // 收集 ROPGadget（僅對 0xC3 保持舊語意）
                   if (b == 0xC3) {
                       std::vector<uint8_t> gadget_bytes;
                       size_t start = (i >= 16) ? i - 16 : 0;
                       for (size_t j = start; j <= i; ++j) gadget_bytes.push_back(buffer[j]);
                       std::string instruction;
                       if (!gadget_bytes.empty()) {
                           uint8_t prev = gadget_bytes.size() >= 2 ? gadget_bytes[gadget_bytes.size() - 2] : 0;
                           if (prev >= 0x58 && prev <= 0x5F) instruction = "pop r32; ret";
                           else if (prev == 0x94) instruction = "xchg eax, esp; ret";
                           else if (gadget_bytes.size() >= 4 && gadget_bytes[gadget_bytes.size() - 4] == 0x83 &&
                                    gadget_bytes[gadget_bytes.size() - 3] == 0xC4) instruction = "add esp, XX; ret";
                           else instruction = "ret";
                       }
                       uint64_t gadget_address = (uint64_t)region.BaseAddress + i;
                       ROPGadget gadget(gadget_address, gadget_bytes, instruction);
                       found_gadgets.push_back(gadget);
                   }
               } else {
                   ret_sled_cur = 0;
                   if (b >= 0x58 && b <= 0x5F) ++pop_count;
               }
           }

           // 熵值估計
           double entropy = 0.0;
           try {
               entropy = EventUtils::calculate_shannon_entropy(buffer.data(), bytes_read);
           } catch (...) {
               entropy = 0.0;
           }
           const double density = bytes_read ? static_cast<double>(ret_like_count) / static_cast<double>(bytes_read) : 0.0;
           const bool is_private = (region.Type == MEM_PRIVATE);

           // 簡單評分（需後續調參）
           int score = 0;
           if (density >= 0.03) score += 4;
           else if (density >= 0.015) score += 2;
           if (pivot_count >= 1 && density > 0.01) score += 2;
           if (ret_sled_max >= 6) score += 2;
           if (nop_sled_max >= 16) score += 1;
           if (int3_sled_max >= 8) score += 1;
           if (is_private) score += 1;
           if (entropy <= 3.0 && density >= 0.01) score += 1;

           // 若可疑，產出事件
           if (score >= 5) {
               std::ostringstream meta;
               meta << "SCATTERED_ROP_HEURISTIC"
                    << " ret_like=" << ret_like_count
                    << " pop=" << pop_count
                    << " pop_ret=" << pop_ret_count
                    << " pivot=" << pivot_count
                    << " density=" << density
                    << " ret_sled_max=" << ret_sled_max
                    << " nop_sled_max=" << nop_sled_max
                    << " int3_sled_max=" << int3_sled_max
                    << " entropy=" << entropy
                    << " private=" << (is_private ? "Y" : "N")
                    << " scanned=" << bytes_read;

               Event ev = Event::make_event(Event::Type::CUSTOM, process_id, (uint64_t)region.BaseAddress, region.RegionSize);
               ev.priority = EventPriority::HIGH;
               ev.source = EventSource::DERIVED;
               ev.meta = meta.str();
               enqueue_event(ev);
           }

           // 對 MEM_PRIVATE + EXEC 小區域也納入 burst 偵測
           if (is_private && region.RegionSize <= 16 * 1024) {
               record_exec_private_small_region_burst(this, process_id, (uint64_t)region.BaseAddress, region.RegionSize);
           }
        }
        
        // 分析gadget分佈模式
        std::string gadget_debug = "*** GADGET SCAN COMPLETE: Found " + std::to_string(found_gadgets.size()) + " gadgets ***";
        log_to_detection_engine("DEBUG", gadget_debug);
@@ void EventHandler::check_executable_integrity(LPVOID base_address, SIZE_T region_size, DWORD pid, int depth) {
        
        // 檢查指令完整性
        int valid_instructions = 0;
        int total_checks = 0;
            
       // 新增：高密度gadget檢測（擴充 ret-like）
       int ret_cnt = 0, pop_cnt = 0, nop_cnt = 0, int3_cnt = 0, ret_sled_max = 0, ret_sled_cur = 0;
        for (size_t i = 0; i < bytes_read; i++) {
            uint8_t b = buffer[i];
           if (is_ret_like(b)) { ret_cnt++; ++ret_sled_cur; ret_sled_max = std::max(ret_sled_max, ret_sled_cur); }
            else if (b >= 0x58 && b <= 0x5F) pop_cnt++;
            else if (b == 0x90) nop_cnt++;
            else if (b == 0xCC) int3_cnt++;
           else ret_sled_cur = 0;
        }
       double ret_density = bytes_read ? static_cast<double>(ret_cnt) / static_cast<double>(bytes_read) : 0.0;
        double sled_ratio = bytes_read ? (double)(nop_cnt + int3_cnt) / bytes_read : 0.0;
        
        // 檢查簽名字串
        bool has_sig = false;
        if (bytes_read >= 6) {
@@
        }
        
        // 小區域 ROP 門檻（優先檢測）
        if (bytes_read <= 512) {
           bool small_hit = (ret_cnt >= 4 && (ret_density >= 0.015 || pop_cnt >= 2 || ret_sled_max >= 4))
                || (ret_cnt + pop_cnt >= 8)
               || (ret_density >= 0.01 && sled_ratio >= 0.05)
               || (ret_sled_max >= 6);
                if (small_hit) {
                std::ostringstream am;
                am << "SMALL_REGION_ROP ret=" << ret_cnt
                   << " pop=" << pop_cnt
                  << " density=" << std::fixed << std::setprecision(4) << ret_density
                   << " sled=" << sled_ratio;
                
                Event alert = Event::make_event(Event::Type::CUSTOM, pid, (uint64_t)base_address, region_size);
                alert.meta = am.str();
                alert.priority = EventPriority::HIGH;
@@
        }
        
        // 高密度gadget檢測條件
       if ((ret_cnt >= 12 && ret_density >= 0.008) ||
            (ret_cnt + pop_cnt >= 20) ||
            (has_sig && ret_cnt >= 6) ||
           (ret_density >= 0.005 && sled_ratio >= 0.12) ||
           (ret_sled_max >= 6 && ret_density >= 0.008)) {
            
            std::ostringstream am;
            am << "ROP/Shellcode Indicators ret=" << ret_cnt
               << " pop=" << pop_cnt
              << " ret_density=" << std::fixed << std::setprecision(4) << ret_density
               << " sled_ratio=" << sled_ratio
               << " sig=" << (has_sig ? "Y" : "N");
            
            Event alert = Event::make_event(Event::Type::CUSTOM, pid, (uint64_t)base_address, region_size);
            alert.meta = am.str();
            alert.priority = EventPriority::HIGH;
            alert.source = EventSource::DERIVED;
            enqueue_event(alert);
            update_stats_on_finding();
            
            // 調試輸出
           std::ostringstream dbg;
           dbg << "*** ROP DENSITY DETECTED: ret=" << ret_cnt
               << " pop=" << pop_cnt
               << " density=" << std::fixed << std::setprecision(4) << ret_density
               << " ret_sled_max=" << ret_sled_max << " ***";
            if (memory_monitor_) {
               memory_monitor_->log_message("DEBUG", dbg.str());
            }
        }
        
        for (size_t i = 0; i < bytes_read - 1; i++) {
                total_checks++;
                
                // 檢查常見的有效指令模式
                if (buffer[i] == 0x90) { // NOP
                    valid_instructions++;
               } else if (is_ret_like(buffer[i])) { // RET-like
                    valid_instructions++;
                } else if (buffer[i] >= 0x58 && buffer[i] <= 0x5F) { // POP
                    valid_instructions++;
                } else if (buffer[i] >= 0x50 && buffer[i] <= 0x57) { // PUSH
                    valid_instructions++;
*** End Patch