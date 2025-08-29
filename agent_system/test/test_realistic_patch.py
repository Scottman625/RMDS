#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試真實的 LLM 補丁格式
"""

import asyncio
import logging
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_realistic_patches():
    """測試真實的 LLM 補丁格式"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試案例 1: 修改現有文件（常見情況）
        patch1 = """Here is the patch to add detection ID generation:

```diff
--- a/src/memory_monitor.cpp
+++ b/src/memory_monitor.cpp
@@ -160,6 +160,9 @@ void MemoryMonitor::monitor_loop() {
             scan_processes();
             scan_memory_regions();
             cleanup_old_attack_chains();
+            
+            // 生成檢測 ID
+            generate_detection_id();
             
             {
                 std::lock_guard<std::mutex> lock(stats_mutex_);
@@ -167,6 +170,15 @@ void MemoryMonitor::monitor_loop() {
             }
             
             std::this_thread::sleep_for(std::chrono::milliseconds(config_.scan_interval_ms));
+        }
+        catch (const std::exception& e) {
+            log_message("ERROR", "Monitor thread exception: " + std::string(e.what()));
+        }
+    }
+}
+
+void MemoryMonitor::generate_detection_id() {
+    static int detection_counter = 0;
+    detection_counter++;
+    std::string detection_id = "detection_" + std::to_string(detection_counter) + "_" + 
+                              std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
+                                  std::chrono::system_clock::now().time_since_epoch()).count());
+    log_message("INFO", "Generated detection ID: " + detection_id);
         }
-        catch (const std::exception& e) {
-            log_message("ERROR", "Monitor thread exception: " + std::string(e.what()));
-        }
-    }
-}
```

This patch adds detection ID generation functionality to the memory monitor.
"""
        
        # 測試案例 2: 多個文件修改
        patch2 = """I'll create multiple files for the detection system:

First, let's add the header:

```diff
--- a/include/detection_engine.hpp
+++ b/include/detection_engine.hpp
@@ -50,6 +50,9 @@ class DetectionEngine {
     void process_event(const MemoryEvent& event);
     void generate_report();
     
+    // 新增檢測 ID 生成
+    std::string generate_detection_id();
+    
 private:
     std::vector<MemoryEvent> events_;
     std::mutex events_mutex_;
```

Now the implementation:

```diff
--- a/src/detection_engine.cpp
+++ b/src/detection_engine.cpp
@@ -1,5 +1,6 @@
 #include "detection_engine.hpp"
 #include <iostream>
+#include <chrono>
 
 // 示例修改：添加時間戳記錄
 void DetectionEngine::process_event(const MemoryEvent& event) {
+    auto timestamp = std::chrono::system_clock::now();
     // 原有的處理邏輯
 }
```

These changes add detection ID functionality.
"""
        
        # 測試案例 3: 包含尾隨空格的補丁
        patch3 = """Here's a patch with trailing whitespace:

```diff
--- a/src/test_trailing.cpp
+++ b/src/test_trailing.cpp
@@ -0,0 +1,5 @@
+#include <iostream>  
+#include <string>  
+
+void test_function() {  
+    std::cout << "Test" << std::endl;  
+}
```

Note the trailing spaces in this patch.
"""
        
        logger.info("測試真實的 LLM 補丁格式...")
        
        test_cases = [
            ("修改現有文件", patch1),
            ("多個文件修改", patch2),
            ("尾隨空格", patch3)
        ]
        
        for i, (name, patch) in enumerate(test_cases):
            logger.info(f"\n--- 測試 {i+1}: {name} ---")
            
            # 測試 diff 提取
            extracted = server._extract_unified_diff(patch)
            if extracted:
                logger.info(f"✅ 成功提取 diff")
                logger.info(f"提取內容長度: {len(extracted)} 字符")
                logger.info(f"前100字符: {extracted[:100]}...")
                
                # 測試乾運行
                dry_run_result = server.apply_patch({
                    "branch": "event-hook",
                    "unified_diff": extracted,
                    "dry_run": True,
                    "commit": False,
                    "task_id": f"test_realistic_{i}"
                })
                
                if dry_run_result.success:
                    logger.info("✅ 乾運行成功")
                else:
                    logger.error(f"❌ 乾運行失敗: {dry_run_result.error}")
            else:
                logger.error("❌ 無法提取 diff")
                
        return True
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")
        return False

async def main():
    """主函數"""
    logger.info("開始測試真實的 LLM 補丁格式...")
    result = await test_realistic_patches()
    
    if result:
        logger.info("🎉 測試完成")
    else:
        logger.error("❌ 測試失敗")

if __name__ == "__main__":
    asyncio.run(main())
