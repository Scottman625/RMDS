#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試強健版 diff 處理功能
"""

import asyncio
import logging
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_robust_diff_extraction():
    """測試強健版 diff 提取功能"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試案例 1: 多文件修改
        patch1 = """Here is the patch to add detection ID generation:

```diff
diff --git a/src/memory_monitor.cpp b/src/memory_monitor.cpp
index 1234567..abcdefg 100644
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
        
        # 測試案例 2: 新增文件
        patch2 = """I'll create a new detection ID generator:

```diff
diff --git a/src/detection_id_generator.cpp b/src/detection_id_generator.cpp
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/detection_id_generator.cpp
@@ -0,0 +1,15 @@
+#include "detection_id_generator.hpp"
+#include <chrono>
+#include <sstream>
+#include <iomanip>
+
+std::string DetectionIdGenerator::generate_id() {
+    static int counter = 0;
+    counter++;
+    
+    auto now = std::chrono::system_clock::now();
+    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
+    
+    return "detection_" + std::to_string(counter) + "_" + std::to_string(timestamp);
+}
```

This creates a new detection ID generator file.
"""
        
        # 測試案例 3: 刪除文件
        patch3 = """Remove the old test file:

```diff
diff --git a/src/old_test_file.cpp b/src/old_test_file.cpp
deleted file mode 100644
index 1234567..0000000
--- a/src/old_test_file.cpp
+++ /dev/null
@@ -1,10 +0,0 @@
-#include <iostream>
-
-int main() {
-    std::cout << "This is an old test file" << std::endl;
-    return 0;
-}
```

This removes the old test file.
"""
        
        # 測試案例 4: 包含警告的補丁（行數不匹配）
        patch4 = """Here's a patch with line count mismatch:

```diff
--- a/src/test_mismatch.cpp
+++ b/src/test_mismatch.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
 #include <string>
+// This line should cause a warning
+// Another line that doesn't match the hunk header
```

This patch has a line count mismatch.
"""
        
        logger.info("測試強健版 diff 提取功能...")
        
        test_cases = [
            ("多文件修改", patch1),
            ("新增文件", patch2),
            ("刪除文件", patch3),
            ("行數不匹配", patch4)
        ]
        
        for i, (name, patch) in enumerate(test_cases):
            logger.info(f"\n--- 測試 {i+1}: {name} ---")
            
            # 測試新的強健版提取
            diff_meta = server._extract_and_validate_unified_diff(patch, server.repo_root)
            
            logger.info(f"提取結果:")
            logger.info(f"  有效: {diff_meta.valid}")
            logger.info(f"  文件數量: {len(diff_meta.files)}")
            logger.info(f"  問題數量: {len(diff_meta.issues)}")
            logger.info(f"  補丁 ID: {diff_meta.patch_id}")
            
            if diff_meta.issues:
                logger.info(f"  問題列表:")
                for issue in diff_meta.issues:
                    logger.info(f"    - {issue}")
            
            if diff_meta.files:
                logger.info(f"  文件列表:")
                for file_info in diff_meta.files:
                    logger.info(f"    - {file_info['old_path']} -> {file_info['new_path']} ({file_info['status']})")
                    logger.info(f"      Hunks: {len(file_info['hunks'])}")
            
            # 測試乾運行
            if diff_meta.valid:
                dry_run_result = server.apply_patch({
                    "branch": "event-hook",
                    "unified_diff": patch,
                    "dry_run": True,
                    "commit": False,
                    "task_id": f"test_robust_{i}"
                })
                
                if dry_run_result.success:
                    logger.info("✅ 乾運行成功")
                else:
                    logger.error(f"❌ 乾運行失敗: {dry_run_result.error}")
            else:
                logger.info("⚠️ 跳過乾運行（diff 無效）")
                
        return True
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")
        return False

async def test_error_feedback():
    """測試錯誤回饋功能"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試案例：不安全路徑
        unsafe_patch = """Here's a patch with unsafe path:

```diff
--- a/src/../secret.txt
+++ b/src/../secret.txt
@@ -1,1 +1,2 @@
 secret data
+more secret data
```

This patch tries to access files outside the allowed directory.
"""
        
        logger.info("\n--- 測試錯誤回饋功能 ---")
        
        diff_meta = server._extract_and_validate_unified_diff(unsafe_patch, server.repo_root)
        
        logger.info(f"不安全路徑測試:")
        logger.info(f"  有效: {diff_meta.valid}")
        logger.info(f"  問題: {diff_meta.issues}")
        
        # 生成修正建議
        if not diff_meta.valid:
            logger.info("修正建議:")
            for issue in diff_meta.issues:
                if issue.startswith("ERR_UNSAFE_PATH"):
                    logger.info("  - 路徑包含不安全字符，請使用相對路徑")
                elif issue.startswith("ERR_FILE_NOT_FOUND"):
                    logger.info("  - 文件不存在，請檢查路徑")
                elif issue.startswith("ERR_NO_HUNKS"):
                    logger.info("  - 缺少有效的修改區塊")
        
        return True
        
    except Exception as e:
        logger.error(f"錯誤回饋測試失敗: {e}")
        return False

async def main():
    """主函數"""
    logger.info("開始測試強健版 diff 處理功能...")
    
    result1 = await test_robust_diff_extraction()
    result2 = await test_error_feedback()
    
    if result1 and result2:
        logger.info("🎉 所有測試完成")
    else:
        logger.error("❌ 部分測試失敗")

if __name__ == "__main__":
    asyncio.run(main())
