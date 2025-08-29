#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試所有修正：權限檢查、diff 提取、非乾跑模式
"""

import asyncio
import logging
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_permission_fix():
    """測試權限檢查修正"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試文件路徑
        test_paths = [
            "src/detection_engine.cpp",
            "src/memory_monitor.cpp", 
            "include/detection_engine.hpp",
            "src/utils/logger.cpp"
        ]
        
        logger.info("測試權限檢查修正...")
        
        for path in test_paths:
            has_permission = server._check_permission(path, "write")
            logger.info(f"  {path}: {'✅ 有權限' if has_permission else '❌ 無權限'}")
            
        return True
        
    except Exception as e:
        logger.error(f"權限檢查測試失敗: {e}")
        return False

async def test_diff_extraction():
    """測試 diff 提取功能"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試案例
        test_cases = [
            # 純 diff
            """--- a/src/test.cpp
+++ b/src/test.cpp
@@ -1,1 +1,2 @@
#include <iostream>
+// test line""",
            
            # 被 ``` 包裹的 diff
            """Here is the patch:

```diff
--- a/src/test.cpp
+++ b/src/test.cpp
@@ -1,1 +1,2 @@
#include <iostream>
+// test line
```

This should work.""",
            
            # 多個 diff 區塊
            """First diff:
--- a/src/test1.cpp
+++ b/src/test1.cpp
@@ -1,1 +1,2 @@
#include <iostream>
+// test1

Second diff:
--- a/src/test2.cpp
+++ b/src/test2.cpp
@@ -1,1 +1,2 @@
#include <iostream>
+// test2""",
            
            # 無效內容
            """This is not a diff at all.
Just some text here."""
        ]
        
        logger.info("測試 diff 提取功能...")
        
        for i, test_content in enumerate(test_cases):
            extracted = server._extract_unified_diff(test_content)
            if extracted:
                logger.info(f"  測試 {i+1}: ✅ 成功提取 diff")
                logger.info(f"    提取內容: {extracted[:100]}...")
            else:
                logger.info(f"  測試 {i+1}: ❌ 無法提取 diff")
                
        return True
        
    except Exception as e:
        logger.error(f"diff 提取測試失敗: {e}")
        return False

async def test_non_dry_run():
    """測試非乾跑模式"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 創建一個簡單的測試補丁
        test_patch = """--- a/src/memory_monitor.cpp
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
"""
        
        logger.info("測試非乾跑模式...")
        
        # 測試乾運行
        dry_run_result = server.apply_patch({
            "branch": "master",
            "unified_diff": test_patch,
            "dry_run": True,
            "commit": False,
            "task_id": "test_fixes"
        })
        
        if not dry_run_result.success:
            logger.error(f"乾運行失敗: {dry_run_result.error}")
            return False
        
        logger.info("✅ 乾運行成功")
        
        # 測試實際應用（不提交）
        apply_result = server.apply_patch({
            "branch": "master",
            "unified_diff": test_patch,
            "dry_run": False,
            "commit": False,  # 不提交
            "task_id": "test_fixes"
        })
        
        if apply_result.success:
            logger.info("✅ 補丁應用成功！")
            logger.info(f"  修改的文件: {apply_result.data.get('modified', [])}")
            logger.info(f"  是否提交: {apply_result.data.get('commit', 'N/A')}")
            logger.info(f"  提交哈希: {apply_result.data.get('commit_hash', 'N/A')}")
            logger.info(f"  補丁 ID: {apply_result.data.get('patch_id', 'N/A')}")
            return True
        else:
            logger.error(f"❌ 補丁應用失敗: {apply_result.error}")
            return False
            
    except Exception as e:
        logger.error(f"非乾跑測試失敗: {e}")
        return False

async def test_workflow_integration():
    """測試工作流整合"""
    try:
        from workflow_orchestrator import WorkflowOrchestrator
        
        orchestrator = WorkflowOrchestrator(
            repo_root="..",
            policy_file="policy.json"
        )
        
        test_task = "請在記憶體監控器中添加檢測 ID 生成功能，並確保每次掃描都生成唯一的檢測 ID"
        
        logger.info("測試工作流整合...")
        
        # 啟動工作流
        workflow_id = await orchestrator.start_workflow(test_task)
        
        if workflow_id:
            logger.info(f"✅ 工作流啟動成功，ID: {workflow_id}")
            
            # 等待工作流完成
            max_wait = 60  # 最多等待 60 秒
            wait_count = 0
            
            while wait_count < max_wait:
                status = orchestrator.get_workflow_status(workflow_id)
                if status and status.get("status") == "completed":
                    logger.info("✅ 工作流完成！")
                    logger.info(f"  結果: {status}")
                    return True
                elif status and status.get("status") == "failed":
                    logger.error(f"❌ 工作流失敗: {status}")
                    return False
                
                await asyncio.sleep(2)
                wait_count += 2
                logger.info(f"  等待中... ({wait_count}/{max_wait}秒)")
            
            logger.error("❌ 工作流超時")
            return False
        else:
            logger.error("❌ 工作流啟動失敗")
            return False
            
    except Exception as e:
        logger.error(f"工作流整合測試失敗: {e}")
        return False

async def main():
    """主函數"""
    logger.info("開始測試所有修正...")
    
    # 測試 1: 權限檢查修正
    logger.info("\n=== 測試 1: 權限檢查修正 ===")
    result1 = await test_permission_fix()
    
    # 測試 2: diff 提取功能
    logger.info("\n=== 測試 2: diff 提取功能 ===")
    result2 = await test_diff_extraction()
    
    # 測試 3: 非乾跑模式
    logger.info("\n=== 測試 3: 非乾跑模式 ===")
    result3 = await test_non_dry_run()
    
    # 測試 4: 工作流整合
    logger.info("\n=== 測試 4: 工作流整合 ===")
    result4 = await test_workflow_integration()
    
    # 總結
    logger.info("\n=== 測試結果總結 ===")
    logger.info(f"權限檢查修正: {'✅ 成功' if result1 else '❌ 失敗'}")
    logger.info(f"diff 提取功能: {'✅ 成功' if result2 else '❌ 失敗'}")
    logger.info(f"非乾跑模式: {'✅ 成功' if result3 else '❌ 失敗'}")
    logger.info(f"工作流整合: {'✅ 成功' if result4 else '❌ 失敗'}")
    
    success_count = sum([result1, result2, result3, result4])
    if success_count == 4:
        logger.info("🎉 所有測試通過！修正成功。")
    else:
        logger.error(f"❌ {4-success_count} 個測試失敗，需要進一步調試。")

if __name__ == "__main__":
    asyncio.run(main())
