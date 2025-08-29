#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試非乾跑模式的補丁應用
"""

import asyncio
import logging
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_non_dry_run_patch():
    """測試非乾跑模式的補丁應用"""
    try:
        # 導入必要的模組
        from mcp_server import MCPServer
        
        # 初始化 MCP 服務器
        server = MCPServer(repo_root="..")
        
        # 創建一個測試補丁
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
        
        logger.info("測試非乾跑模式的補丁應用...")
        
        # 先進行乾運行檢查
        dry_run_result = server.apply_patch({
            "branch": "main",
            "unified_diff": test_patch,
            "dry_run": True,
            "task_id": "test_non_dry_run"
        })
        
        if not dry_run_result.success:
            logger.error(f"乾運行失敗: {dry_run_result.error}")
            return False
        
        logger.info("乾運行成功，準備實際應用補丁...")
        
        # 實際應用補丁
        apply_result = server.apply_patch({
            "branch": "main",
            "unified_diff": test_patch,
            "dry_run": False,  # 非乾跑模式
            "task_id": "test_non_dry_run"
        })
        
        if apply_result.success:
            logger.info("✅ 補丁應用成功！")
            logger.info(f"修改的文件: {apply_result.data.get('modified', [])}")
            logger.info(f"提交哈希: {apply_result.data.get('commit_hash', 'N/A')}")
            return True
        else:
            logger.error(f"❌ 補丁應用失敗: {apply_result.error}")
            return False
            
    except Exception as e:
        logger.error(f"測試過程中發生錯誤: {e}")
        return False

async def test_workflow_non_dry_run():
    """測試工作流的非乾跑模式"""
    try:
        from workflow_orchestrator import WorkflowOrchestrator
        
        # 初始化工作流協調器
        orchestrator = WorkflowOrchestrator(
            repo_root="..",
            policy_file="policy.json"
        )
        
        # 創建一個簡單的測試任務
        test_task = "請在記憶體監控器中添加檢測 ID 生成功能"
        
        logger.info("啟動工作流測試...")
        
        # 啟動工作流
        workflow_id = await orchestrator.start_workflow(test_task)
        
        if workflow_id:
            logger.info(f"✅ 工作流啟動成功，ID: {workflow_id}")
            
            # 等待工作流完成
            while True:
                status = orchestrator.get_workflow_status(workflow_id)
                if status and status.get("status") == "completed":
                    logger.info("✅ 工作流完成！")
                    logger.info(f"結果: {status}")
                    return True
                elif status and status.get("status") == "failed":
                    logger.error(f"❌ 工作流失敗: {status}")
                    return False
                
                await asyncio.sleep(2)
        else:
            logger.error("❌ 工作流啟動失敗")
            return False
            
    except Exception as e:
        logger.error(f"工作流測試過程中發生錯誤: {e}")
        return False

async def main():
    """主函數"""
    logger.info("開始測試非乾跑模式...")
    
    # 測試 1: 直接補丁應用
    logger.info("\n=== 測試 1: 直接補丁應用 ===")
    result1 = await test_non_dry_run_patch()
    
    # 測試 2: 工作流非乾跑模式
    logger.info("\n=== 測試 2: 工作流非乾跑模式 ===")
    result2 = await test_workflow_non_dry_run()
    
    # 總結
    logger.info("\n=== 測試結果總結 ===")
    logger.info(f"直接補丁應用: {'✅ 成功' if result1 else '❌ 失敗'}")
    logger.info(f"工作流非乾跑: {'✅ 成功' if result2 else '❌ 失敗'}")
    
    if result1 and result2:
        logger.info("🎉 所有測試通過！非乾跑模式正常工作。")
    else:
        logger.error("❌ 部分測試失敗，需要進一步調試。")

if __name__ == "__main__":
    asyncio.run(main())
