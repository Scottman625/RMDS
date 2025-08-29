#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試強健版 diff 處理功能
"""

import logging

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_robust_diff_extraction():
    """測試強健版 diff 提取功能"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試案例 1: 純 diff
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
        
        logger.info("測試強健版 diff 提取功能...")
        
        for i, test_content in enumerate(test_cases):
            logger.info(f"\n--- 測試 {i+1} ---")
            
            # 使用新的強健版 diff 提取
            diff_meta = server._extract_and_validate_unified_diff(test_content, server.repo_root)
            
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
            
            if diff_meta.valid:
                logger.info("✅ 成功提取 diff")
            else:
                logger.info("❌ 無法提取 diff")
                
        return True
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_actual_patch_application():
    """測試實際的補丁應用"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 創建一個簡單的測試補丁
        test_patch = """Here is a simple patch:

```diff
--- a/src/test_detection_id.cpp
+++ b/src/test_detection_id.cpp
@@ -0,0 +1,10 @@
+#include <iostream>
+#include <chrono>
+#include <string>
+
+std::string generate_detection_id() {
+    static int counter = 0;
+    counter++;
+    return "detection_" + std::to_string(counter) + "_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
+}
```

This creates a simple detection ID generator.
"""
        
        logger.info("\n--- 測試實際補丁應用 ---")
        
        # 測試乾運行
        dry_run_result = server.apply_patch({
            "branch": "event-hook",
            "unified_diff": test_patch,
            "dry_run": True,
            "commit": False,
            "task_id": "test_robust_validation"
        })
        
        if dry_run_result.success:
            logger.info("✅ 乾運行成功")
            logger.info(f"  會修改的文件: {dry_run_result.data.get('would_modify', [])}")
            logger.info(f"  補丁 ID: {dry_run_result.data.get('patch_id', 'N/A')}")
            logger.info(f"  問題: {dry_run_result.data.get('issues', [])}")
        else:
            logger.error(f"❌ 乾運行失敗: {dry_run_result.error}")
            return False
        
        # 測試實際應用（不提交）
        apply_result = server.apply_patch({
            "branch": "event-hook",
            "unified_diff": test_patch,
            "dry_run": False,
            "commit": False,
            "task_id": "test_robust_validation"
        })
        
        if apply_result.success:
            logger.info("✅ 實際應用成功")
            logger.info(f"  修改的文件: {apply_result.data.get('modified', [])}")
            logger.info(f"  補丁 ID: {apply_result.data.get('patch_id', 'N/A')}")
            logger.info(f"  是否提交: {apply_result.data.get('commit', 'N/A')}")
        else:
            logger.error(f"❌ 實際應用失敗: {apply_result.error}")
            return False
            
        return True
        
    except Exception as e:
        logger.error(f"實際補丁應用測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主函數"""
    logger.info("開始測試強健版 diff 處理功能...")
    
    result1 = test_robust_diff_extraction()
    result2 = test_actual_patch_application()
    
    if result1 and result2:
        logger.info("🎉 所有測試完成")
    else:
        logger.error("❌ 部分測試失敗")

if __name__ == "__main__":
    main()
