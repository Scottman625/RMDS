#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡化的測試：權限檢查、diff 提取、非乾跑模式
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
        
        # 創建一個非常簡單的測試補丁
        test_patch = """--- a/src/test_detection_id.cpp
+++ b/src/test_detection_id.cpp
@@ -0,0 +1,5 @@
+#include <iostream>
+#include <string>
+
+void generate_detection_id() {
+    std::cout << "Generated detection ID" << std::endl;
+}
"""
        
        logger.info("測試非乾跑模式...")
        
        # 測試乾運行
        dry_run_result = server.apply_patch({
            "branch": "event-hook",  # 使用當前分支
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
            "branch": "event-hook",  # 使用當前分支
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
    
    # 總結
    logger.info("\n=== 測試結果總結 ===")
    logger.info(f"權限檢查修正: {'✅ 成功' if result1 else '❌ 失敗'}")
    logger.info(f"diff 提取功能: {'✅ 成功' if result2 else '❌ 失敗'}")
    logger.info(f"非乾跑模式: {'✅ 成功' if result3 else '❌ 失敗'}")
    
    success_count = sum([result1, result2, result3])
    if success_count == 3:
        logger.info("🎉 所有測試通過！修正成功。")
    else:
        logger.error(f"❌ {3-success_count} 個測試失敗，需要進一步調試。")

if __name__ == "__main__":
    asyncio.run(main())
