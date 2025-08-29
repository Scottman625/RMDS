#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡單測試強健版 diff 處理功能
"""

import logging

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_simple():
    """簡單測試"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 簡單的測試補丁 - 新增文件
        test_patch = """Here is a simple patch:

```diff
--- /dev/null
+++ b/src/test_simple.cpp
@@ -0,0 +1,5 @@
+#include <iostream>
+
+int main() {
+    return 0;
+}
```

This is a simple test.
"""
        
        logger.info("測試簡單補丁...")
        
        # 測試新的強健版提取
        diff_meta = server._extract_and_validate_unified_diff(test_patch, server.repo_root)
        
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
        
        # 測試乾運行
        if diff_meta.valid:
            dry_run_result = server.apply_patch({
                "branch": "event-hook",
                "unified_diff": test_patch,
                "dry_run": True,
                "commit": False,
                "task_id": "test_simple"
            })
            
            if dry_run_result.success:
                logger.info("✅ 乾運行成功")
                logger.info(f"  會修改的文件: {dry_run_result.data.get('would_modify', [])}")
                logger.info(f"  補丁 ID: {dry_run_result.data.get('patch_id', 'N/A')}")
            else:
                logger.error(f"❌ 乾運行失敗: {dry_run_result.error}")
        else:
            logger.info("⚠️ 跳過乾運行（diff 無效）")
        
        logger.info("✅ 測試完成")
        return True
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_simple()
