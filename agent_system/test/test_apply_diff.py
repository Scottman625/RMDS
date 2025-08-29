#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 apply_diff 功能
"""

import logging
from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_apply_diff():
    """測試 apply_diff 功能"""
    
    server = MCPServer(repo_root="../", policy_file="policy.json")
    
    # 測試文件路徑
    test_file = "src/test_apply_diff.cpp"
    
    # 創建一個測試文件
    original_content = """#include <iostream>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}"""
    
    # 先創建文件
    create_result = server.write_file({
        "path": test_file,
        "content": original_content,
        "create_dirs": True
    })
    
    if not create_result.success:
        print(f"❌ 創建測試文件失敗: {create_result.error}")
        return
    
    print("✅ 成功創建測試文件")
    
    # 測試 diff 內容
    diff_content = """@@ -1,5 +1,7 @@
 #include <iostream>
+#include <string>
 
 int main() {
     std::cout << "Hello, World!" << std::endl;
+    std::string message = "Test message";
     return 0;
 }"""
    
    # 應用 diff
    diff_result = server.apply_diff({
        "path": test_file,
        "diff_content": diff_content
    })
    
    if diff_result.success:
        print("✅ 成功應用 diff")
        print(f"原始大小: {diff_result.data.get('original_size')}")
        print(f"新大小: {diff_result.data.get('new_size')}")
        print(f"原始行數: {diff_result.data.get('original_lines')}")
        print(f"新行數: {diff_result.data.get('new_lines')}")
        
        # 讀取修改後的文件
        read_result = server.read_file({"path": test_file})
        if read_result.success:
            print("修改後的內容:")
            print(read_result.data.get('content', ''))
        else:
            print(f"❌ 讀取文件失敗: {read_result.error}")
    else:
        print(f"❌ 應用 diff 失敗: {diff_result.error}")

if __name__ == "__main__":
    test_apply_diff()
