#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試智能文件更新功能
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from workflow_orchestrator import WorkflowOrchestrator
from mcp_server import MCPServer

def test_intelligent_file_update():
    """測試智能文件更新功能"""
    print("🧪 測試智能文件更新功能...")
    
    # 創建 MCP 服務器
    mcp_server = MCPServer("..")
    
    # 創建工作流協調器
    orchestrator = WorkflowOrchestrator("..")
    
    # 測試文件路徑
    test_file = "src/test_intelligent_update.cpp"
    
    # 創建測試文件
    test_content = """#include <iostream>

void test_function() {
    std::cout << "Hello, World!" << std::endl;
}

int main() {
    test_function();
    return 0;
}
"""
    
    print(f"📝 創建測試文件: {test_file}")
    write_result = mcp_server.write_file({
        "path": test_file,
        "content": test_content,
        "create_dirs": True
    })
    
    if not write_result.success:
        print(f"❌ 創建測試文件失敗: {write_result.error}")
        return
    
    print("✅ 測試文件創建成功")
    
    # 測試方法1: 標準 diff 格式
    print("\n🔄 測試方法1: 標準 diff 格式")
    standard_diff_response = f"""--- a/{test_file}
+++ b/{test_file}
@@ -1,5 +1,6 @@
 #include <iostream>
+#include <chrono>
 
 void test_function() {{
+    auto timestamp = std::chrono::system_clock::now();
     std::cout << "Hello, World!" << std::endl;
 }}
 """
    
    update_result = orchestrator._intelligent_file_update(test_file, standard_diff_response, "test_intelligent_update.cpp")
    print(f"方法1結果: {update_result}")
    
    # 測試方法2: 結構化更新信息
    print("\n🔄 測試方法2: 結構化更新信息")
    structured_response = f"""*** Update File: {test_file}
@@ -1,5 +1,6 @@
 #include <iostream>
+#include <string>
 
 void test_function() {{
+    std::string message = "Updated function";
     std::cout << "Hello, World!" << std::endl;
 }}
 """
    
    update_result = orchestrator._intelligent_file_update(test_file, structured_response, "test_intelligent_update.cpp")
    print(f"方法2結果: {update_result}")
    
    # 測試方法3: 部分內容更新
    print("\n🔄 測試方法3: 部分內容更新")
    partial_response = "添加新的函數: void new_function() { std::cout << 'New function' << std::endl; }"
    
    update_result = orchestrator._intelligent_file_update(test_file, partial_response, "test_intelligent_update.cpp")
    print(f"方法3結果: {update_result}")
    
    # 測試方法4: 備用補丁
    print("\n🔄 測試方法4: 備用補丁")
    backup_response = "無法解析的 LLM 回應"
    
    update_result = orchestrator._intelligent_file_update(test_file, backup_response, "test_intelligent_update.cpp")
    print(f"方法4結果: {update_result}")
    
    # 讀取最終文件內容
    print(f"\n📖 讀取最終文件內容: {test_file}")
    read_result = mcp_server.read_file({"path": test_file})
    if read_result.success:
        print("最終文件內容:")
        print(read_result.data.get('content', ''))
    else:
        print(f"❌ 讀取文件失敗: {read_result.error}")
    
    # 清理測試文件
    print(f"\n🧹 清理測試文件: {test_file}")
    try:
        os.remove(os.path.join("..", test_file))
        print("✅ 測試文件清理成功")
    except Exception as e:
        print(f"⚠️ 清理測試文件時出現警告: {e}")
    
    print("\n🎯 測試完成！")

if __name__ == "__main__":
    test_intelligent_file_update()
