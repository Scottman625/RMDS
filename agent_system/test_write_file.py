#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 write_file 功能
"""

import logging

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_write_file():
    """測試 write_file 功能"""
    try:
        from mcp_server import MCPServer
        
        server = MCPServer(repo_root="..")
        
        # 測試創建新文件
        test_content = """#include <iostream>
#include <chrono>
#include <string>

std::string generate_detection_id() {
    static int counter = 0;
    counter++;
    return "detection_" + std::to_string(counter) + "_" + 
           std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count());
}

int main() {
    std::cout << "Generated ID: " << generate_detection_id() << std::endl;
    return 0;
}
"""
        
        logger.info("測試 write_file 功能...")
        
        # 測試寫入新文件
        write_result = server.write_file({
            "path": "src/test_detection_id.cpp",
            "content": test_content,
            "create_dirs": True
        })
        
        if write_result.success:
            logger.info("✅ 文件創建成功")
            logger.info(f"  文件路徑: {write_result.data.get('path')}")
            logger.info(f"  文件大小: {write_result.data.get('size')} bytes")
            logger.info(f"  行數: {write_result.data.get('lines')}")
            logger.info(f"  文件哈希: {write_result.data.get('hash')}")
        else:
            logger.error(f"❌ 文件創建失敗: {write_result.error}")
            return False
        
        # 測試讀取剛創建的文件
        read_result = server.read_file({
            "path": "src/test_detection_id.cpp"
        })
        
        if read_result.success:
            logger.info("✅ 文件讀取成功")
            logger.info(f"  內容長度: {len(read_result.data.get('content', ''))}")
            logger.info(f"  內容前100字符: {read_result.data.get('content', '')[:100]}...")
        else:
            logger.error(f"❌ 文件讀取失敗: {read_result.error}")
            return False
        
        # 測試修改現有文件
        modified_content = test_content + "\n// 這是修改後的內容\n"
        modify_result = server.write_file({
            "path": "src/test_detection_id.cpp",
            "content": modified_content,
            "create_dirs": False
        })
        
        if modify_result.success:
            logger.info("✅ 文件修改成功")
            logger.info(f"  新文件大小: {modify_result.data.get('size')} bytes")
        else:
            logger.error(f"❌ 文件修改失敗: {modify_result.error}")
            return False
        
        logger.info("🎉 所有測試通過！")
        return True
        
    except Exception as e:
        logger.error(f"測試失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_write_file()
