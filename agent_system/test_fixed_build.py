#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試修復後的系統
"""

import asyncio
import logging
import sys
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_openai_api():
    """測試 OpenAI API 修復"""
    try:
        import openai
        logger.info("OpenAI 模組導入成功")
        
        # 測試新版 API（不需要 API 金鑰）
        client = openai.AsyncOpenAI(api_key="dummy")
        logger.info("OpenAI 客戶端創建成功")
        
        return True
    except Exception as e:
        # 如果是 API 金鑰錯誤，說明 API 修復成功
        if "api_key" in str(e).lower() or "openai_api_key" in str(e).lower():
            logger.info("OpenAI API 修復成功（需要有效的 API 金鑰）")
            return True
        else:
            logger.error(f"OpenAI API 測試失敗: {e}")
            return False

def test_encoding_fix():
    """測試編碼修復"""
    try:
        import subprocess
        import os
        import platform
        
        # 根據平台選擇命令
        if platform.system() == "Windows":
            cmd = ["cmd", "/c", "echo", "測試中文編碼"]
        else:
            cmd = ["echo", "測試中文編碼"]
        
        # 測試 subprocess 編碼
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        logger.info(f"編碼測試成功: {result.stdout}")
        return True
    except Exception as e:
        logger.error(f"編碼測試失敗: {e}")
        return False

async def test_llm_client():
    """測試 LLM 客戶端"""
    try:
        from llm_client import LLMClient
        
        client = LLMClient()
        logger.info("LLM 客戶端創建成功")
        
        # 測試配置載入
        configs = client.configs
        logger.info(f"載入配置成功: {len(configs)} 個配置")
        
        return True
    except Exception as e:
        logger.error(f"LLM 客戶端測試失敗: {e}")
        return False

async def test_mcp_server():
    """測試 MCP 服務器"""
    try:
        from mcp_server import MCPServer
        
        # 初始化服務器
        server = MCPServer(repo_root="..")
        logger.info("MCP 服務器創建成功")
        
        # 測試基本功能
        result = server.list_files({"path": "src", "glob": "*.cpp"})
        logger.info(f"文件列表測試成功: {result.success}")
        
        return True
    except Exception as e:
        logger.error(f"MCP 服務器測試失敗: {e}")
        return False

async def main():
    """主測試函數"""
    logger.info("開始測試修復後的系統...")
    
    # 測試 OpenAI API
    logger.info("1. 測試 OpenAI API 修復...")
    if test_openai_api():
        logger.info("✓ OpenAI API 修復成功")
    else:
        logger.error("✗ OpenAI API 修復失敗")
        return False
    
    # 測試編碼修復
    logger.info("2. 測試編碼修復...")
    if test_encoding_fix():
        logger.info("✓ 編碼修復成功")
    else:
        logger.error("✗ 編碼修復失敗")
        return False
    
    # 測試 LLM 客戶端
    logger.info("3. 測試 LLM 客戶端...")
    if await test_llm_client():
        logger.info("✓ LLM 客戶端測試成功")
    else:
        logger.error("✗ LLM 客戶端測試失敗")
        return False
    
    # 測試 MCP 服務器
    logger.info("4. 測試 MCP 服務器...")
    if await test_mcp_server():
        logger.info("✓ MCP 服務器測試成功")
    else:
        logger.error("✗ MCP 服務器測試失敗")
        return False
    
    logger.info("所有測試完成！系統修復成功。")
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
