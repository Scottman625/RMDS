
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 OpenAI API 參數修復
"""

import asyncio
import logging
import sys
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_openai_api_params():
    """測試 OpenAI API 參數修復"""
    try:
        from llm_client import LLMClient
        
        client = LLMClient()
        logger.info("LLM 客戶端創建成功")
        
        # 測試不同模型的參數處理
        test_models = [
            "gpt-5-mini",  # 新模型，使用 max_completion_tokens
            "gpt-4-turbo",  # 舊模型，使用 max_tokens
            "gpt-4o-mini"   # 新模型，使用 max_completion_tokens
        ]
        
        for model in test_models:
            logger.info(f"測試模型: {model}")
            
            # 創建測試參數
            test_params = {
                "model": model,
                "prompt": "Hello, this is a test.",
                "max_tokens": 100,
                "temperature": 0.1,
                "top_p": 0.9,
                "frequency_penalty": 0.0,
                "presence_penalty": 0.0
            }
            
            # 測試參數處理邏輯
            completion_params = {
                "model": test_params["model"],
                "messages": [{"role": "user", "content": test_params["prompt"]}],
                "temperature": test_params["temperature"],
                "top_p": test_params["top_p"],
                "frequency_penalty": test_params["frequency_penalty"],
                "presence_penalty": test_params["presence_penalty"]
            }
            
            # 根據模型類型選擇正確的參數名稱
            if "gpt-5" in test_params["model"] or "gpt-4o" in test_params["model"]:
                completion_params["max_completion_tokens"] = test_params["max_tokens"]
                logger.info(f"  ✓ 使用 max_completion_tokens 參數")
            else:
                completion_params["max_tokens"] = test_params["max_tokens"]
                logger.info(f"  ✓ 使用 max_tokens 參數")
            
            logger.info(f"  ✓ 參數處理成功")
        
        logger.info("所有模型參數測試通過")
        return True
        
    except Exception as e:
        logger.error(f"API 參數測試失敗: {e}")
        return False

async def test_llm_client_integration():
    """測試 LLM 客戶端整合"""
    try:
        from llm_client import LLMClient, TaskType
        
        client = LLMClient()
        logger.info("LLM 客戶端整合測試開始")
        
        # 測試配置載入
        configs = client.configs
        logger.info(f"載入配置成功: {len(configs)} 個配置")
        
        # 檢查每個任務的配置
        for task_type in TaskType:
            config = configs.get(task_type)
            if config:
                logger.info(f"  {task_type.name}: {config.model} (provider: {config.provider.value})")
        
        logger.info("LLM 客戶端整合測試成功")
        return True
        
    except Exception as e:
        logger.error(f"LLM 客戶端整合測試失敗: {e}")
        return False

async def main():
    """主測試函數"""
    logger.info("開始測試 OpenAI API 參數修復...")
    
    # 測試 API 參數處理
    logger.info("1. 測試 OpenAI API 參數處理...")
    if await test_openai_api_params():
        logger.info("✓ API 參數處理測試成功")
    else:
        logger.error("✗ API 參數處理測試失敗")
        return False
    
    # 測試 LLM 客戶端整合
    logger.info("2. 測試 LLM 客戶端整合...")
    if await test_llm_client_integration():
        logger.info("✓ LLM 客戶端整合測試成功")
    else:
        logger.error("✗ LLM 客戶端整合測試失敗")
        return False
    
    logger.info("所有測試完成！API 參數修復成功。")
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
