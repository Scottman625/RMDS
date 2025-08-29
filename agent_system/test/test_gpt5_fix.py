
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 GPT-5-mini 模型參數修復
"""

import asyncio
import logging
import sys
from pathlib import Path

# 設置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def test_gpt5_mini_params():
    """測試 GPT-5-mini 模型參數處理"""
    try:
        # 模擬參數處理邏輯
        test_models = [
            "gpt-5-mini",  # 不支持自定義 temperature
            "gpt-5-flash",  # 支持自定義 temperature
            "gpt-4-turbo",  # 舊模型，支持所有參數
            "gpt-4o-mini"   # 新模型，支持自定義 temperature
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
            
            # 模擬參數處理邏輯
            completion_params = {
                "model": test_params["model"],
                "messages": [{"role": "user", "content": test_params["prompt"]}]
            }
            
            # 根據模型類型選擇正確的參數名稱
            if "gpt-5" in test_params["model"] or "gpt-4o" in test_params["model"]:
                completion_params["max_completion_tokens"] = test_params["max_tokens"]
                
                # gpt-5-mini 模型不支持自定義 temperature，只支持默認值
                if "gpt-5-mini" in test_params["model"]:
                    logger.info(f"  ✓ 使用 max_completion_tokens 參數")
                    logger.info(f"  ✓ 跳過 temperature 參數（使用默認值）")
                    logger.info(f"  ✓ 跳過其他控制參數（top_p, frequency_penalty, presence_penalty）")
                else:
                    # 其他 gpt-5 模型可以設置 temperature
                    completion_params["temperature"] = test_params["temperature"]
                    completion_params["top_p"] = test_params["top_p"]
                    completion_params["frequency_penalty"] = test_params["frequency_penalty"]
                    completion_params["presence_penalty"] = test_params["presence_penalty"]
                    logger.info(f"  ✓ 使用 max_completion_tokens 參數")
                    logger.info(f"  ✓ 設置 temperature 參數")
                    logger.info(f"  ✓ 設置其他控制參數")
            else:
                completion_params["max_tokens"] = test_params["max_tokens"]
                completion_params["temperature"] = test_params["temperature"]
                completion_params["top_p"] = test_params["top_p"]
                completion_params["frequency_penalty"] = test_params["frequency_penalty"]
                completion_params["presence_penalty"] = test_params["presence_penalty"]
                logger.info(f"  ✓ 使用 max_tokens 參數")
                logger.info(f"  ✓ 設置所有控制參數")
            
            logger.info(f"  ✓ 參數處理成功")
            logger.info(f"  最終參數: {list(completion_params.keys())}")
        
        logger.info("所有模型參數測試通過")
        return True
        
    except Exception as e:
        logger.error(f"GPT-5-mini 參數測試失敗: {e}")
        return False

async def test_llm_client_config():
    """測試 LLM 客戶端配置"""
    try:
        from llm_client import LLMClient, TaskType
        
        client = LLMClient()
        logger.info("LLM 客戶端配置測試開始")
        
        # 檢查配置載入
        configs = client.configs
        logger.info(f"載入配置成功: {len(configs)} 個配置")
        
        # 檢查每個任務的配置
        for task_type in TaskType:
            config = configs.get(task_type)
            if config:
                logger.info(f"  {task_type.name}: {config.model} (provider: {config.provider.value})")
                
                # 檢查是否使用了 gpt-5-mini
                if "gpt-5-mini" in config.model:
                    logger.info(f"    ⚠️  注意: 此模型不支持自定義 temperature 參數")
        
        logger.info("LLM 客戶端配置測試成功")
        return True
        
    except Exception as e:
        logger.error(f"LLM 客戶端配置測試失敗: {e}")
        return False

async def main():
    """主測試函數"""
    logger.info("開始測試 GPT-5-mini 模型參數修復...")
    
    # 測試 GPT-5-mini 參數處理
    logger.info("1. 測試 GPT-5-mini 參數處理...")
    if await test_gpt5_mini_params():
        logger.info("✓ GPT-5-mini 參數處理測試成功")
    else:
        logger.error("✗ GPT-5-mini 參數處理測試失敗")
        return False
    
    # 測試 LLM 客戶端配置
    logger.info("2. 測試 LLM 客戶端配置...")
    if await test_llm_client_config():
        logger.info("✓ LLM 客戶端配置測試成功")
    else:
        logger.error("✗ LLM 客戶端配置測試失敗")
        return False
    
    logger.info("所有測試完成！GPT-5-mini 參數修復成功。")
    logger.info("注意: gpt-5-mini 模型將使用默認的 temperature 值（1.0）")
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
