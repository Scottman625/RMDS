#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - LLM 整合測試
測試 LLM 客戶端和各個 Agent 的 LLM 整合功能
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from llm_client import LLMClient, TaskType, SYSTEM_PROMPTS
from workflow_orchestrator import WorkflowOrchestrator

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMIntegrationTester:
    """LLM 整合測試器"""
    
    def __init__(self):
        self.llm_client = LLMClient()
        self.test_results = {}
    
    async def test_llm_client_initialization(self):
        """測試 LLM 客戶端初始化"""
        logger.info("測試 LLM 客戶端初始化...")
        
        try:
            # 檢查可用的提供商
            available_providers = self.llm_client.list_available_providers()
            logger.info(f"可用的 LLM 提供商: {available_providers}")
            
            # 檢查任務配置
            for task_type in TaskType:
                config = self.llm_client.get_task_config(task_type)
                if config:
                    logger.info(f"{task_type.value}: {config.provider.value} - {config.model}")
                else:
                    logger.warning(f"未找到 {task_type.value} 的配置")
            
            self.test_results["initialization"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"LLM 客戶端初始化失敗: {e}")
            self.test_results["initialization"] = f"FAIL: {e}"
            return False
    
    async def test_requirement_analysis(self):
        """測試需求分析 LLM 整合"""
        logger.info("測試需求分析 LLM 整合...")
        
        try:
            prompt = """
請分析以下用戶任務並生成標準化的需求規格：

用戶任務：在 detection_engine.cpp 中添加新的記憶體檢測功能，能夠識別異常的記憶體訪問模式。

請提供詳細的需求分析，包括：
1. 需求背景和目標
2. 功能需求列表
3. 非功能需求（性能、安全、可維護性等）
4. 涉及的技術模組和文件
5. 風險評估
6. 工作量估算
"""
            
            response = await self.llm_client.generate_response(
                task_type=TaskType.REQUIREMENT_ANALYSIS,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPTS[TaskType.REQUIREMENT_ANALYSIS]
            )
            
            if response.error:
                logger.error(f"需求分析 LLM 調用失敗: {response.error}")
                self.test_results["requirement_analysis"] = f"FAIL: {response.error}"
                return False
            
            logger.info(f"需求分析成功，使用模型: {response.model}")
            logger.info(f"Token 使用: {response.usage}")
            logger.info(f"響應長度: {len(response.content)} 字符")
            
            self.test_results["requirement_analysis"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"需求分析測試失敗: {e}")
            self.test_results["requirement_analysis"] = f"FAIL: {e}"
            return False
    
    async def test_task_decomposition(self):
        """測試任務分解 LLM 整合"""
        logger.info("測試任務分解 LLM 整合...")
        
        try:
            prompt = """
請基於以下需求規格，將任務分解為具體的開發任務：

需求規格：
- 在 detection_engine.cpp 中添加新的記憶體檢測功能
- 能夠識別異常的記憶體訪問模式
- 需要考慮性能和安全性

請提供詳細的任務分解，包括：
1. 任務列表和描述
2. 每個任務的優先級和依賴關係
3. 工作量估算
4. 負責的 Agent 角色
5. 預期的交付物

請以結構化的 JSON 格式回應。
"""
            
            response = await self.llm_client.generate_response(
                task_type=TaskType.TASK_DECOMPOSITION,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPTS[TaskType.TASK_DECOMPOSITION]
            )
            
            if response.error:
                logger.error(f"任務分解 LLM 調用失敗: {response.error}")
                self.test_results["task_decomposition"] = f"FAIL: {response.error}"
                return False
            
            logger.info(f"任務分解成功，使用模型: {response.model}")
            logger.info(f"Token 使用: {response.usage}")
            
            self.test_results["task_decomposition"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"任務分解測試失敗: {e}")
            self.test_results["task_decomposition"] = f"FAIL: {e}"
            return False
    
    async def test_code_generation(self):
        """測試代碼生成 LLM 整合"""
        logger.info("測試代碼生成 LLM 整合...")
        
        try:
            prompt = """
請基於以下需求，為 RMDS 專案生成 C++ 代碼修改：

任務描述：在 detection_engine.cpp 中添加時間戳記錄功能

現有代碼：
#include "detection_engine.hpp"
#include <iostream>

void DetectionEngine::process_event(const MemoryEvent& event) {
    // 原有的處理邏輯
}

請生成統一的 diff 格式的補丁，要求：
1. 符合現代 C++ 標準 (C++17/20)
2. 遵循專案命名規範
3. 添加適當的註釋
4. 考慮性能和安全性
5. 確保代碼可讀性
"""
            
            response = await self.llm_client.generate_response(
                task_type=TaskType.CPP_GENERATION,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPTS[TaskType.CPP_GENERATION]
            )
            
            if response.error:
                logger.error(f"代碼生成 LLM 調用失敗: {response.error}")
                self.test_results["code_generation"] = f"FAIL: {response.error}"
                return False
            
            logger.info(f"代碼生成成功，使用模型: {response.model}")
            logger.info(f"Token 使用: {response.usage}")
            
            self.test_results["code_generation"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"代碼生成測試失敗: {e}")
            self.test_results["code_generation"] = f"FAIL: {e}"
            return False
    
    async def test_code_review(self):
        """測試代碼審查 LLM 整合"""
        logger.info("測試代碼審查 LLM 整合...")
        
        try:
            prompt = """
請審查以下 C++ 代碼的變更：

文件：src/detection_engine.cpp
修改後的代碼：
#include "detection_engine.hpp"
#include <iostream>
#include <chrono>

void DetectionEngine::process_event(const MemoryEvent& event) {
    auto timestamp = std::chrono::system_clock::now();
    // 原有的處理邏輯
}

請進行全面的代碼審查，包括：
1. 代碼質量和風格
2. 潛在的 bug 和安全問題
3. 性能影響
4. 可維護性
5. 改進建議
"""
            
            response = await self.llm_client.generate_response(
                task_type=TaskType.CODE_REVIEW,
                prompt=prompt,
                system_prompt=SYSTEM_PROMPTS[TaskType.CODE_REVIEW]
            )
            
            if response.error:
                logger.error(f"代碼審查 LLM 調用失敗: {response.error}")
                self.test_results["code_review"] = f"FAIL: {response.error}"
                return False
            
            logger.info(f"代碼審查成功，使用模型: {response.model}")
            logger.info(f"Token 使用: {response.usage}")
            
            self.test_results["code_review"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"代碼審查測試失敗: {e}")
            self.test_results["code_review"] = f"FAIL: {e}"
            return False
    
    async def test_workflow_orchestrator_integration(self):
        """測試工作流協調器 LLM 整合"""
        logger.info("測試工作流協調器 LLM 整合...")
        
        try:
            # 創建工作流協調器
            orchestrator = WorkflowOrchestrator(repo_root="..")
            
            # 檢查 LLM 客戶端是否正確初始化
            if not hasattr(orchestrator, 'llm_client'):
                logger.error("工作流協調器未正確初始化 LLM 客戶端")
                self.test_results["orchestrator_integration"] = "FAIL: LLM client not initialized"
                return False
            
            logger.info("工作流協調器 LLM 整合成功")
            self.test_results["orchestrator_integration"] = "PASS"
            return True
            
        except Exception as e:
            logger.error(f"工作流協調器整合測試失敗: {e}")
            self.test_results["orchestrator_integration"] = f"FAIL: {e}"
            return False
    
    async def run_all_tests(self):
        """運行所有測試"""
        logger.info("開始 LLM 整合測試...")
        
        tests = [
            self.test_llm_client_initialization,
            self.test_requirement_analysis,
            self.test_task_decomposition,
            self.test_code_generation,
            self.test_code_review,
            self.test_workflow_orchestrator_integration
        ]
        
        for test in tests:
            try:
                await test()
            except Exception as e:
                logger.error(f"測試執行失敗: {e}")
        
        # 輸出測試結果
        self.print_test_results()
    
    def print_test_results(self):
        """輸出測試結果"""
        logger.info("\n" + "="*50)
        logger.info("LLM 整合測試結果")
        logger.info("="*50)
        
        passed = 0
        total = len(self.test_results)
        
        for test_name, result in self.test_results.items():
            status = "✅ PASS" if result == "PASS" else "❌ FAIL"
            logger.info(f"{test_name:30} {status}")
            if result == "PASS":
                passed += 1
        
        logger.info("="*50)
        logger.info(f"總計: {passed}/{total} 測試通過")
        
        if passed == total:
            logger.info("🎉 所有 LLM 整合測試通過！")
        else:
            logger.warning("⚠️  部分測試失敗，請檢查配置和 API 金鑰")

async def main():
    """主函數"""
    # 檢查環境變量
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        logger.error("請設置 OPENAI_API_KEY 或 ANTHROPIC_API_KEY 環境變量")
        return
    
    # 創建測試器並運行測試
    tester = LLMIntegrationTester()
    await tester.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())
