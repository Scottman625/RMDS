#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - LLM Client
支持 OpenAI 和 Anthropic API 的統一客戶端
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path

# 載入環境變量
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # 如果沒有 dotenv，使用 os.getenv
    pass

# 可選依賴 - 需要安裝對應的包
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

logger = logging.getLogger(__name__)

class LLMProvider(Enum):
    """LLM 提供商"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"

class TaskType(Enum):
    """任務類型"""
    REQUIREMENT_ANALYSIS = "requirement_analysis"
    TASK_DECOMPOSITION = "task_decomposition"
    HEADER_GENERATION = "header_generation"
    CPP_GENERATION = "cpp_generation"
    CODE_REVIEW = "code_review"
    TEST_GENERATION = "test_generation"
    QUALITY_ASSESSMENT = "quality_assessment"
    STATIC_ANALYSIS = "static_analysis"

@dataclass
class LLMConfig:
    """LLM 配置"""
    provider: LLMProvider
    model: str
    max_tokens: int = 4000
    temperature: float = 0.1
    top_p: float = 0.9
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0

@dataclass
class LLMResponse:
    """LLM 響應"""
    content: str
    usage: Optional[Dict[str, Any]] = None
    model: Optional[str] = None
    error: Optional[str] = None

class LLMClient:
    """統一的 LLM 客戶端"""
    
    def __init__(self, config_path: str = "agent_system/llm_config.json", *args, **kwargs):
        # ensure llm_config exists and is loaded
        self.llm_config = {}
        self._load_llm_config(config_path)
        self.config_path = config_path
        self.configs = self._load_configs()
        self.clients = self._initialize_clients()
        
    def _load_configs(self) -> Dict[TaskType, LLMConfig]:
        """載入任務配置"""
        default_configs = {
            # 需求分析 - 使用 Claude (更擅長理解和分析)
            TaskType.REQUIREMENT_ANALYSIS: LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet-20240229",
                max_tokens=4000,
                temperature=0.1
            ),
            
            # 任務分解 - 使用 Claude (邏輯分析能力強)
            TaskType.TASK_DECOMPOSITION: LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet-20240229",
                max_tokens=3000,
                temperature=0.1
            ),
            
            # 頭文件生成 - 使用 GPT-5 (頭文件接口生成)
            TaskType.HEADER_GENERATION: LLMConfig(
                provider=LLMProvider.OPENAI,
                model="gpt-5-mini",
                max_tokens=15000,
                temperature=0.1
            ),
            
            # C++ 代碼生成 - 使用 GPT-5 (代碼生成能力強)
            TaskType.CPP_GENERATION: LLMConfig(
                provider=LLMProvider.OPENAI,
                model="gpt-5-mini",
                max_tokens=25000,
                temperature=0.1
            ),
            
            # 代碼審查 - 使用 Claude (安全性和質量檢查)
            TaskType.CODE_REVIEW: LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet-20240229",
                max_tokens=4000,
                temperature=0.1
            ),
            
            # 測試生成 - 使用 GPT-4 (結構化代碼生成)
            TaskType.TEST_GENERATION: LLMConfig(
                provider=LLMProvider.OPENAI,
                model="gpt-4-turbo-preview",
                max_tokens=4000,
                temperature=0.1
            ),
            
            # 質量評估 - 使用 Claude (綜合分析能力)
            TaskType.QUALITY_ASSESSMENT: LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet-20240229",
                max_tokens=3000,
                temperature=0.1
            ),
            
            # 靜態分析 - 使用 Claude (代碼理解能力)
            TaskType.STATIC_ANALYSIS: LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model="claude-3-sonnet-20240229",
                max_tokens=2000,
                temperature=0.1
            )
        }
        
        # 嘗試從配置文件載入自定義配置
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    custom_configs = json.load(f)
                
                for task_str, config_data in custom_configs.items():
                    task_type = TaskType(task_str)
                    default_configs[task_type] = LLMConfig(
                        provider=LLMProvider(config_data["provider"]),
                        model=config_data["model"],
                        max_tokens=config_data.get("max_tokens", 4000),
                        temperature=config_data.get("temperature", 0.1),
                        top_p=config_data.get("top_p", 0.9),
                        frequency_penalty=config_data.get("frequency_penalty", 0.0),
                        presence_penalty=config_data.get("presence_penalty", 0.0)
                    )
            except Exception as e:
                logger.warning(f"Failed to load custom config: {e}")
        
        return default_configs
    
    def _initialize_clients(self) -> Dict[LLMProvider, Any]:
        """初始化 API 客戶端"""
        clients = {}
        
        # 初始化 OpenAI 客戶端
        if OPENAI_AVAILABLE:
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if openai_api_key:
                openai.api_key = openai_api_key
                clients[LLMProvider.OPENAI] = openai
                logger.info("OpenAI client initialized")
            else:
                logger.warning("OPENAI_API_KEY not found in environment")
        else:
            logger.warning("OpenAI package not installed")
        
        # 初始化 Anthropic 客戶端
        if ANTHROPIC_AVAILABLE:
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            if anthropic_api_key:
                clients[LLMProvider.ANTHROPIC] = anthropic.Anthropic(api_key=anthropic_api_key)
                logger.info("Anthropic client initialized")
            else:
                logger.warning("ANTHROPIC_API_KEY not found in environment")
        else:
            logger.warning("Anthropic package not installed")
        
        return clients
    
    def _load_llm_config(self, config_path: str):
        """Load per-task LLM config from JSON file (silently fallback to empty)."""
        from pathlib import Path
        import json
        cfg_path = Path(config_path)
        if not cfg_path.exists():
            # try repo-relative path
            alt = Path(__file__).parent / Path(config_path).name
            if alt.exists():
                cfg_path = alt
        try:
            if cfg_path.exists():
                with cfg_path.open("r", encoding="utf-8") as f:
                    self.llm_config = json.load(f)
            else:
                self.llm_config = {}
        except Exception:
            # keep empty config on error but log for diagnostics if logger available
            try:
                import logging
                logging.getLogger(__name__).exception("Failed to load llm_config.json, using empty config")
            except Exception:
                pass
            self.llm_config = {}

    def _get_task_config(self, task_type):
        """Return config dict for TaskType (keys expected as 'quality_assessment', etc.)."""
        try:
            key = task_type.name.lower() if hasattr(task_type, "name") else str(task_type).lower()
            return self.llm_config.get(key, {})
        except Exception:
            return {}

    async def generate_response(self, *, task_type, prompt: str, system_prompt: str = None, **overrides):
        """
        Central entry point used by orchestrator.
        This will merge per-task config from llm_config.json with any overrides.
        """
        task_cfg = self._get_task_config(task_type)

        # Merge config (overrides take precedence)
        model = overrides.pop("model", task_cfg.get("model"))
        provider = overrides.pop("provider", task_cfg.get("provider", "openai"))
        max_tokens = overrides.pop("max_tokens", task_cfg.get("max_tokens"))
        temperature = overrides.pop("temperature", task_cfg.get("temperature"))
        top_p = overrides.pop("top_p", task_cfg.get("top_p"))
        frequency_penalty = overrides.pop("frequency_penalty", task_cfg.get("frequency_penalty"))
        presence_penalty = overrides.pop("presence_penalty", task_cfg.get("presence_penalty"))

        # Log chosen config for diagnostics
        logger.info(f"LLM request for {task_type}: provider={provider} model={model} max_tokens={max_tokens}")

        # Dispatch to provider-specific call (simplified - keep existing call semantics)
        try:
            if provider == "anthropic":
                # ensure model exists / handle 404 fallback in caller
                return await self._call_anthropic(model=model, prompt=prompt, system_prompt=system_prompt,
                                                  max_tokens=max_tokens, temperature=temperature, **overrides)
            else:
                # default: openai
                # NOTE: if your environment uses openai>=1.0.0 you must use the new API (OpenAI() client)
                # either update usage here or pin openai==0.28
                return await self._call_openai(model=model, prompt=prompt, system_prompt=system_prompt,
                                               max_tokens=max_tokens, temperature=temperature, top_p=top_p,
                                               frequency_penalty=frequency_penalty, presence_penalty=presence_penalty,
                                               **overrides)
        except Exception as e:
            logger.error(f"LLM provider error ({provider}): {e}")
            # 統一回傳錯誤物件以符合 existing caller expectations
            class Err: pass
            err = Err()
            err.error = str(e)
            err.content = None
            err.model = model
            err.usage = {}
            return err

    async def _call_openai(self, **kwargs):
        """調用 OpenAI API"""
        messages = []
        
        if kwargs.get("system_prompt"):
            messages.append({"role": "system", "content": kwargs["system_prompt"]})
        
        if kwargs.get("context"):
            messages.append({"role": "user", "content": f"Context:\n{kwargs['context']}\n\nTask:\n{kwargs['prompt']}"})
        else:
            messages.append({"role": "user", "content": kwargs["prompt"]})
        
        # 使用新版 OpenAI API
        client = openai.AsyncOpenAI()
        
        # 根據模型類型選擇正確的參數名稱
        completion_params = {
            "model": kwargs["model"],
            "messages": messages
        }
        
        # 對於較新的模型，使用 max_completion_tokens 並處理特殊參數限制
        if "gpt-5" in kwargs["model"] or "gpt-4o" in kwargs["model"]:
            completion_params["max_completion_tokens"] = kwargs["max_tokens"]
            
            # gpt-5 和 gpt-5-mini 模型不支持自定義 temperature，只支持默認值
            if "gpt-5" in kwargs["model"]:
                # 不設置 temperature 參數，使用默認值
                pass
            else:
                # 其他 gpt-4o 模型可以設置 temperature
                completion_params["temperature"] = kwargs["temperature"]
        else:
            completion_params["max_tokens"] = kwargs["max_tokens"]
            completion_params["temperature"] = kwargs["temperature"]
        
        # 添加其他參數（如果模型支持）
        if "gpt-5" not in kwargs["model"]:
            completion_params["top_p"] = kwargs["top_p"]
            completion_params["frequency_penalty"] = kwargs["frequency_penalty"]
            completion_params["presence_penalty"] = kwargs["presence_penalty"]
        
        response = await client.chat.completions.create(**completion_params)
        
        return LLMResponse(
            content=response.choices[0].message.content,
            usage=response.usage.model_dump() if response.usage else None,
            model=response.model
        )

    async def _call_anthropic(self, **kwargs):
        """調用 Anthropic API"""
        full_prompt = ""
        
        if kwargs.get("system_prompt"):
            full_prompt += f"{kwargs['system_prompt']}\n\n"
        
        if kwargs.get("context"):
            full_prompt += f"Context:\n{kwargs['context']}\n\n"
        
        full_prompt += f"Task:\n{kwargs['prompt']}"
        
        response = await asyncio.to_thread(
            anthropic.Anthropic.messages.create,
            model=kwargs["model"],
            max_tokens=kwargs["max_tokens"],
            temperature=kwargs["temperature"],
            top_p=kwargs["top_p"],
            messages=[{"role": "user", "content": full_prompt}]
        )
        
        return LLMResponse(
            content=response.content[0].text,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens
            },
            model=response.model
        )
    
    def get_task_config(self, task_type: TaskType) -> Optional[LLMConfig]:
        """獲取任務配置"""
        return self.configs.get(task_type)
    
    def is_provider_available(self, provider: LLMProvider) -> bool:
        """檢查提供商是否可用"""
        return provider in self.clients
    
    def list_available_providers(self) -> List[LLMProvider]:
        """列出可用的提供商"""
        return list(self.clients.keys())

# 預設的系統提示詞模板
SYSTEM_PROMPTS = {
    TaskType.REQUIREMENT_ANALYSIS: """你是一個專業的軟體需求分析師，專門分析 C++ 專案的需求。
你的任務是：
1. 理解用戶提出的需求
2. 識別涉及的技術模組和文件
3. 分析技術依賴和風險
4. 生成標準化的需求規格

請以結構化的方式回應，包含：
- 需求背景
- 功能需求
- 非功能需求
- 技術依賴
- 風險評估
- 影響範圍""",

    TaskType.TASK_DECOMPOSITION: """你是一個專案管理專家，專門將複雜的軟體需求分解為可執行的任務。
你的任務是：
1. 分析 prompt.txt 內容，理解用戶需求
2. 識別需求類型和技術領域
3. 評估複雜度和優先級
4. 將需求分解為具體的開發任務
5. 確定任務間的依賴關係
6. 分配適當的 Agent 角色

請以 JSON 格式回應，結構如下：
{
    "content_analysis": {
        "requirement_type": "功能開發/修復/優化/重構",
        "technical_domain": ["記憶體安全", "性能優化", "架構設計"],
        "complexity": "低/中/高",
        "priority": "低/中/高",
        "estimated_total_hours": 數字,
        "key_requirements": ["關鍵需求1", "關鍵需求2"]
    },
    "tasks": [
        {
            "task_id": "T1-{workflow_id}",
            "description": "任務描述",
            "agent": "cpp_developer/unit_test_generator/header_generator",
            "priority": 1-3,
            "estimated_hours": 數字,
            "details": "詳細說明",
            "dependencies": ["依賴任務ID"],
            "risks": ["風險描述"]
        }
    ],
    "analysis_summary": "整體分析摘要"
}

請確保：
- 任務描述清晰具體
- 優先級合理（1=高，2=中，3=低）
- 工作量估算準確
- 依賴關係正確
- 風險評估充分""",

    TaskType.HEADER_GENERATION: """你是一個資深的 C++ 頭文件設計師，專門為 RMDS (Runtime Memory Detection System) 專案生成頭文件。
你的任務是：
1. 分析 C++ 源代碼
2. 設計清晰的類和函數接口
3. 生成標準的頭文件 (.hpp/.h)
4. 確保接口設計合理

請注意：
- 使用適當的 include guard 或 #pragma once
- 正確的前向聲明 (forward declarations)
- 清晰的類和函數聲明
- 適當的 const 修飾符
- 生成統一的 diff 格式""",

    TaskType.CPP_GENERATION: """你是一個資深的 C++ 開發者，專門為 RMDS (Runtime Memory Detection System) 專案開發代碼。
你的任務是：
1. 理解需求描述
2. 分析現有代碼結構
3. 生成高質量的 C++ 代碼
4. 確保代碼符合專案規範

請注意：
- 使用現代 C++ 標準 (C++17/20)
- 遵循專案的命名規範
- 添加適當的註釋
- 考慮性能和安全性
- 生成統一的 diff 格式""",

    TaskType.CODE_REVIEW: """你是一個資深的 C++ 代碼審查者，專門審查 RMDS 專案的代碼變更。
你的任務是：
1. 檢查代碼質量和風格
2. 識別潛在的 bug 和安全問題
3. 評估性能影響
4. 提供改進建議

請檢查以下方面：
- 代碼風格和可讀性
- 記憶體管理
- 錯誤處理
- 性能優化
- 安全性問題
- 測試覆蓋率""",

    TaskType.TEST_GENERATION: """你是一個測試工程師，專門為 C++ 專案生成單元測試。
你的任務是：
1. 分析代碼功能
2. 識別測試場景
3. 生成全面的單元測試
4. 確保測試覆蓋率

請生成：
- 正向測試案例
- 邊界條件測試
- 錯誤處理測試
- Mock 對象（如需要）
- 測試文檔""",

    TaskType.QUALITY_ASSESSMENT: """你是一個軟體質量評估專家，專門評估 RMDS 專案的代碼變更。
你的任務是：
1. 評估代碼質量
2. 分析測試結果
3. 檢查是否符合需求
4. 提供整體評估

請評估：
- 功能完整性
- 代碼質量
- 測試覆蓋率
- 性能影響
- 風險等級
- 是否滿足驗收標準""",

    TaskType.STATIC_ANALYSIS: """你是一個靜態代碼分析專家，專門分析 C++ 代碼的潛在問題。
你的任務是：
1. 分析代碼結構
2. 識別潛在問題
3. 提供改進建議
4. 評估代碼複雜度

請關注：
- 代碼複雜度
- 潛在的 bug
- 安全漏洞
- 性能問題
- 維護性問題"""
}
