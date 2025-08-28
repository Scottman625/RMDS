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
    CODE_GENERATION = "code_generation"
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
    
    def __init__(self, config_file: str = "llm_config.json"):
        self.config_file = config_file
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
            
            # 代碼生成 - 使用 GPT-4 (代碼生成能力強)
            TaskType.CODE_GENERATION: LLMConfig(
                provider=LLMProvider.OPENAI,
                model="gpt-4-turbo-preview",
                max_tokens=6000,
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
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
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
    
    async def generate_response(self, task_type: TaskType, prompt: str, 
                              context: Optional[str] = None, 
                              system_prompt: Optional[str] = None) -> LLMResponse:
        """生成 LLM 響應"""
        config = self.configs.get(task_type)
        if not config:
            return LLMResponse(content="", error=f"No config found for task type: {task_type}")
        
        client = self.clients.get(config.provider)
        if not client:
            return LLMResponse(content="", error=f"Client not available for provider: {config.provider}")
        
        try:
            if config.provider == LLMProvider.OPENAI:
                return await self._call_openai(client, config, prompt, context, system_prompt)
            elif config.provider == LLMProvider.ANTHROPIC:
                return await self._call_anthropic(client, config, prompt, context, system_prompt)
        except Exception as e:
            logger.error(f"Error calling {config.provider.value}: {e}")
            return LLMResponse(content="", error=str(e))
    
    async def _call_openai(self, client, config: LLMConfig, prompt: str, 
                          context: Optional[str] = None, 
                          system_prompt: Optional[str] = None) -> LLMResponse:
        """調用 OpenAI API"""
        messages = []
        
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        
        if context:
            messages.append({"role": "user", "content": f"Context:\n{context}\n\nTask:\n{prompt}"})
        else:
            messages.append({"role": "user", "content": prompt})
        
        response = await asyncio.to_thread(
            client.ChatCompletion.acreate,
            model=config.model,
            messages=messages,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            top_p=config.top_p,
            frequency_penalty=config.frequency_penalty,
            presence_penalty=config.presence_penalty
        )
        
        return LLMResponse(
            content=response.choices[0].message.content,
            usage=response.usage.dict() if response.usage else None,
            model=response.model
        )
    
    async def _call_anthropic(self, client, config: LLMConfig, prompt: str,
                             context: Optional[str] = None, 
                             system_prompt: Optional[str] = None) -> LLMResponse:
        """調用 Anthropic API"""
        full_prompt = ""
        
        if system_prompt:
            full_prompt += f"{system_prompt}\n\n"
        
        if context:
            full_prompt += f"Context:\n{context}\n\n"
        
        full_prompt += f"Task:\n{prompt}"
        
        response = await asyncio.to_thread(
            client.messages.create,
            model=config.model,
            max_tokens=config.max_tokens,
            temperature=config.temperature,
            top_p=config.top_p,
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
1. 分析需求規格
2. 識別需要修改的模組
3. 將需求分解為具體的開發任務
4. 確定任務間的依賴關係
5. 估算任務複雜度和優先級

請以 JSON 格式回應，包含：
- 任務列表
- 每個任務的描述、模組、依賴、優先級
- 整體時間估算""",

    TaskType.CODE_GENERATION: """你是一個資深的 C++ 開發者，專門為 RMDS (Runtime Memory Detection System) 專案開發代碼。
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
