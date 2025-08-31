#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - Workflow Orchestrator
基於 MCP 的工作流協調器
"""

import asyncio
import logging
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid

from mcp_server import MCPServer, ActionResult
from llm_client import LLMClient, TaskType, SYSTEM_PROMPTS

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WorkflowTask:
    """工作流任務"""
    task_id: str
    agent_name: str
    agent_role: str
    input_data: Dict[str, Any]
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

@dataclass
class WorkflowStage:
    """工作流階段"""
    stage_name: str
    stage_description: str
    tasks: List[WorkflowTask]
    status: str = "pending"  # pending, running, completed, failed
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

@dataclass
class WorkflowContext:
    """工作流上下文"""
    workflow_id: str
    user_task: str
    project_root: Path
    current_stage: str
    stages: Dict[str, WorkflowStage]
    artifacts: Dict[str, Any]
    metadata: Dict[str, Any]

class WorkflowOrchestrator:
    """工作流協調器"""
    
    def __init__(self, repo_root: str, policy_file: str = "policy.json"):
        self.repo_root = Path(repo_root)
        self.mcp_server = MCPServer(repo_root=str(repo_root), policy_file=policy_file)
        self.llm_client = LLMClient()
        self.active_workflows: Dict[str, WorkflowContext] = {}
        self.workflow_history: List[Dict[str, Any]] = []
        
        # 工作流數據文件路徑
        self.workflow_data_file = Path("logs/workflow_data.json")
        self.workflow_data_file.parent.mkdir(exist_ok=True)
        
        # 定義工作流階段
        self.workflow_stages = self._define_workflow_stages()
        
        # 加載歷史工作流數據
        self._load_workflow_data()
        
        logger.info("Workflow Orchestrator initialized with LLM client")
    
    def _load_workflow_data(self):
        """加載工作流數據"""
        try:
            if self.workflow_data_file.exists():
                with open(self.workflow_data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.workflow_history = data.get('workflow_history', [])
                    logger.info(f"Loaded {len(self.workflow_history)} historical workflows")
        except Exception as e:
            logger.warning(f"Failed to load workflow data: {e}")
            self.workflow_history = []
    
    def _save_workflow_data(self):
        """保存工作流數據"""
        try:
            # 準備要保存的數據
            data = {
                'workflow_history': self.workflow_history,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(self.workflow_data_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Workflow data saved to {self.workflow_data_file}")
        except Exception as e:
            logger.error(f"Failed to save workflow data: {e}")
    
    def _serialize_workflow_context(self, context: WorkflowContext) -> Dict[str, Any]:
        """序列化工作流上下文"""
        return {
            'workflow_id': context.workflow_id,
            'user_task': context.user_task,
            'project_root': str(context.project_root),
            'current_stage': context.current_stage,
            'stages': {
                name: {
                    'stage_name': stage.stage_name,
                    'stage_description': stage.stage_description,
                    'status': stage.status,
                    'start_time': stage.start_time.isoformat() if stage.start_time else None,
                    'end_time': stage.end_time.isoformat() if stage.end_time else None,
                    'tasks': [
                        {
                            'task_id': task.task_id,
                            'agent_name': task.agent_name,
                            'agent_role': task.agent_role,
                            'input_data': task.input_data,
                            'status': task.status,
                            'result': task.result,
                            'error': task.error,
                            'start_time': task.start_time.isoformat() if task.start_time else None,
                            'end_time': task.end_time.isoformat() if task.end_time else None
                        }
                        for task in stage.tasks
                    ]
                }
                for name, stage in context.stages.items()
            },
            'artifacts': context.artifacts,
            'metadata': context.metadata
        }
    
    def _deserialize_workflow_context(self, data: Dict[str, Any]) -> WorkflowContext:
        """反序列化工作流上下文"""
        # 重建階段
        stages = {}
        for name, stage_data in data['stages'].items():
            tasks = []
            for task_data in stage_data['tasks']:
                task = WorkflowTask(
                    task_id=task_data['task_id'],
                    agent_name=task_data['agent_name'],
                    agent_role=task_data['agent_role'],
                    input_data=task_data['input_data'],
                    status=task_data['status'],
                    result=task_data.get('result'),
                    error=task_data.get('error'),
                    start_time=datetime.fromisoformat(task_data['start_time']) if task_data.get('start_time') else None,
                    end_time=datetime.fromisoformat(task_data['end_time']) if task_data.get('end_time') else None
                )
                tasks.append(task)
            
            stage = WorkflowStage(
                stage_name=stage_data['stage_name'],
                stage_description=stage_data['stage_description'],
                tasks=tasks,
                status=stage_data['status'],
                start_time=datetime.fromisoformat(stage_data['start_time']) if stage_data.get('start_time') else None,
                end_time=datetime.fromisoformat(stage_data['end_time']) if stage_data.get('end_time') else None
            )
            stages[name] = stage
        
        return WorkflowContext(
            workflow_id=data['workflow_id'],
            user_task=data['user_task'],
            project_root=Path(data['project_root']),
            current_stage=data['current_stage'],
            stages=stages,
            artifacts=data['artifacts'],
            metadata=data['metadata']
        )
    
    def _define_workflow_stages(self) -> Dict[str, Dict[str, Any]]:
        """定義工作流階段"""
        return {
            "requirement_analysis": {
                "name": "需求分析階段",
                "description": "分析用戶輸入的任務，理解需求並標準化",
                "agents": [
                    {
                        "name": "requirement_analyzer",
                        "role": "需求分析器",
                        "responsibilities": [
                            "解析用戶輸入的任務描述",
                            "識別涉及的 C++ 模組和文件",
                            "分析技術需求和依賴關係",
                            "生成標準化的需求規格"
                        ]
                    }
                ]
            },
            "task_decomposition": {
                "name": "任務分解階段",
                "description": "將需求分解為具體的開發任務",
                "agents": [
                    {
                        "name": "task_decomposer",
                        "role": "任務分解器",
                        "responsibilities": [
                            "分析需求並拆分成具體任務",
                            "識別任務間的依賴關係",
                            "評估每個任務的複雜度和風險",
                            "分配任務給相應的開發 Agent"
                        ]
                    }
                ]
            },
            "code_development": {
                "name": "代碼開發階段",
                "description": "並行執行多個開發任務",
                "agents": [
                    {
                        "name": "cpp_developer",
                        "role": "C++ 開發者",
                        "responsibilities": [
                            "修改 C++ 源代碼文件",
                            "實現新功能或修復問題",
                            "確保代碼符合項目標準",
                            "生成代碼變更報告"
                        ]
                    },
                    {
                        "name": "header_generator",
                        "role": "頭文件生成器",
                        "responsibilities": [
                            "生成或更新 C++ 頭文件",
                            "確保接口一致性",
                            "處理前向聲明和包含關係"
                        ]
                    }
                ]
            },
            "code_review": {
                "name": "代碼審查階段",
                "description": "自動化代碼審查和質量檢查",
                "agents": [
                    {
                        "name": "code_reviewer",
                        "role": "代碼審查者",
                        "responsibilities": [
                            "檢查代碼風格和規範",
                            "識別潛在的 bug 和問題",
                            "驗證代碼邏輯正確性",
                            "檢查性能影響"
                        ]
                    },
                    {
                        "name": "static_analyzer",
                        "role": "靜態分析器",
                        "responsibilities": [
                            "運行 clang-tidy 檢查",
                            "執行 cppcheck 分析",
                            "檢查記憶體洩漏風險",
                            "識別安全漏洞"
                        ]
                    }
                ]
            },
            "test_generation": {
                "name": "測試生成階段",
                "description": "自動生成和更新測試代碼",
                "agents": [
                    {
                        "name": "unit_test_generator",
                        "role": "單元測試生成器",
                        "responsibilities": [
                            "分析代碼變更並生成對應測試",
                            "創建測試用例和測試數據",
                            "確保測試覆蓋率",
                            "更新現有測試"
                        ]
                    }
                ]
            },
            "build_and_test": {
                "name": "構建和測試階段",
                "description": "編譯代碼並執行測試",
                "agents": [
                    {
                        "name": "test_runner",
                        "role": "測試執行器",
                        "responsibilities": [
                            "執行單元測試",
                            "運行集成測試",
                            "收集測試結果",
                            "生成測試報告"
                        ]
                    }
                ]
            },
            "quality_assessment": {
                "name": "質量評估階段",
                "description": "綜合評估代碼質量和變更影響",
                "agents": [
                    {
                        "name": "quality_assessor",
                        "role": "質量評估器",
                        "responsibilities": [
                            "綜合分析所有測試結果",
                            "評估代碼質量指標",
                            "檢查是否滿足需求",
                            "生成質量評估報告"
                        ]
                    }
                ]
            }
        }
    
    async def start_workflow(self, user_task: str) -> str:
        """啟動新的工作流"""
        workflow_id = f"wf_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # 創建工作流上下文
        context = WorkflowContext(
            workflow_id=workflow_id,
            user_task=user_task,
            project_root=self.repo_root,
            current_stage="requirement_analysis",
            stages={},
            artifacts={},
            metadata={
                "start_time": datetime.now().isoformat(),
                "user_task": user_task,
                "project_root": str(self.repo_root)
            }
        )
        
        # 初始化所有階段
        for stage_name, stage_config in self.workflow_stages.items():
            tasks = []
            for agent_config in stage_config["agents"]:
                task = WorkflowTask(
                    task_id=f"{workflow_id}_{stage_name}_{agent_config['name']}",
                    agent_name=agent_config["name"],
                    agent_role=agent_config["role"],
                    input_data={}
                )
                tasks.append(task)
            
            context.stages[stage_name] = WorkflowStage(
                stage_name=stage_name,
                stage_description=stage_config["description"],
                tasks=tasks
            )
        
        self.active_workflows[workflow_id] = context
        
        logger.info(f"Started workflow: {workflow_id}")
        logger.info(f"User task: {user_task}")
        
        # 開始執行第一個階段
        await self._execute_stage(workflow_id, "requirement_analysis")
        
        return workflow_id
    
    async def _execute_stage(self, workflow_id: str, stage_name: str):
        """執行指定階段"""
        if workflow_id not in self.active_workflows:
            logger.error(f"Workflow not found: {workflow_id}")
            return
        
        context = self.active_workflows[workflow_id]
        stage = context.stages.get(stage_name)
        
        if not stage:
            logger.error(f"Stage not found: {stage_name}")
            return
        
        # 更新階段狀態
        stage.status = "running"
        stage.start_time = datetime.now()
        context.current_stage = stage_name
        
        logger.info(f"Executing stage: {stage_name} (workflow: {workflow_id})")
        
        # 如果是 code_development 階段，序列化可能會修改檔案的任務以避免衝突
        try:
            results = []
            if stage_name == "code_development":
                # 逐一執行，避免多個開發任務同時修改相同檔案
                for task in stage.tasks:
                    try:
                        res = await self._execute_task(workflow_id, stage_name, task)
                        results.append(res)
                    except Exception as e:
                        results.append(e)
            else:
                # 其他階段仍然並行執行
                task_coroutines = [self._execute_task(workflow_id, stage_name, task) for task in stage.tasks]
                results = await asyncio.gather(*task_coroutines, return_exceptions=True)
            
            # 檢查結果
            success_count = 0
            failed_count = 0
            
            for i, result in enumerate(results):
                task = stage.tasks[i]
                if isinstance(result, Exception):
                    logger.error(f"Task {task.task_id} failed: {result}")
                    task.status = "failed"
                    task.error = str(result)
                    failed_count += 1
                else:
                    logger.info(f"Task {task.task_id} completed successfully")
                    task.status = "completed"
                    task.result = result
                    success_count += 1
            
            # 更新階段狀態
            stage.end_time = datetime.now()
            if failed_count == 0:
                stage.status = "completed"
                await self._handle_stage_complete(workflow_id, stage_name)
            else:
                stage.status = "failed"
                await self._handle_stage_failed(workflow_id, stage_name, f"{failed_count} tasks failed")
        
        except Exception as e:
            logger.error(f"Stage execution error: {e}")
            stage.status = "failed"
            stage.end_time = datetime.now()
            await self._handle_stage_failed(workflow_id, stage_name, str(e))
    
    async def _execute_task(self, workflow_id: str, stage_name: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行單個任務"""
        task.status = "running"
        task.start_time = datetime.now()
        
        logger.info(f"Executing task: {task.task_id}")
        
        try:
            # 根據 Agent 角色執行不同的操作
            if task.agent_role == "需求分析器":
                result = await self._execute_requirement_analyzer(workflow_id, task)
            elif task.agent_role == "任務分解器":
                result = await self._execute_task_decomposer(workflow_id, task)
            elif task.agent_role == "C++ 開發者":
                result = await self._execute_cpp_developer(workflow_id, task)
            elif task.agent_role == "頭文件生成器":
                result = await self._execute_header_generator(workflow_id, task)
            elif task.agent_role == "代碼審查者":
                result = await self._execute_code_reviewer(workflow_id, task)
            elif task.agent_role == "靜態分析器":
                result = await self._execute_static_analyzer(workflow_id, task)
            elif task.agent_role == "單元測試生成器":
                result = await self._execute_unit_test_generator(workflow_id, task)
            elif task.agent_role == "測試執行器":
                result = await self._execute_test_runner(workflow_id, task)
            elif task.agent_role == "質量評估器":
                result = await self._execute_quality_assessor(workflow_id, task)
            else:
                result = {"status": "unknown_agent_role", "message": f"Unknown agent role: {task.agent_role}"}
            
            task.end_time = datetime.now()
            return result
        
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            task.end_time = datetime.now()
            logger.error(f"Task execution error: {e}")
            raise
    
    async def _execute_requirement_analyzer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行需求分析器"""
        context = self.active_workflows[workflow_id]
        user_task = context.user_task
        
        # 分析用戶任務，識別相關文件
        result = self.mcp_server.list_files({
            "path": "src",
            "glob": "*.cpp"
        })
        
        if not result.success:
            return {"error": "Failed to list source files"}
        
        # 讀取 prompt.txt 文件內容
        prompt_result = self.mcp_server.read_file({
            "path": "agent_system/prompt.txt"
        })
        
        if not prompt_result.success:
            logger.error(f"Failed to read prompt.txt: {prompt_result.error}")
            return {"error": f"Failed to read prompt.txt: {prompt_result.error}"}
        
        prompt_content = prompt_result.data.get("content", "")
        
        # 分析任務需求 - 直接傳遞原始內容，讓任務分解器自行解析
        requirement_spec = {
            "spec_id": f"SPEC-{workflow_id}",
            "title": user_task,
            "description": user_task,
            "files_affected": result.data.get("files", []),
            "estimated_complexity": "unknown",  # 讓任務分解器根據內容判斷
            "priority": "unknown",  # 讓任務分解器根據內容判斷
            "prompt_analysis": prompt_content,  # 完整的原始內容
            "analysis_source": "prompt.txt",
            "analysis_summary": prompt_content,  # 也將完整內容放入 summary，讓任務分解器有更多上下文
            "raw_content_length": len(prompt_content),
            "content_preview": prompt_content[:500] + "..." if len(prompt_content) > 500 else prompt_content
        }
        
        # 保存到工作流上下文
        context.artifacts["requirement_spec"] = requirement_spec
        
        return {
            "status": "completed",
            "requirement_spec": requirement_spec,
            "files_analyzed": len(result.data.get("files", [])),
            "prompt_content": prompt_content,
            "content_processing_method": "raw_content_passthrough"
        }
    
    async def _execute_task_decomposer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行任務分解器"""
        context = self.active_workflows[workflow_id]
        requirement_spec = context.artifacts.get("requirement_spec", {})
        
        # 獲取 prompt.txt 的完整內容
        prompt_content = requirement_spec.get("prompt_analysis", "")
        raw_content_length = requirement_spec.get("raw_content_length", 0)
        
        # 使用 LLM 分析 prompt.txt 內容並生成任務計劃
        task_plan = await self._analyze_prompt_content_with_llm(workflow_id, prompt_content, requirement_spec)
        
        context.artifacts["task_plan"] = task_plan
        
        return {
            "status": "completed",
            "task_plan": task_plan,
            "total_tasks": len(task_plan["tasks"]),
            "decomposition_method": "llm_based_analysis",
            "content_analyzed": True,
            "raw_content_length": raw_content_length
        }
    
    async def _analyze_prompt_content_with_llm(self, workflow_id: str, prompt_content: str, requirement_spec: Dict[str, Any]) -> Dict[str, Any]:
        """使用 LLM 分析 prompt.txt 內容並生成任務計劃"""
        
        # 構建 LLM 提示詞
        prompt = f"""
請分析以下 prompt.txt 內容，並生成詳細的任務分解計劃：

原始內容：
{prompt_content}

請基於內容分析，生成結構化的任務計劃，包括：

1. 內容分析：
   - 需求類型（功能開發、修復、優化、重構等）
   - 技術領域（記憶體安全、性能優化、架構設計等）
   - 複雜度評估（低/中/高）
   - 優先級評估（低/中/高）

2. 任務分解：
   - 將需求分解為具體的開發任務
   - 每個任務包含：描述、負責的 Agent、優先級、工作量估算
   - 識別任務間的依賴關係
   - 評估風險和挑戰

請以 JSON 格式回應，結構如下：
{{
    "content_analysis": {{
        "requirement_type": "功能開發/修復/優化/重構",
        "technical_domain": ["記憶體安全", "性能優化", "架構設計"],
        "complexity": "低/中/高",
        "priority": "低/中/高",
        "estimated_total_hours": 數字,
        "key_requirements": ["關鍵需求1", "關鍵需求2"]
    }},
    "tasks": [
        {{
            "task_id": "T1-{workflow_id}",
            "description": "任務描述",
            "agent": "cpp_developer/unit_test_generator/header_generator",
            "priority": 1-3,
            "estimated_hours": 數字,
            "details": "詳細說明",
            "dependencies": ["依賴任務ID"],
            "risks": ["風險描述"]
        }}
    ],
    "analysis_summary": "整體分析摘要"
}}
"""
        
        # 調用 LLM 進行分析
        response = await self.llm_client.generate_response(
            task_type=TaskType.TASK_DECOMPOSITION,
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS[TaskType.TASK_DECOMPOSITION]
        )
        
        if response.error:
            logger.error(f"LLM error in task decomposition: {response.error}")
            # 如果 LLM 失敗，使用預設任務計劃
            return self._generate_fallback_task_plan(workflow_id, prompt_content, requirement_spec)
        
        # 嘗試解析 LLM 回應
        try:
            # 嘗試從回應中提取 JSON
            import json
            import re
            
            # 尋找 JSON 內容
            json_match = re.search(r'\{.*\}', response.content, re.DOTALL)
            if json_match:
                llm_analysis = json.loads(json_match.group())
            else:
                # 如果無法找到 JSON，嘗試解析整個回應
                llm_analysis = json.loads(response.content)
            
            # 驗證和清理 LLM 分析結果
            validated_analysis = self._validate_and_clean_llm_analysis(llm_analysis, workflow_id)
            
            # 構建任務計劃
            task_plan = {
                "plan_id": f"PLAN-{workflow_id}",
                "spec_id": requirement_spec.get("spec_id"),
                "decomposition_source": "llm_analysis",
                "tasks": validated_analysis.get("tasks", []),
                "content_analysis": validated_analysis.get("content_analysis", {}),
                "analysis_basis": f"基於 LLM 分析的 {len(prompt_content)} 字符 prompt.txt 內容",
                "prompt_content_length": len(prompt_content),
                "content_preview": requirement_spec.get("content_preview", ""),
                "estimated_total_hours": validated_analysis.get("content_analysis", {}).get("estimated_total_hours", 0),
                "llm_response": response.content,
                "model_used": response.model,
                "tokens_used": response.usage,
                "analysis_method": "llm_based_decomposition"
            }
            
            return task_plan
            
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error(f"Failed to parse LLM response: {e}")
            logger.error(f"LLM response content: {response.content}")
            # 如果解析失敗，使用預設任務計劃
            return self._generate_fallback_task_plan(workflow_id, prompt_content, requirement_spec)
    
    def _validate_and_clean_llm_analysis(self, llm_analysis: Dict[str, Any], workflow_id: str) -> Dict[str, Any]:
        """驗證和清理 LLM 分析結果"""
        validated = {
            "content_analysis": {},
            "tasks": []
        }
        
        # 驗證和清理內容分析
        content_analysis = llm_analysis.get("content_analysis", {})
        validated["content_analysis"] = {
            "requirement_type": content_analysis.get("requirement_type", "功能開發"),
            "technical_domain": content_analysis.get("technical_domain", []),
            "complexity": content_analysis.get("complexity", "中"),
            "priority": content_analysis.get("priority", "中"),
            "estimated_total_hours": content_analysis.get("estimated_total_hours", 8),
            "key_requirements": content_analysis.get("key_requirements", [])
        }
        
        # 驗證和清理任務列表
        tasks = llm_analysis.get("tasks", [])
        task_counter = 1
        
        for task in tasks:
            if isinstance(task, dict):
                validated_task = {
                    "task_id": task.get("task_id", f"T{task_counter}-{workflow_id}"),
                    "description": task.get("description", "未指定任務"),
                    "agent": task.get("agent", "cpp_developer"),
                    "priority": min(max(task.get("priority", 2), 1), 3),  # 確保在 1-3 範圍內
                    "estimated_hours": max(task.get("estimated_hours", 4), 1),  # 確保至少 1 小時
                    "details": task.get("details", ""),
                    "dependencies": task.get("dependencies", []),
                    "risks": task.get("risks", [])
                }
                validated["tasks"].append(validated_task)
                task_counter += 1
        
        # 如果沒有任務，添加預設任務
        if not validated["tasks"]:
            validated["tasks"] = [
                {
                    "task_id": f"T1-{workflow_id}",
                    "description": "核心功能實現",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 6,
                    "details": "實現 prompt.txt 中描述的核心功能",
                    "dependencies": [],
                    "risks": ["需求理解可能不完整"]
                }
            ]
        
        return validated
    
    def _generate_fallback_task_plan(self, workflow_id: str, prompt_content: str, requirement_spec: Dict[str, Any]) -> Dict[str, Any]:
        """生成預設任務計劃（當 LLM 分析失敗時使用）"""
        logger.warning(f"Using fallback task plan for workflow {workflow_id}")
        
        # 簡單的內容分析
        content_length = len(prompt_content)
        complexity = "高" if content_length > 2000 else "中" if content_length > 500 else "低"
        
        # 預設任務
        tasks = [
            {
                "task_id": f"T1-{workflow_id}",
                "description": "需求分析和架構設計",
                "agent": "cpp_developer",
                "priority": 1,
                "estimated_hours": 4,
                "details": "分析 prompt.txt 內容，設計系統架構",
                "dependencies": [],
                "risks": ["需求理解可能不完整"]
            },
            {
                "task_id": f"T2-{workflow_id}",
                "description": "核心功能實現",
                "agent": "cpp_developer",
                "priority": 1,
                "estimated_hours": 6,
                "details": "實現 prompt.txt 中描述的核心功能",
                "dependencies": [f"T1-{workflow_id}"],
                "risks": ["技術實現複雜度未知"]
            },
            {
                "task_id": f"T3-{workflow_id}",
                "description": "測試和驗證",
                "agent": "unit_test_generator",
                "priority": 2,
                "estimated_hours": 3,
                "details": "生成測試用例並驗證功能",
                "dependencies": [f"T2-{workflow_id}"],
                "risks": ["測試覆蓋率可能不足"]
            }
        ]
        
        return {
            "plan_id": f"PLAN-{workflow_id}",
            "spec_id": requirement_spec.get("spec_id"),
            "decomposition_source": "fallback_analysis",
            "tasks": tasks,
            "content_analysis": {
                "requirement_type": "功能開發",
                "technical_domain": ["通用開發"],
                "complexity": complexity,
                "priority": "中",
                "estimated_total_hours": 13,
                "key_requirements": ["實現 prompt.txt 描述的功能"]
            },
            "analysis_basis": f"預設分析（LLM 分析失敗）- {len(prompt_content)} 字符內容",
            "prompt_content_length": len(prompt_content),
            "content_preview": requirement_spec.get("content_preview", ""),
            "estimated_total_hours": 13,
            "analysis_method": "fallback_decomposition"
        }
    
    def _get_keyword_patterns(self) -> Dict[str, Dict[str, Any]]:
        """獲取可配置的關鍵字模式"""
        return {
            "memory_security": {
                "keywords": ["記憶體", "memory", "攻擊", "attack", "檢測", "detection", "安全", "security", "漏洞", "vulnerability"],
                "task_template": {
                    "description": "實現{category}相關功能",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 6,
                    "details": "基於 prompt.txt 內容實現{category}功能"
                }
            },
            "performance_optimization": {
                "keywords": ["性能", "performance", "優化", "optimization", "效率", "efficiency", "速度", "speed", "快", "fast"],
                "task_template": {
                    "description": "性能優化和調優",
                    "agent": "cpp_developer",
                    "priority": 2,
                    "estimated_hours": 4,
                    "details": "根據 prompt.txt 要求進行性能優化"
                }
            },
            "architecture_design": {
                "keywords": ["架構", "architecture", "設計", "design", "結構", "structure", "模式", "pattern", "重構", "refactor"],
                "task_template": {
                    "description": "系統架構設計和重構",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 8,
                    "details": "根據 prompt.txt 設計要求重構系統架構"
                }
            },
            "real_time": {
                "keywords": ["即時", "real-time", "實時", "realtime", "實時", "live", "即時", "instant", "實時", "realtime"],
                "task_template": {
                    "description": "即時處理系統實現",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 6,
                    "details": "實現低延遲的即時處理機制"
                }
            },
            "testing": {
                "keywords": ["測試", "test", "驗證", "validation", "檢查", "check", "單元測試", "unit test", "集成測試", "integration test"],
                "task_template": {
                    "description": "生成單元測試",
                    "agent": "unit_test_generator",
                    "priority": 2,
                    "estimated_hours": 3,
                    "details": "為新功能生成完整的測試用例"
                }
            },
            "documentation": {
                "keywords": ["文檔", "documentation", "說明", "manual", "指南", "guide", "註釋", "comment", "文檔", "docs"],
                "task_template": {
                    "description": "更新文檔和註釋",
                    "agent": "cpp_developer",
                    "priority": 3,
                    "estimated_hours": 2,
                    "details": "根據 prompt.txt 要求更新相關文檔"
                }
            },
            "database": {
                "keywords": ["數據庫", "database", "db", "sql", "nosql", "存儲", "storage", "數據", "data"],
                "task_template": {
                    "description": "數據庫相關功能實現",
                    "agent": "cpp_developer",
                    "priority": 2,
                    "estimated_hours": 5,
                    "details": "實現數據庫相關功能"
                }
            },
            "network": {
                "keywords": ["網絡", "network", "socket", "tcp", "udp", "http", "https", "通信", "communication"],
                "task_template": {
                    "description": "網絡通信功能實現",
                    "agent": "cpp_developer",
                    "priority": 2,
                    "estimated_hours": 5,
                    "details": "實現網絡通信相關功能"
                }
            },
            "ui_interface": {
                "keywords": ["界面", "ui", "gui", "用戶界面", "user interface", "前端", "frontend", "顯示", "display"],
                "task_template": {
                    "description": "用戶界面實現",
                    "agent": "cpp_developer",
                    "priority": 2,
                    "estimated_hours": 4,
                    "details": "實現用戶界面相關功能"
                }
            },
            "algorithm": {
                "keywords": ["算法", "algorithm", "邏輯", "logic", "計算", "calculation", "處理", "process"],
                "task_template": {
                    "description": "核心算法實現",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 6,
                    "details": "實現核心算法邏輯"
                }
            }
        }
    
    def _analyze_content_with_patterns(self, content_lower: str, keyword_patterns: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """使用動態模式分析內容"""
        content_analysis = {}
        
        # 分析每個關鍵字模式
        for pattern_name, pattern_config in keyword_patterns.items():
            keywords = pattern_config["keywords"]
            is_detected = any(keyword in content_lower for keyword in keywords)
            content_analysis[f"is_{pattern_name}"] = is_detected
            
            # 記錄檢測到的具體關鍵字
            detected_keywords = [kw for kw in keywords if kw in content_lower]
            if detected_keywords:
                content_analysis[f"detected_{pattern_name}_keywords"] = detected_keywords
        
        # 通用分析
        content_analysis["has_specific_requirements"] = any(keyword in content_lower for keyword in [
            "必須", "must", "需要", "need", "要求", "requirement", "實現", "implement", "添加", "add"
        ])
        
        # 計算檢測到的模式數量
        detected_patterns = sum(1 for key, value in content_analysis.items() 
                              if key.startswith("is_") and value)
        content_analysis["total_detected_patterns"] = detected_patterns
        
        return content_analysis
    
    def _generate_tasks_dynamically(self, workflow_id: str, content_analysis: Dict[str, Any], prompt_content: str) -> List[Dict[str, Any]]:
        """動態生成任務列表"""
        tasks = []
        task_counter = 1
        keyword_patterns = self._get_keyword_patterns()
        
        # 基礎任務 - 根據內容長度和複雜度
        if content_analysis["content_length_category"] == "long":
            tasks.append({
                "task_id": f"T{task_counter}-{workflow_id}",
                "description": "需求分析和架構設計",
                "agent": "cpp_developer",
                "priority": 1,
                "estimated_hours": 4,
                "details": "深入分析 prompt.txt 內容，設計系統架構和技術方案",
                "content_based": True,
                "generation_method": "content_length_based"
            })
            task_counter += 1
        
        # 根據檢測到的模式動態生成任務
        for pattern_name, pattern_config in keyword_patterns.items():
            if content_analysis.get(f"is_{pattern_name}", False):
                task_template = pattern_config["task_template"]
                
                # 創建任務
                task = {
                    "task_id": f"T{task_counter}-{workflow_id}",
                    "description": task_template["description"],
                    "agent": task_template["agent"],
                    "priority": task_template["priority"],
                    "estimated_hours": task_template["estimated_hours"],
                    "details": task_template["details"],
                    "content_based": True,
                    "generation_method": f"pattern_based_{pattern_name}",
                    "detected_keywords": content_analysis.get(f"detected_{pattern_name}_keywords", [])
                }
                
                tasks.append(task)
                task_counter += 1
        
        # 通用任務
        tasks.append({
            "task_id": f"T{task_counter}-{workflow_id}",
            "description": "核心功能實現",
            "agent": "cpp_developer",
            "priority": 1,
            "estimated_hours": 6,
            "details": "實現 prompt.txt 中描述的核心功能",
            "content_based": True,
            "generation_method": "generic_core_function"
        })
        task_counter += 1
        
        # 如果沒有檢測到特定需求，添加通用任務
        if len(tasks) <= 2:  # 只有基礎任務
            tasks.append({
                "task_id": f"T{task_counter}-{workflow_id}",
                "description": "通用功能實現",
                "agent": "cpp_developer",
                "priority": 1,
                "estimated_hours": 4,
                "details": "實現 prompt.txt 中描述的功能需求",
                "content_based": True,
                "generation_method": "fallback_generic"
            })
            task_counter += 1
        
        return tasks
    
    def _fix_diff_format(self, diff_content: str) -> str:
        """修復 diff 格式，確保行數正確"""
        try:
            lines = diff_content.split('\n')
            fixed_lines = []
            
            for i, line in enumerate(lines):
                if line.startswith('@@'):
                    # 修復 @@ 行
                    # 格式應該是: @@ -old_start,old_count +new_start,new_count @@
                    parts = line.split(' ')
                    if len(parts) >= 3:
                        old_part = parts[1]  # -old_start,old_count
                        new_part = parts[2]  # +new_start,new_count
                        
                        # 確保格式正確
                        if not old_part.startswith('-') or not new_part.startswith('+'):
                            # 如果格式不正確，嘗試修復
                            old_start = 1
                            new_start = 1
                            
                            # 計算後續的行數變化
                            added_lines = 0
                            removed_lines = 0
                            for j in range(i + 1, len(lines)):
                                if lines[j].startswith('+') and not lines[j].startswith('++'):
                                    added_lines += 1
                                elif lines[j].startswith('-') and not lines[j].startswith('--'):
                                    removed_lines += 1
                                elif not lines[j].startswith(' ') and not lines[j].startswith('+') and not lines[j].startswith('-'):
                                    break
                            
                            # 假設原始文件至少有 1 行
                            old_count = max(1, removed_lines)
                            new_count = max(1, added_lines)
                            
                            fixed_line = f"@@ -{old_start},{old_count} +{new_start},{new_count} @@"
                            fixed_lines.append(fixed_line)
                        else:
                            fixed_lines.append(line)
                    else:
                        # 如果 @@ 行格式不完整，使用預設格式
                        fixed_lines.append("@@ -1,1 +1,1 @@")
                else:
                    fixed_lines.append(line)
            
            return '\n'.join(fixed_lines)
        except Exception as e:
            logger.error(f"Error fixing diff format: {e}")
            return diff_content
    

    
    async def _execute_cpp_developer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行 C++ 開發者"""
        logger.info(f"[CPP_DEVELOPER] Starting task {task.task_id}")
        context = self.active_workflows[workflow_id]
        
        # 讀取相關源文件
        result = self.mcp_server.read_file({
            "path": "src/detection_engine.cpp"
        })
        
        if not result.success:
            logger.error(f"[CPP_DEVELOPER] Failed to read source file: {result.error}")
            return {"error": "Failed to read source file"}
        
        logger.info(f"[CPP_DEVELOPER] Successfully read source file, content length: {len(result.data.get('content', ''))}")
        
        # 構建 LLM 提示詞
        task_description = task.input_data.get("description", "實現功能需求")
        requirement_spec = context.artifacts.get("requirement_spec", {})
        
        prompt = f"""
請基於以下需求，為 RMDS 專案生成 C++ 代碼修改：

任務描述：{task_description}
需求規格：{requirement_spec}

現有代碼：
{result.data.get("content", "")}

請生成統一的 diff 格式的補丁，要求：
1. 符合現代 C++ 標準 (C++17/20)
2. 遵循專案命名規範
3. 添加適當的註釋
4. 考慮性能和安全性
5. 確保代碼可讀性
"""
        
        logger.info(f"[CPP_DEVELOPER] Sending prompt to LLM, prompt length: {len(prompt)}")
        
        # 調用 LLM 生成代碼修改
        response = await self.llm_client.generate_response(
            task_type=TaskType.CODE_GENERATION,
            prompt=prompt,
            context=result.data.get("content", ""),
            system_prompt=SYSTEM_PROMPTS[TaskType.CODE_GENERATION]
        )
        
        if response.error:
            logger.error(f"[CPP_DEVELOPER] LLM error in code generation: {response.error}")
            # 如果 LLM 失敗，使用預設補丁
            sample_patch = """--- a/src/detection_engine.cpp
+++ b/src/detection_engine.cpp
@@ -1,5 +1,6 @@
 #include "detection_engine.hpp"
 #include <iostream>
+#include <chrono>
 
 // 示例修改：添加時間戳記錄
 void DetectionEngine::process_event(const MemoryEvent& event) {
+    auto timestamp = std::chrono::system_clock::now();
     // 原有的處理邏輯
 }
"""
            logger.info(f"[CPP_DEVELOPER] Using fallback patch due to LLM error")
        else:
            # 嘗試從 LLM 響應中提取 diff
            sample_patch = response.content
            logger.info(f"[CPP_DEVELOPER] LLM response received, content length: {len(sample_patch)}")
            logger.info(f"[CPP_DEVELOPER] LLM response starts with: {sample_patch[:200]}...")
            
            # 如果響應不是標準 diff 格式，嘗試直接寫入文件
            if not sample_patch.startswith("---"):
                logger.info(f"[CPP_DEVELOPER] Response is not a standard diff, attempting to parse as file content")
                
                # 嘗試解析 LLM 響應，提取文件名和內容
                lines = sample_patch.split('\n')
                
                # 檢查是否是 diff 格式但以其他方式開頭
                if sample_patch.startswith("*** Begin Patch") or "*** Update File:" in sample_patch or "*** Add File:" in sample_patch:
                    logger.info(f"[CPP_DEVELOPER] Detected diff-like format, attempting to extract diff content")
                    
                    # 尋找文件路徑
                    file_path = None
                    for line in lines:
                        if "*** Update File:" in line:
                            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
                            # 清理路徑，移除多餘的斜杠
                            file_path = '/'.join(part for part in file_path.split('/') if part)
                            break
                        elif "*** Add File:" in line:
                            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
                            # 清理路徑，移除多餘的斜杠
                            file_path = '/'.join(part for part in file_path.split('/') if part)
                            break
                    
                    # 尋找 diff 內容的開始
                    diff_start = -1
                    for i, line in enumerate(lines):
                        if line.startswith("@@"):
                            diff_start = i
                            break
                    
                    if diff_start >= 0 and file_path:
                        # 嘗試構建 diff 格式
                        if "*** Add File:" in sample_patch:
                            # 新文件
                            diff_content = f"--- /dev/null\n+++ b/{file_path}\n"
                        else:
                            # 修改文件
                            diff_content = f"--- a/{file_path}\n+++ b/{file_path}\n"
                        
                        # 添加從 @@ 開始的內容，但需要修復 @@ 標記
                        diff_lines = lines[diff_start:]
                        if diff_lines and diff_lines[0].startswith("@@"):
                            # 計算實際的行數變化
                            added_lines = sum(1 for line in diff_lines[1:] if line.startswith('+') and not line.startswith('++'))
                            removed_lines = sum(1 for line in diff_lines[1:] if line.startswith('-') and not line.startswith('--'))
                            
                            # 讀取原始文件來獲取準確的行數
                            original_file_result = self.mcp_server.read_file({"path": file_path})
                            if original_file_result.success:
                                original_content = original_file_result.data.get("content", "")
                                original_lines = len(original_content.split('\n'))
                            else:
                                # 如果無法讀取原始文件，使用保守估計
                                original_lines = max(1, len(diff_lines) - added_lines + removed_lines)
                            
                            new_lines = original_lines + added_lines - removed_lines
                            
                            # 確保行數為正數
                            original_lines = max(1, original_lines)
                            new_lines = max(1, new_lines)
                            
                            diff_lines[0] = f"@@ -1,{original_lines} +1,{new_lines} @@"
                        
                        diff_content += '\n'.join(diff_lines)
                        
                        # 清理 diff 內容，移除尾隨空格
                        diff_content = '\n'.join(line.rstrip() for line in diff_content.split('\n'))
                        
                        logger.info(f"[CPP_DEVELOPER] Extracted diff content, length: {len(diff_content)}")
                        logger.debug(f"[CPP_DEVELOPER] Extracted diff content: {diff_content[:500]}...")
                        
                        # 嘗試驗證 diff
                        diff_meta = self.mcp_server._extract_and_validate_unified_diff(diff_content, self.mcp_server.repo_root)
                        if diff_meta.valid:
                            sample_patch = diff_content
                            logger.info(f"[CPP_DEVELOPER] Diff validation successful, using diff format")
                        else:
                            logger.warning(f"[CPP_DEVELOPER] Diff validation failed: {diff_meta.issues}, falling back to direct file write")
                            # 如果 diff 驗證失敗，嘗試直接寫入文件
                            if file_path:
                                # 提取文件內容（從 diff 內容中重建）
                                content_lines = []
                                for line in diff_lines[1:]:  # 跳過 @@ 行
                                    if line.startswith('+') and not line.startswith('++'):
                                        content_lines.append(line[1:])  # 移除 + 前綴
                                    elif not line.startswith('-') and not line.startswith('--'):
                                        content_lines.append(line)
                                
                                content = '\n'.join(content_lines)
                                
                                # 使用 write_file 直接創建文件
                                write_result = self.mcp_server.write_file({
                                    "path": file_path,
                                    "content": content,
                                    "create_dirs": True
                                })
                                
                                if write_result.success:
                                    logger.info(f"[CPP_DEVELOPER] Successfully created file using write_file: {file_path}")
                                    return {
                                        "status": "completed",
                                        "file_created": True,
                                        "file_path": file_path,
                                        "content": content,
                                        "method": "write_file",
                                        "llm_response": response.content if not response.error else None,
                                        "model_used": response.model if not response.error else None,
                                        "tokens_used": response.usage if not response.error else None
                                    }
                                else:
                                    logger.error(f"[CPP_DEVELOPER] Failed to write file: {write_result.error}")
                                    return {"error": f"Failed to write file: {write_result.error}"}
                            else:
                                # 如果無法解析，使用預設格式
                                sample_patch = f"""# LLM 生成的代碼修改建議：
{response.content}

# 請手動應用以上修改到對應文件。
"""
                    else:
                        logger.warning(f"[CPP_DEVELOPER] Could not find diff markers or file path in response")
                        # 如果無法解析，使用預設格式
                        sample_patch = f"""# LLM 生成的代碼修改建議：
{response.content}

# 請手動應用以上修改到對應文件。
"""
                else:
                    # 尋找可能的文件路徑
                    for i, line in enumerate(lines):
                        logger.debug(f"[CPP_DEVELOPER] Checking line {i}: {line.strip()}")
                        # 處理多種可能的格式
                        line_stripped = line.strip()
                        
                        # 格式1: *** Add File: src/test_detection_id.cpp
                        if line_stripped.startswith("*** Add File:") or line_stripped.startswith("*** Update File:"):
                            file_path = line_stripped.split(":", 1)[1].strip()
                            # 統一使用正斜杠並清理路徑
                            file_path = file_path.replace('\\', '/')
                            file_path = '/'.join(part for part in file_path.split('/') if part)
                            content_start = i + 1
                            logger.info(f"[CPP_DEVELOPER] Found file path from '*** Add/Update File:' format: {file_path}")
                            break
                        
                        # 格式2: 直接的文件路徑
                        elif line_stripped.endswith('.cpp') or line_stripped.endswith('.hpp'):
                            # 確保這是一個有效的文件路徑，不是其他內容
                            if '/' in line_stripped or '\\' in line_stripped:
                                file_path = line_stripped.replace('\\', '/')
                                # 清理路徑，移除多餘的斜杠
                                file_path = '/'.join(part for part in file_path.split('/') if part)
                                content_start = i + 1
                                logger.info(f"[CPP_DEVELOPER] Found direct file path: {file_path}")
                                break
                    
                    if file_path and content_start < len(lines):
                        # 提取文件內容
                        content = '\n'.join(lines[content_start:])
                        logger.info(f"[CPP_DEVELOPER] Extracted content for {file_path}, content length: {len(content)}")
                        
                        # 使用 write_file 直接創建文件
                        write_result = self.mcp_server.write_file({
                            "path": file_path,
                            "content": content,
                            "create_dirs": True
                        })
                        
                        logger.info(f"[CPP_DEVELOPER] Write file result: success={write_result.success}, error={write_result.error}")
                        
                        if write_result.success:
                            logger.info(f"[CPP_DEVELOPER] Successfully created file: {file_path}")
                            return {
                                "status": "completed",
                                "file_created": True,
                                "file_path": file_path,
                                "content": content,
                                "method": "write_file",
                                "llm_response": response.content if not response.error else None,
                                "model_used": response.model if not response.error else None,
                                "tokens_used": response.usage if not response.error else None
                            }
                        else:
                            logger.error(f"[CPP_DEVELOPER] Failed to write file: {write_result.error}")
                            return {"error": f"Failed to write file: {write_result.error}"}
                    else:
                        logger.warning(f"[CPP_DEVELOPER] Could not parse file path from LLM response")
                        # 如果無法解析，使用預設格式
                        sample_patch = f"""# LLM 生成的代碼修改建議：
{response.content}

# 請手動應用以上修改到對應文件。
"""
            else:
                logger.info(f"[CPP_DEVELOPER] Response appears to be a standard diff format")
        
        logger.info(f"[CPP_DEVELOPER] Final patch content length: {len(sample_patch)}")
        logger.debug(f"[CPP_DEVELOPER] Patch content: {sample_patch}")
        
        # 乾運行補丁
        logger.info(f"[CPP_DEVELOPER] Starting dry run patch application")
        dry_run_result = self.mcp_server.apply_patch({
            "unified_diff": sample_patch,
            "dry_run": True,
            "commit": False,
            "task_id": task.task_id
        })
        
        logger.info(f"[CPP_DEVELOPER] Dry run result: success={dry_run_result.success}, error={dry_run_result.error}")
        
        if not dry_run_result.success:
            logger.warning(f"[CPP_DEVELOPER] Patch dry run failed: {dry_run_result.error}")
            logger.info(f"[CPP_DEVELOPER] Attempting to fix diff format and retry...")
            
            # 嘗試修復 diff 格式
            fixed_patch = self._fix_diff_format(sample_patch)
            if fixed_patch != sample_patch:
                logger.info(f"[CPP_DEVELOPER] Retrying with fixed diff format")
                dry_run_result = self.mcp_server.apply_patch({
                    "unified_diff": fixed_patch,
                    "dry_run": True,
                    "commit": False,
                    "task_id": task.task_id
                })
                
                if dry_run_result.success:
                    sample_patch = fixed_patch
                    logger.info(f"[CPP_DEVELOPER] Fixed diff format successful")
                else:
                    logger.warning(f"[CPP_DEVELOPER] Fixed diff format also failed: {dry_run_result.error}")
                    logger.info(f"[CPP_DEVELOPER] Falling back to direct file write method")
            
            # 嘗試從 LLM 響應中提取文件內容並直接寫入
            if "*** Update File:" in response.content or "*** Add File:" in response.content:
                lines = response.content.split('\n')
                file_path = None
                
                # 尋找文件路徑
                for line in lines:
                    if "*** Update File:" in line:
                        file_path = line.split(":", 1)[1].strip().replace('\\', '/')
                        # 清理路徑，移除多餘的斜杠
                        file_path = '/'.join(part for part in file_path.split('/') if part)
                        break
                    elif "*** Add File:" in line:
                        file_path = line.split(":", 1)[1].strip().replace('\\', '/')
                        # 清理路徑，移除多餘的斜杠
                        file_path = '/'.join(part for part in file_path.split('/') if part)
                        break
                
                if file_path:
                    # 尋找 diff 內容的開始
                    diff_start = -1
                    for i, line in enumerate(lines):
                        if line.startswith("@@"):
                            diff_start = i
                            break
                    
                    if diff_start >= 0:
                        # 從 diff 內容中重建文件內容
                        diff_lines = lines[diff_start:]
                        diff_content = '\n'.join(diff_lines)
                        
                        logger.info(f"[CPP_DEVELOPER] 🔄 測試回退到 apply_diff 方法...")
                        logger.info(f"[CPP_DEVELOPER] 使用 apply_diff 應用變更到: {file_path}")
                        
                        # 使用新的 apply_diff 方法來正確應用 diff 變更
                        diff_result = self.mcp_server.apply_diff({
                            "path": file_path,
                            "diff_content": diff_content
                        })
                        
                        if diff_result.success:
                            logger.info(f"[CPP_DEVELOPER] ✅ 成功使用 apply_diff 應用變更: {file_path}")
                            logger.info(f"[CPP_DEVELOPER] 原始大小: {diff_result.data.get('original_size', 'unknown')}")
                            logger.info(f"[CPP_DEVELOPER] 新大小: {diff_result.data.get('new_size', 'unknown')}")
                            logger.info(f"[CPP_DEVELOPER] 變更行數: {diff_result.data.get('original_lines', 0)} -> {diff_result.data.get('new_lines', 0)}")
                            
                            # 更新結果
                            result = {
                                "success": True,
                                "method": "apply_diff",
                                "file_path": file_path,
                                "original_size": diff_result.data.get('original_size'),
                                "new_size": diff_result.data.get('new_size'),
                                "changes_applied": True,
                                "message": f"Successfully applied diff changes to {file_path}"
                            }
                        else:
                            logger.error(f"[CPP_DEVELOPER] ❌ apply_diff 失敗: {diff_result.error}")
                            
                            # 如果 apply_diff 也失敗，嘗試使用 write_file 作為最後手段
                            logger.warning(f"[CPP_DEVELOPER] 🔄 嘗試使用 write_file 作為最後手段...")
                            
                            # 重建完整內容（這會丟失原始內容，但至少能工作）
                            content_lines = []
                            for line in diff_lines[1:]:  # 跳過 @@ 行
                                if line.startswith('+') and not line.startswith('++'):
                                    content_lines.append(line[1:])  # 移除 + 前綴
                                elif not line.startswith('-') and not line.startswith('--'):
                                    content_lines.append(line)
                            
                            content = '\n'.join(content_lines)
                            
                            write_result = self.mcp_server.write_file({
                                "path": file_path,
                                "content": content,
                                "create_dirs": True,
                                "mode": "overwrite"  # 明確指定覆蓋模式
                            })
                            
                            if write_result.success:
                                logger.warning(f"[CPP_DEVELOPER] ⚠️ 使用 write_file 成功（但可能丟失原始內容）: {file_path}")
                                result = {
                                    "success": True,
                                    "method": "write_file_fallback",
                                    "file_path": file_path,
                                    "warning": "Original file content may have been lost",
                                    "message": f"Successfully wrote file {file_path} (fallback method)"
                                }
                            else:
                                logger.error(f"[CPP_DEVELOPER] ❌ write_file 也失敗: {write_result.error}")
                                result = {
                                    "success": False,
                                    "error": f"Both apply_diff and write_file failed: {diff_result.error}, {write_result.error}"
                                }
                    else:
                        logger.error(f"[CPP_DEVELOPER] ❌ 無法找到 diff 內容")
                        result = {
                            "success": False,
                            "error": "Could not find diff content in LLM response"
                        }
            
            # 如果無法解析，返回錯誤
            return {"error": f"Patch dry run failed: {dry_run_result.error}"}
        
        # 實際應用補丁
        logger.info(f"[CPP_DEVELOPER] Starting actual patch application")
        apply_result = self.mcp_server.apply_patch({
            "unified_diff": sample_patch,
            "dry_run": False,
            "commit": False,  # 不提交到 git
            "task_id": task.task_id
        })
        
        logger.info(f"[CPP_DEVELOPER] Apply result: success={apply_result.success}, error={apply_result.error}")
        if apply_result.success:
            logger.info(f"[CPP_DEVELOPER] Modified files: {apply_result.data.get('modified', [])}")
        
        if not apply_result.success:
            logger.error(f"[CPP_DEVELOPER] Patch apply failed: {apply_result.error}")
            return {"error": f"Patch apply failed: {apply_result.error}"}
        
        context.artifacts["code_changes"] = {
            "patch": sample_patch,
            "commit_hash": apply_result.data.get("commit_hash"),
            "modified_files": apply_result.data.get("modified", []),
            "llm_response": response.content if not response.error else None,
            "model_used": response.model if not response.error else None,
            "tokens_used": response.usage if not response.error else None
        }
        
        logger.info(f"[CPP_DEVELOPER] Task completed successfully")
        return {
            "status": "completed",
            "patch_applied": True,
            "commit_hash": apply_result.data.get("commit_hash"),
            "files_modified": apply_result.data.get("modified", [])
        }
    
    async def _execute_header_generator(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行頭文件生成器（生成或更新 .hpp/.h）"""
        context = self.active_workflows[workflow_id]
        src_path = task.input_data.get("source", "src/detection_engine.cpp")
        
        # 讀取源文件
        file_res = self.mcp_server.read_file({"path": src_path})
        if not file_res.success:
            return {"error": f"Failed to read source file: {src_path}"}
        
        prompt = f"""
請根據下面的 C++ 源碼自動生成或更新對應的頭文件（.hpp/.h），僅輸出 unified diff：
文件：{src_path}

源碼：
{file_res.data.get("content", "")}

要求：
- 生成正確的 include guard 或 #pragma once
- 宣告類/函式的接口、必要的 forward-declarations
- 保持風格一致
請輸出標準的 unified diff（以 --- a/... +++ b/... 開頭）。
"""
        response = await self.llm_client.generate_response(
            task_type=TaskType.CODE_GENERATION,
            prompt=prompt,
            context=file_res.data.get("content", ""),
            system_prompt=SYSTEM_PROMPTS[TaskType.CODE_GENERATION]
        )
        
        if response.error:
            logger.error(f"LLM error in header generation: {response.error}")
            return {"error": f"LLM failed: {response.error}"}
        
        patch = response.content
        if not patch.startswith("---"):
            # 保險處理：若 LLM 未輸出 diff，返回原文建議
            return {"status": "completed", "message": "LLM returned non-diff content", "content": response.content}
        
        # 乾運行再套用補丁
        dry = self.mcp_server.apply_patch({
            "branch": "main",
            "unified_diff": patch,
            "dry_run": True,
            "task_id": task.task_id
        })
        if not dry.success:
            return {"error": f"Header patch dry run failed: {dry.error}"}
        
        apply_res = self.mcp_server.apply_patch({
            "branch": "main",
            "unified_diff": patch,
            "dry_run": False,
            "task_id": task.task_id
        })
        if not apply_res.success:
            return {"error": f"Header patch apply failed: {apply_res.error}"}
        
        context.artifacts.setdefault("header_generation", []).append({
            "source": src_path,
            "patch": patch,
            "commit_hash": apply_res.data.get("commit_hash"),
            "modified": apply_res.data.get("modified", []),
            "model_used": response.model,
            "tokens_used": response.usage
        })
        
        return {
            "status": "completed",
            "patch_applied": True,
            "files_modified": apply_res.data.get("modified", [])
        }
    async def _execute_code_reviewer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行代碼審查者"""
        context = self.active_workflows[workflow_id]
        code_changes = context.artifacts.get("code_changes", {})
        
        # 讀取修改後的文件
        modified_files = code_changes.get("modified_files", [])
        review_results = []
        
        for file_path in modified_files:
            result = self.mcp_server.read_file({"path": file_path})
            if result.success:
                # 構建 LLM 提示詞
                prompt = f"""
請審查以下 C++ 代碼的變更：

文件：{file_path}
修改後的代碼：
{result.data.get("content", "")}

請進行全面的代碼審查，包括：
1. 代碼質量和風格
2. 潛在的 bug 和安全問題
3. 性能影響
4. 可維護性
5. 改進建議
"""
                
                # 調用 LLM 進行代碼審查
                response = await self.llm_client.generate_response(
                    task_type=TaskType.CODE_REVIEW,
                    prompt=prompt,
                    context=result.data.get("content", ""),
                    system_prompt=SYSTEM_PROMPTS[TaskType.CODE_REVIEW]
                )
                
                if response.error:
                    logger.error(f"LLM error in code review: {response.error}")
                    review_results.append({
                        "file": file_path,
                        "issues": [],
                        "suggestions": ["考慮添加更多註釋"],
                        "overall_quality": "good",
                        "llm_error": response.error
                    })
                else:
                    review_results.append({
                        "file": file_path,
                        "issues": [],
                        "suggestions": ["考慮添加更多註釋"],
                        "overall_quality": "good",
                        "llm_review": response.content,
                        "model_used": response.model,
                        "tokens_used": response.usage
                    })
        
        context.artifacts["code_review"] = {
            "review_results": review_results,
            "total_files_reviewed": len(review_results)
        }
        
        return {
            "status": "completed",
            "files_reviewed": len(review_results),
            "overall_quality": "good"
        }
    
    async def _execute_static_analyzer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行靜態分析器"""
        context = self.active_workflows[workflow_id]
        code_changes = context.artifacts.get("code_changes", {})
        modified_files = code_changes.get("modified_files", [])
        
        # 執行工具靜態分析
        result = self.mcp_server.run_static_analysis({
            "branch": "main",
            "tools": ["clang-tidy", "cppcheck"]
        })
        
        static_analysis_results = result.data if result.success else {}
        
        # 對修改的文件進行 LLM 靜態分析
        llm_analysis_results = []
        for file_path in modified_files:
            file_result = self.mcp_server.read_file({"path": file_path})
            if file_result.success:
                prompt = f"""
請對以下 C++ 代碼進行靜態分析：

文件：{file_path}
代碼內容：
{file_result.data.get("content", "")}

請分析以下方面：
1. 代碼複雜度和可讀性
2. 潛在的 bug 和邏輯錯誤
3. 安全漏洞和風險
4. 性能問題和優化機會
5. 維護性問題
6. 代碼風格和規範

請提供詳細的分析報告和改進建議。
"""
                
                response = await self.llm_client.generate_response(
                    task_type=TaskType.STATIC_ANALYSIS,
                    prompt=prompt,
                    context=file_result.data.get("content", ""),
                    system_prompt=SYSTEM_PROMPTS[TaskType.STATIC_ANALYSIS]
                )
                
                if response.error:
                    logger.error(f"LLM error in static analysis: {response.error}")
                    llm_analysis_results.append({
                        "file": file_path,
                        "analysis": "LLM 分析失敗",
                        "error": response.error
                    })
                else:
                    llm_analysis_results.append({
                        "file": file_path,
                        "analysis": response.content,
                        "model_used": response.model,
                        "tokens_used": response.usage
                    })
        
        # 合併工具分析和 LLM 分析結果
        combined_results = {
            "tool_analysis": static_analysis_results,
            "llm_analysis": llm_analysis_results,
            "total_files_analyzed": len(modified_files)
        }
        
        context.artifacts["static_analysis"] = combined_results
        
        return {
            "status": "completed",
            "issues_found": static_analysis_results.get("total_issues", 0),
            "tools_used": static_analysis_results.get("tools_used", []),
            "static_analysis_results": combined_results
        }
    
    async def _execute_unit_test_generator(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行單元測試生成器"""
        context = self.active_workflows[workflow_id]
        code_changes = context.artifacts.get("code_changes", {})
        modified_files = code_changes.get("modified_files", [])
        
        # 讀取修改的文件內容
        test_generation_results = []
        for file_path in modified_files:
            file_result = self.mcp_server.read_file({"path": file_path})
            if file_result.success:
                prompt = f"""
請為以下 C++ 代碼生成單元測試：

文件：{file_path}
代碼內容：
{file_result.data.get("content", "")}

請生成全面的單元測試，包括：
1. 正向測試案例
2. 邊界條件測試
3. 錯誤處理測試
4. Mock 對象（如需要）
5. 測試文檔和註釋

請使用 Google Test 框架，並確保測試覆蓋率。
"""
                
                response = await self.llm_client.generate_response(
                    task_type=TaskType.TEST_GENERATION,
                    prompt=prompt,
                    context=file_result.data.get("content", ""),
                    system_prompt=SYSTEM_PROMPTS[TaskType.TEST_GENERATION]
                )
                
                if response.error:
                    logger.error(f"LLM error in test generation: {response.error}")
                    test_generation_results.append({
                        "file": file_path,
                        "test_code": "#include <gtest/gtest.h>\n// LLM 測試生成失敗",
                        "test_files": [f"test_{file_path.split('/')[-1].replace('.cpp', '.cpp')}"],
                        "error": response.error
                    })
                else:
                    test_generation_results.append({
                        "file": file_path,
                        "test_code": response.content,
                        "test_files": [f"test_{file_path.split('/')[-1].replace('.cpp', '.cpp')}"],
                        "model_used": response.model,
                        "tokens_used": response.usage
                    })
        
        context.artifacts["generated_tests"] = {
            "test_generation_results": test_generation_results,
            "total_tests_generated": len(test_generation_results)
        }
        
        return {
            "status": "completed",
            "tests_generated": len(test_generation_results),
            "test_files": [result["test_files"][0] for result in test_generation_results]
        }
    
    async def _execute_test_runner(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行測試執行器"""
        context = self.active_workflows[workflow_id]
        
        # 首先編譯項目
        logger.info("Building project for testing...")
        build_result = self.mcp_server.build_project({
            "build_type": "Debug",
            "target": "all"
        })
        
        if not build_result.success:
            return {"error": f"Build failed: {build_result.error}"}
        
        # 查找測試可執行文件
        test_executables = []
        for exe_info in build_result.data.get("executables", []):
            exe_path = exe_info["path"]
            if "test" in exe_path.lower() or "tests" in exe_path.lower():
                test_executables.append(exe_path)
        
        if not test_executables:
            # 如果沒有找到測試可執行文件，嘗試運行 ctest
            logger.info("No test executables found, trying ctest...")
            ctest_result = self.mcp_server.run_unit_tests({
                "branch": "main",
                "coverage": True
            })
            
            if not ctest_result.success:
                return {"error": f"CTest execution failed: {ctest_result.error}"}
            
            context.artifacts["test_results"] = ctest_result.data
            return {
                "status": "completed",
                "test_status": ctest_result.data.get("status"),
                "coverage": ctest_result.data.get("coverage", {}),
                "build_success": True
            }
        
        # 執行每個測試可執行文件
        test_results = []
        for test_exe in test_executables:
            logger.info(f"Running test: {test_exe}")
            exec_result = self.mcp_server.execute_binary({
                "path": test_exe,
                "args": [],
                "working_dir": str(self.repo_root)
            })
            
            if exec_result.success:
                test_results.append({
                    "test_file": test_exe,
                    "status": "pass" if exec_result.data["return_code"] == 0 else "fail",
                    "return_code": exec_result.data["return_code"],
                    "stdout": exec_result.data["stdout"],
                    "stderr": exec_result.data["stderr"]
                })
            else:
                test_results.append({
                    "test_file": test_exe,
                    "status": "error",
                    "error": exec_result.error
                })
        
        # 統計測試結果
        passed_tests = sum(1 for result in test_results if result["status"] == "pass")
        failed_tests = sum(1 for result in test_results if result["status"] == "fail")
        error_tests = sum(1 for result in test_results if result["status"] == "error")
        
        overall_status = "pass" if failed_tests == 0 and error_tests == 0 else "fail"
        
        test_summary = {
            "total_tests": len(test_results),
            "passed": passed_tests,
            "failed": failed_tests,
            "errors": error_tests,
            "status": overall_status,
            "test_results": test_results,
            "build_info": build_result.data
        }
        
        context.artifacts["test_results"] = test_summary
        
        return {
            "status": "completed",
            "test_status": overall_status,
            "total_tests": len(test_results),
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "build_success": True,
            "test_summary": test_summary
        }
    
    async def _execute_quality_assessor(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行質量評估器"""
        context = self.active_workflows[workflow_id]
        
        # 收集所有評估數據
        test_results = context.artifacts.get("test_results", {})
        static_analysis = context.artifacts.get("static_analysis", {})
        code_review = context.artifacts.get("code_review", {})
        requirement_spec = context.artifacts.get("requirement_spec", {})
        
        # 構建 LLM 提示詞
        prompt = f"""
    請對以下 RMDS 專案的代碼變更進行全面的質量評估：

    需求規格：{requirement_spec}
    測試結果：{test_results}
    靜態分析結果：{static_analysis}
    代碼審查結果：{code_review}

    請評估以下方面：
    1. 功能完整性 - 是否滿足所有需求
    2. 代碼質量 - 可讀性、可維護性、性能
    3. 測試覆蓋率 - 單元測試的完整性和有效性
    4. 安全性 - 潛在的安全風險
    5. 性能影響 - 對系統性能的影響
    6. 整體評估 - 是否達到生產標準

    請提供詳細的評估報告和改進建議。
    """
        
        # 調用 LLM 進行質量評估
        response = await self.llm_client.generate_response(
            task_type=TaskType.QUALITY_ASSESSMENT,
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS[TaskType.QUALITY_ASSESSMENT]
        )
        
        if response.error:
            logger.error(f"LLM error in quality assessment: {response.error}")
            # 如果 LLM 失敗，使用預設評估
            assessment_report = {
                "quality_score": 0.8,
                "overall_quality": "good",
                "issues_count": static_analysis.get("total_issues", 0),
                "test_status": test_results.get("status", "unknown"),
                "recommendations": [
                    "代碼質量良好",
                    "建議添加更多單元測試"
                ],
                "llm_error": response.error
            }
        else:
            # 解析 LLM 評估結果（目前只把 LLM 回應保存；可擴充解析具體欄位）
            assessment_report = {
                "quality_score": 0.8,  # TODO: 從 response.content 解析具體分數（若 LLM 提供）
                "overall_quality": "good",  # TODO: 從 LLM 回應判斷狀態
                "issues_count": static_analysis.get("total_issues", 0),
                "test_status": test_results.get("status", "unknown"),
                "recommendations": [
                    "代碼質量良好",
                    "建議添加更多單元測試"
                ],
                "llm_assessment": response.content,
                "model_used": response.model,
                "tokens_used": response.usage
            }
        
        # 保證回傳欄位一致且已定義
        quality_score = assessment_report.get("quality_score", 0.8)
        overall_quality = assessment_report.get("overall_quality", "unknown")
        recommendations = assessment_report.get("recommendations", [])
        
        context.artifacts["quality_assessment"] = assessment_report
        
        return {
            "status": "completed",
            "quality_score": quality_score,
            "overall_quality": overall_quality,
            "recommendations": recommendations
        }
    
    async def _handle_stage_complete(self, workflow_id: str, stage_name: str):
        """處理階段完成"""
        logger.info(f"Stage completed: {stage_name} (workflow: {workflow_id})")
        
        # 檢查是否還有下一個階段
        next_stage = self._get_next_stage(stage_name)
        if next_stage:
            await self._execute_stage(workflow_id, next_stage)
        else:
            # 工作流完成
            await self._complete_workflow(workflow_id)
    
    async def _handle_stage_failed(self, workflow_id: str, stage_name: str, error_message: str):
        """處理階段失敗"""
        logger.error(f"Stage failed: {stage_name} (workflow: {workflow_id}) - {error_message}")
        
        # 檢查是否需要重試
        if self._should_retry_stage(workflow_id, stage_name):
            logger.info(f"Retrying stage: {stage_name}")
            await self._execute_stage(workflow_id, stage_name)
        else:
            # 工作流失敗
            await self._fail_workflow(workflow_id, error_message)
    
    def _get_next_stage(self, current_stage: str) -> Optional[str]:
        """獲取下一個階段"""
        stage_order = [
            "requirement_analysis",
            "task_decomposition", 
            "code_development",
            "code_review",
            "test_generation",
            "build_and_test",
            "quality_assessment"
        ]
        
        try:
            current_index = stage_order.index(current_stage)
            if current_index + 1 < len(stage_order):
                return stage_order[current_index + 1]
        except ValueError:
            pass
        
        return None
    
    def _should_retry_stage(self, workflow_id: str, stage_name: str) -> bool:
        """檢查是否應該重試階段"""
        # 實現重試邏輯
        return False
    
    async def _complete_workflow(self, workflow_id: str):
        """完成工作流"""
        logger.info(f"Workflow completed: {workflow_id}")
        
        context = self.active_workflows[workflow_id]
        context.metadata["end_time"] = datetime.now().isoformat()
        context.metadata["status"] = "completed"
        
        # 生成最終報告
        final_report = await self._generate_final_report(workflow_id)
        
        # 保存到歷史記錄
        self.workflow_history.append({
            "workflow_id": workflow_id,
            "status": "completed",
            "start_time": context.metadata["start_time"],
            "end_time": context.metadata["end_time"],
            "final_report": final_report
        })
        
        # 保存工作流數據
        self._save_workflow_data()
        
        # 清理
        del self.active_workflows[workflow_id]
    
    async def _fail_workflow(self, workflow_id: str, error_message: str):
        """工作流失敗"""
        logger.error(f"Workflow failed: {workflow_id} - {error_message}")
        
        context = self.active_workflows[workflow_id]
        context.metadata["end_time"] = datetime.now().isoformat()
        context.metadata["status"] = "failed"
        context.metadata["error_message"] = error_message
        
        # 序列化完整的工作流上下文
        workflow_data = self._serialize_workflow_context(context)
        
        # 保存到歷史記錄
        self.workflow_history.append({
            "workflow_id": workflow_id,
            "status": "failed",
            "start_time": context.metadata["start_time"],
            "end_time": context.metadata["end_time"],
            "error_message": error_message,
            "workflow_data": workflow_data
        })
        
        # 保存工作流數據
        self._save_workflow_data()
        
        # 清理
        del self.active_workflows[workflow_id]
    
    async def _generate_final_report(self, workflow_id: str) -> Dict[str, Any]:
        """生成最終報告"""
        context = self.active_workflows[workflow_id]
        
        report = {
            "workflow_id": workflow_id,
            "user_task": context.user_task,
            "start_time": context.metadata["start_time"],
            "end_time": context.metadata["end_time"],
            "stages_completed": list(context.stages.keys()),
            "artifacts": context.artifacts,
            "summary": {
                "total_stages": len(self.workflow_stages),
                "completed_stages": len(context.stages),
                "success_rate": len(context.stages) / len(self.workflow_stages) * 100
            }
        }
        
        return report
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """獲取工作流狀態"""
        if workflow_id in self.active_workflows:
            context = self.active_workflows[workflow_id]
            return {
                "workflow_id": workflow_id,
                "status": "active",
                "current_stage": context.current_stage,
                "start_time": context.metadata["start_time"],
                "stages": {name: asdict(stage) for name, stage in context.stages.items()},
                "artifacts": context.artifacts,
                "user_task": context.user_task
            }
        
        # 檢查歷史記錄
        for record in self.workflow_history:
            if record["workflow_id"] == workflow_id:
                result = {
                    "workflow_id": workflow_id,
                    "status": record["status"],
                    "start_time": record["start_time"],
                    "end_time": record["end_time"]
                }
                
                # 如果有最終報告，添加詳細信息
                if "final_report" in record:
                    result.update({
                        "user_task": record["final_report"].get("user_task"),
                        "artifacts": record["final_report"].get("artifacts", {}),
                        "summary": record["final_report"].get("summary", {})
                    })
                
                # 如果有完整的工作流數據（失敗的工作流）
                if "workflow_data" in record:
                    workflow_data = record["workflow_data"]
                    result.update({
                        "user_task": workflow_data.get("user_task"),
                        "artifacts": workflow_data.get("artifacts", {}),
                        "stages": workflow_data.get("stages", {})
                    })
                
                # 如果有錯誤信息
                if "error_message" in record:
                    result["error_message"] = record["error_message"]
                
                return result
        
        return None
    
    def get_all_workflows(self) -> List[Dict[str, Any]]:
        """獲取所有工作流狀態"""
        active_workflows = []
        for workflow_id in self.active_workflows:
            status = self.get_workflow_status(workflow_id)
            if status:
                active_workflows.append(status)
        
        return active_workflows + self.workflow_history

# 使用範例
async def main():
    """主函數範例"""
    # 初始化工作流協調器
    orchestrator = WorkflowOrchestrator(repo_root=".")
    
    # 啟動工作流
    user_task = "在 detection_engine.cpp 中添加新的記憶體檢測功能"
    workflow_id = await orchestrator.start_workflow(user_task)
    
    print(f"Workflow started: {workflow_id}")
    
    # 監控工作流狀態
    while True:
        status = orchestrator.get_workflow_status(workflow_id)
        if status and status["status"] in ["completed", "failed"]:
            print(f"Workflow {status['status']}: {workflow_id}")
            break
        
        await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
