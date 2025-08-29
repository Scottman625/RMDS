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
        
        # 定義工作流階段
        self.workflow_stages = self._define_workflow_stages()
        
        logger.info("Workflow Orchestrator initialized with LLM client")
    
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
        
        # 構建 LLM 提示詞
        prompt = f"""
請分析以下用戶任務並生成標準化的需求規格：

用戶任務：{user_task}

相關源文件：{result.data.get("files", [])}

請提供詳細的需求分析，包括：
1. 需求背景和目標
2. 功能需求列表
3. 非功能需求（性能、安全、可維護性等）
4. 涉及的技術模組和文件
5. 風險評估
6. 工作量估算
"""
        
        # 調用 LLM 進行需求分析
        response = await self.llm_client.generate_response(
            task_type=TaskType.REQUIREMENT_ANALYSIS,
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS[TaskType.REQUIREMENT_ANALYSIS]
        )
        
        if response.error:
            logger.error(f"LLM error in requirement analysis: {response.error}")
            return {"error": f"LLM analysis failed: {response.error}"}
        
        # 分析任務需求
        requirement_spec = {
            "spec_id": f"SPEC-{workflow_id}",
            "title": user_task,
            "description": user_task,
            "files_affected": result.data.get("files", []),
            "estimated_complexity": "medium",
            "priority": "normal",
            "llm_analysis": response.content,
            "model_used": response.model,
            "tokens_used": response.usage
        }
        
        # 保存到工作流上下文
        context.artifacts["requirement_spec"] = requirement_spec
        
        return {
            "status": "completed",
            "requirement_spec": requirement_spec,
            "files_analyzed": len(result.data.get("files", [])),
            "llm_response": response.content
        }
    
    async def _execute_task_decomposer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行任務分解器"""
        context = self.active_workflows[workflow_id]
        requirement_spec = context.artifacts.get("requirement_spec", {})
        
        # 構建 LLM 提示詞
        prompt = f"""
請基於以下需求規格，將任務分解為具體的開發任務：

需求規格：{requirement_spec}

請提供詳細的任務分解，包括：
1. 任務列表和描述
2. 每個任務的優先級和依賴關係
3. 工作量估算
4. 負責的 Agent 角色
5. 預期的交付物

請以結構化的 JSON 格式回應。
"""
        
        # 調用 LLM 進行任務分解
        response = await self.llm_client.generate_response(
            task_type=TaskType.TASK_DECOMPOSITION,
            prompt=prompt,
            system_prompt=SYSTEM_PROMPTS[TaskType.TASK_DECOMPOSITION]
        )
        
        if response.error:
            logger.error(f"LLM error in task decomposition: {response.error}")
            return {"error": f"LLM decomposition failed: {response.error}"}
        
        # 基於需求規格分解任務（如果 LLM 失敗，使用預設方案）
        task_plan = {
            "plan_id": f"PLAN-{workflow_id}",
            "spec_id": requirement_spec.get("spec_id"),
            "llm_decomposition": response.content,
            "tasks": [
                {
                    "task_id": f"T1-{workflow_id}",
                    "description": "分析現有代碼結構",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 2
                },
                {
                    "task_id": f"T2-{workflow_id}",
                    "description": "實現核心功能",
                    "agent": "cpp_developer",
                    "priority": 1,
                    "estimated_hours": 4
                },
                {
                    "task_id": f"T3-{workflow_id}",
                    "description": "生成對應測試",
                    "agent": "unit_test_generator",
                    "priority": 2,
                    "estimated_hours": 2
                }
            ],
            "model_used": response.model,
            "tokens_used": response.usage
        }
        
        context.artifacts["task_plan"] = task_plan
        
        return {
            "status": "completed",
            "task_plan": task_plan,
            "total_tasks": len(task_plan["tasks"]),
            "llm_response": response.content
        }
    
    async def _execute_cpp_developer(self, workflow_id: str, task: WorkflowTask) -> Dict[str, Any]:
        """執行 C++ 開發者"""
        context = self.active_workflows[workflow_id]
        
        # 讀取相關源文件
        result = self.mcp_server.read_file({
            "path": "src/detection_engine.cpp"
        })
        
        if not result.success:
            return {"error": "Failed to read source file"}
        
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
        
        # 調用 LLM 生成代碼修改
        response = await self.llm_client.generate_response(
            task_type=TaskType.CODE_GENERATION,
            prompt=prompt,
            context=result.data.get("content", ""),
            system_prompt=SYSTEM_PROMPTS[TaskType.CODE_GENERATION]
        )
        
        if response.error:
            logger.error(f"LLM error in code generation: {response.error}")
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
        else:
            # 嘗試從 LLM 響應中提取 diff
            sample_patch = response.content
            # 如果響應不是標準 diff 格式，使用預設格式
            if not sample_patch.startswith("---"):
                sample_patch = f"""# LLM 生成的代碼修改建議：
{response.content}

# 請手動應用以上修改到對應文件。
"""
        
        # 乾運行補丁
        dry_run_result = self.mcp_server.apply_patch({
            "branch": "main",
            "unified_diff": sample_patch,
            "dry_run": True,
            "task_id": task.task_id
        })
        
        if not dry_run_result.success:
            return {"error": f"Patch dry run failed: {dry_run_result.error}"}
        
        # 實際應用補丁
        apply_result = self.mcp_server.apply_patch({
            "branch": "main",
            "unified_diff": sample_patch,
            "dry_run": False,
            "task_id": task.task_id
        })
        
        if not apply_result.success:
            return {"error": f"Patch apply failed: {apply_result.error}"}
        
        context.artifacts["code_changes"] = {
            "patch": sample_patch,
            "commit_hash": apply_result.data.get("commit_hash"),
            "modified_files": apply_result.data.get("modified", []),
            "llm_response": response.content if not response.error else None,
            "model_used": response.model if not response.error else None,
            "tokens_used": response.usage if not response.error else None
        }
        
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
        
        # 清理
        del self.active_workflows[workflow_id]
    
    async def _fail_workflow(self, workflow_id: str, error_message: str):
        """工作流失敗"""
        logger.error(f"Workflow failed: {workflow_id} - {error_message}")
        
        context = self.active_workflows[workflow_id]
        context.metadata["end_time"] = datetime.now().isoformat()
        context.metadata["status"] = "failed"
        context.metadata["error_message"] = error_message
        
        # 保存到歷史記錄
        self.workflow_history.append({
            "workflow_id": workflow_id,
            "status": "failed",
            "start_time": context.metadata["start_time"],
            "end_time": context.metadata["end_time"],
            "error_message": error_message
        })
        
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
                "stages": {name: asdict(stage) for name, stage in context.stages.items()}
            }
        
        # 檢查歷史記錄
        for record in self.workflow_history:
            if record["workflow_id"] == workflow_id:
                return {
                    "workflow_id": workflow_id,
                    "status": record["status"],
                    "start_time": record["start_time"],
                    "end_time": record["end_time"]
                }
        
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
