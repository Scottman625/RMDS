#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - Workflow Runner
工作流運行腳本
"""

import asyncio
import argparse
import logging
import sys
from pathlib import Path

from workflow_orchestrator import WorkflowOrchestrator

# 配置日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/workflow.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

async def run_workflow(user_task: str, repo_root: str = ".", policy_file: str = "policy.json"):
    """運行工作流"""
    try:
        # 確保日誌目錄存在
        Path("logs").mkdir(exist_ok=True)
        
        # 修正路徑：如果 repo_root 是相對路徑，則相對於 agent_system 目錄
        if not Path(repo_root).is_absolute():
            # 獲取 agent_system 目錄的父目錄（即專案根目錄）
            agent_system_dir = Path(__file__).parent
            repo_root = str(agent_system_dir.parent / repo_root)
        
        # 修正 policy_file 路徑
        if not Path(policy_file).is_absolute():
            policy_file = str(Path(__file__).parent / policy_file)
        
        # 初始化工作流協調器
        logger.info(f"Initializing workflow orchestrator with repo_root: {repo_root}")
        logger.info(f"Policy file: {policy_file}")
        orchestrator = WorkflowOrchestrator(repo_root=repo_root, policy_file=policy_file)
        
        # 啟動工作流
        logger.info(f"Starting workflow for task: {user_task}")
        workflow_id = await orchestrator.start_workflow(user_task)
        
        print(f"✅ 工作流已啟動: {workflow_id}")
        print(f"📋 任務: {user_task}")
        print("🔄 正在執行中...")
        
        # 監控工作流狀態
        while True:
            status = orchestrator.get_workflow_status(workflow_id)
            
            if status:
                if status["status"] == "active":
                    current_stage = status.get("current_stage", "unknown")
                    print(f"📍 當前階段: {current_stage}")
                    
                    # 顯示階段進度
                    stages = status.get("stages", {})
                    completed_stages = sum(1 for stage in stages.values() if stage.get("status") == "completed")
                    total_stages = len(stages)
                    
                    if total_stages > 0:
                        progress = (completed_stages / total_stages) * 100
                        print(f"📊 進度: {completed_stages}/{total_stages} 階段完成 ({progress:.1f}%)")
                
                elif status["status"] == "completed":
                    print("✅ 工作流完成！")
                    print(f"📅 開始時間: {status.get('start_time', 'N/A')}")
                    print(f"📅 結束時間: {status.get('end_time', 'N/A')}")
                    break
                
                elif status["status"] == "failed":
                    print("❌ 工作流失敗！")
                    print(f"📅 開始時間: {status.get('start_time', 'N/A')}")
                    print(f"📅 結束時間: {status.get('end_time', 'N/A')}")
                    print(f"💥 錯誤: {status.get('error_message', 'Unknown error')}")
                    break
            
            await asyncio.sleep(5)
        
        # 顯示最終報告
        print("\n📋 工作流報告:")
        print(f"   ID: {workflow_id}")
        print(f"   狀態: {status['status']}")
        print(f"   任務: {user_task}")
        
        return workflow_id, status["status"]
    
    except Exception as e:
        logger.error(f"Workflow execution failed: {e}")
        print(f"❌ 工作流執行失敗: {e}")
        return None, "failed"

async def list_workflows(repo_root: str = ".", policy_file: str = "policy.json"):
    """列出所有工作流"""
    try:
        # 修正路徑
        if not Path(repo_root).is_absolute():
            agent_system_dir = Path(__file__).parent
            repo_root = str(agent_system_dir.parent / repo_root)
        
        if not Path(policy_file).is_absolute():
            policy_file = str(Path(__file__).parent / policy_file)
        
        orchestrator = WorkflowOrchestrator(repo_root=repo_root, policy_file=policy_file)
        workflows = orchestrator.get_all_workflows()
        
        if not workflows:
            print("📭 沒有找到工作流")
            return
        
        print("📋 工作流列表:")
        print("-" * 80)
        
        for workflow in workflows:
            print(f"ID: {workflow['workflow_id']}")
            print(f"狀態: {workflow['status']}")
            print(f"開始時間: {workflow.get('start_time', 'N/A')}")
            if workflow.get('end_time'):
                print(f"結束時間: {workflow['end_time']}")
            if workflow.get('current_stage'):
                print(f"當前階段: {workflow['current_stage']}")
            print("-" * 80)
    
    except Exception as e:
        logger.error(f"Failed to list workflows: {e}")
        print(f"❌ 列出工作流失敗: {e}")

async def show_workflow_details(workflow_id: str, repo_root: str = ".", policy_file: str = "policy.json"):
    """顯示工作流詳細信息"""
    try:
        # 修正路徑
        if not Path(repo_root).is_absolute():
            agent_system_dir = Path(__file__).parent
            repo_root = str(agent_system_dir.parent / repo_root)
        
        if not Path(policy_file).is_absolute():
            policy_file = str(Path(__file__).parent / policy_file)
        
        orchestrator = WorkflowOrchestrator(repo_root=repo_root, policy_file=policy_file)
        status = orchestrator.get_workflow_status(workflow_id)
        
        if not status:
            print(f"❌ 找不到工作流: {workflow_id}")
            return
        
        print(f"📋 工作流詳細信息: {workflow_id}")
        print("=" * 80)
        print(f"狀態: {status['status']}")
        print(f"開始時間: {status.get('start_time', 'N/A')}")
        print(f"結束時間: {status.get('end_time', 'N/A')}")
        
        if status.get('user_task'):
            print(f"用戶任務: {status['user_task']}")
        
        if status.get('current_stage'):
            print(f"當前階段: {status['current_stage']}")
        
        if status.get('error_message'):
            print(f"錯誤信息: {status['error_message']}")
        
        if status.get('stages'):
            print("\n📊 階段詳情:")
            stages = status['stages']
            for stage_name, stage_data in stages.items():
                stage_status = stage_data.get('status', 'unknown')
                print(f"  {stage_name}: {stage_status}")
                
                if stage_data.get('tasks'):
                    for task in stage_data['tasks']:
                        task_status = task.get('status', 'unknown')
                        print(f"    - {task.get('agent_name', 'unknown')}: {task_status}")
        
        if status.get('artifacts'):
            print("\n📦 工作流產物:")
            artifacts = status['artifacts']
            for key, value in artifacts.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, str):
                            if len(sub_value) > 200:
                                print(f"    {sub_key}:")
                                print(f"      {sub_value[:200]}...")
                                print(f"      (內容長度: {len(sub_value)} 字符)")
                            else:
                                print(f"    {sub_key}: {sub_value}")
                        else:
                            print(f"    {sub_key}: {sub_value}")
                elif isinstance(value, str):
                    if len(value) > 200:
                        print(f"  {key}:")
                        print(f"    {value[:200]}...")
                        print(f"    (內容長度: {len(value)} 字符)")
                    else:
                        print(f"  {key}: {value}")
                else:
                    print(f"  {key}: {value}")
        
        if status.get('summary'):
            print("\n📈 工作流摘要:")
            summary = status['summary']
            for key, value in summary.items():
                print(f"  {key}: {value}")
        
        print("=" * 80)
    
    except Exception as e:
        logger.error(f"Failed to show workflow details: {e}")
        print(f"❌ 顯示工作流詳情失敗: {e}")

def main():
    """主函數"""
    parser = argparse.ArgumentParser(description="RMDS Agent Workflow Runner")
    parser.add_argument("command", choices=["run", "list", "show"], help="命令")
    parser.add_argument("--task", help="用戶任務描述")
    parser.add_argument("--workflow-id", help="工作流 ID")
    parser.add_argument("--repo-root", default=".", help="項目根目錄")
    parser.add_argument("--policy", default="policy.json", help="策略文件")
    
    args = parser.parse_args()
    
    if args.command == "run":
        # if not args.task:
        #     print("❌ 運行工作流需要提供 --task 參數")
        #     return
        
        asyncio.run(run_workflow(args.task, args.repo_root, args.policy))
    
    elif args.command == "list":
        asyncio.run(list_workflows(args.repo_root, args.policy))
    
    elif args.command == "show":
        if not args.workflow_id:
            print("❌ 顯示工作流詳情需要提供 --workflow-id 參數")
            return
        
        asyncio.run(show_workflow_details(args.workflow_id, args.repo_root, args.policy))

if __name__ == "__main__":
    main()
