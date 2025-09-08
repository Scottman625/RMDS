#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
查看工作流狀態和詳細信息
"""

import asyncio
import json
from pathlib import Path
from workflow_orchestrator import WorkflowOrchestrator

async def check_workflow_status(workflow_id: str):
    """查看特定工作流的狀態"""
    
    orchestrator = WorkflowOrchestrator(repo_root="../", policy_file="policy.json")
    
    # 獲取工作流狀態
    status = orchestrator.get_workflow_status(workflow_id)
    
    if status:
        print(f"📋 工作流狀態報告")
        print(f"   ID: {workflow_id}")
        print(f"   狀態: {status['status']}")
        print(f"   開始時間: {status.get('start_time', 'N/A')}")
        print(f"   結束時間: {status.get('end_time', 'N/A')}")
        
        # 顯示階段信息
        stages = status.get('stages', {})
        print(f"\n📊 階段詳情:")
        for stage_name, stage_info in stages.items():
            stage_status = stage_info.get('status', 'unknown')
            start_time = stage_info.get('start_time', 'N/A')
            end_time = stage_info.get('end_time', 'N/A')
            
            print(f"   {stage_name}: {stage_status}")
            print(f"     開始: {start_time}")
            print(f"     結束: {end_time}")
            
            # 顯示任務詳情
            tasks = stage_info.get('tasks', [])
            for task in tasks:
                task_status = task.get('status', 'unknown')
                print(f"     - {task.get('task_id', 'unknown')}: {task_status}")
        
        # 顯示工件信息
        artifacts = status.get('artifacts', {})
        if artifacts:
            print(f"\n📦 工件:")
            for artifact_name, artifact_info in artifacts.items():
                print(f"   {artifact_name}: {type(artifact_info).__name__}")
    
    else:
        print(f"❌ 找不到工作流: {workflow_id}")

def check_mcp_logs(workflow_id: str):
    """查看 MCP 日誌中的工作流相關記錄"""
    
    log_file = Path("../logs/mcp_actions.log")
    if not log_file.exists():
        print("❌ MCP 日誌文件不存在")
        return
    
    print(f"🔍 在 MCP 日誌中搜索工作流: {workflow_id}")
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 搜索包含工作流 ID 的行
        workflow_lines = []
        for line in lines:
            if workflow_id in line:
                workflow_lines.append(line.strip())
        
        if workflow_lines:
            print(f"✅ 找到 {len(workflow_lines)} 條相關記錄")
            print("\n📝 最近的記錄:")
            for line in workflow_lines[-5:]:  # 顯示最後5條
                try:
                    data = json.loads(line)
                    action = data.get('action', 'unknown')
                    timestamp = data.get('timestamp', 'unknown')
                    print(f"   {timestamp}: {action}")
                except:
                    print(f"   {line[:100]}...")
        else:
            print("❌ 沒有找到相關記錄")
    
    except Exception as e:
        print(f"❌ 讀取日誌文件失敗: {e}")

if __name__ == "__main__":
    # 工作流 ID
    workflow_id = "wf_20250829_171626_dc1ba534"
    
    print("🔍 檢查工作流狀態...")
    asyncio.run(check_workflow_status(workflow_id))
    
    print("\n" + "="*50 + "\n")
    
    print("🔍 檢查 MCP 日誌...")
    check_mcp_logs(workflow_id)
