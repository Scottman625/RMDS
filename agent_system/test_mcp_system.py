#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RMDS Agent System - MCP System Test
測試 MCP 系統的基本功能
"""

import asyncio
import logging
import sys
from pathlib import Path

# 添加當前目錄到 Python 路徑
sys.path.insert(0, str(Path(__file__).parent))

from mcp_server import MCPServer

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_mcp_server():
    """測試 MCP 服務器基本功能"""
    print("🧪 開始測試 MCP 服務器...")
    
    try:
        # 初始化 MCP 服務器
        print("📋 初始化 MCP 服務器...")
        server = MCPServer(repo_root="..")
        print("✅ MCP 服務器初始化成功")
        
        # 測試列出文件
        print("\n📁 測試列出文件...")
        result = server.list_files({"path": "src", "glob": "*.cpp"})
        if result.success:
            print(f"✅ 成功列出 {result.data.get('count', 0)} 個文件")
            files = result.data.get('files', [])
            for file_info in files[:3]:  # 只顯示前3個文件
                print(f"   - {file_info['path']}")
        else:
            print(f"❌ 列出文件失敗: {result.error}")
        
        # 測試讀取文件
        print("\n📖 測試讀取文件...")
        result = server.read_file({"path": "src/detection_engine.cpp"})
        if result.success:
            print(f"✅ 成功讀取文件，大小: {result.data.get('size', 0)} 字符")
            print(f"   行數: {result.data.get('lines', 0)}")
            print(f"   哈希: {result.data.get('hash', '')[:16]}...")
        else:
            print(f"❌ 讀取文件失敗: {result.error}")
        
        # 測試乾運行補丁
        print("\n🔧 測試乾運行補丁...")
        test_patch = """--- a/src/test_example.cpp
+++ b/src/test_example.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
 
 int main() {
+    std::cout << "Hello from test patch!" << std::endl;
     return 0;
 }
"""
        result = server.apply_patch({
            "branch": "main",
            "unified_diff": test_patch,
            "dry_run": True,
            "task_id": "test_task"
        })
        
        if result.success:
            print("✅ 乾運行補丁成功")
            if result.data.get("dry_run"):
                print(f"   將修改文件: {result.data.get('would_modify', [])}")
        else:
            print(f"❌ 乾運行補丁失敗: {result.error}")
        
        # 測試獲取操作日誌
        print("\n📊 測試獲取操作日誌...")
        result = server.get_action_log({"limit": 5})
        if result.success:
            print(f"✅ 成功獲取 {result.data.get('total_entries', 0)} 條日誌記錄")
        else:
            print(f"❌ 獲取日誌失敗: {result.error}")
        
        print("\n🎉 MCP 服務器測試完成！")
        return True
        
    except Exception as e:
        print(f"❌ MCP 服務器測試失敗: {e}")
        logger.error(f"Test failed: {e}")
        return False

async def test_workflow_orchestrator():
    """測試工作流協調器"""
    print("\n🧪 開始測試工作流協調器...")
    
    try:
        from workflow_orchestrator import WorkflowOrchestrator
        
        # 初始化工作流協調器
        print("📋 初始化工作流協調器...")
        orchestrator = WorkflowOrchestrator(repo_root="..")
        print("✅ 工作流協調器初始化成功")
        
        # 測試工作流階段定義
        print("\n📊 檢查工作流階段...")
        stages = orchestrator.workflow_stages
        print(f"✅ 定義了 {len(stages)} 個工作流階段:")
        for stage_name, stage_config in stages.items():
            print(f"   - {stage_name}: {stage_config['name']}")
        
        # 測試創建工作流（不實際執行）
        print("\n🔄 測試工作流創建...")
        test_task = "測試任務：在 detection_engine.cpp 中添加日誌功能"
        
        # 創建工作流上下文（模擬）
        workflow_id = f"test_wf_{int(asyncio.get_event_loop().time())}"
        print(f"✅ 模擬創建工作流: {workflow_id}")
        print(f"   任務: {test_task}")
        
        print("\n🎉 工作流協調器測試完成！")
        return True
        
    except Exception as e:
        print(f"❌ 工作流協調器測試失敗: {e}")
        logger.error(f"Workflow test failed: {e}")
        return False

def test_policy_config():
    """測試策略配置"""
    print("\n🧪 開始測試策略配置...")
    
    try:
        import json
        
        # 檢查策略文件
        policy_file = Path("policy.json")
        if policy_file.exists():
            with open(policy_file, 'r', encoding='utf-8') as f:
                policy = json.load(f)
            
            print("✅ 策略文件載入成功")
            print(f"   寫入允許: {len(policy.get('write_allow', []))} 個模式")
            print(f"   讀取允許: {len(policy.get('read_allow', []))} 個模式")
            print(f"   拒絕訪問: {len(policy.get('deny', []))} 個模式")
            print(f"   最大補丁大小: {policy.get('max_patch_size', 'N/A')} 行")
            print(f"   最大文件大小: {policy.get('max_file_size_mb', 'N/A')} MB")
        else:
            print("❌ 策略文件不存在")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ 策略配置測試失敗: {e}")
        return False

def main():
    """主測試函數"""
    print("🚀 RMDS Agent System - MCP 系統測試")
    print("=" * 50)
    
    # 檢查環境
    print("🔍 檢查環境...")
    if not Path("..").exists():
        print("❌ 請在 agent_system 目錄中運行此測試")
        return False
    
    if not Path("../src").exists():
        print("❌ 未找到 src 目錄，請確保在正確的項目結構中運行")
        return False
    
    print("✅ 環境檢查通過")
    
    # 運行測試
    tests = [
        ("策略配置", test_policy_config),
        ("MCP 服務器", test_mcp_server),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} 測試通過")
            else:
                print(f"❌ {test_name} 測試失敗")
        except Exception as e:
            print(f"❌ {test_name} 測試異常: {e}")
    
    # 測試工作流協調器（異步）
    print(f"\n{'='*20} 工作流協調器 {'='*20}")
    try:
        if asyncio.run(test_workflow_orchestrator()):
            passed += 1
            print("✅ 工作流協調器測試通過")
        else:
            print("❌ 工作流協調器測試失敗")
    except Exception as e:
        print(f"❌ 工作流協調器測試異常: {e}")
    
    total += 1
    
    # 顯示測試結果
    print(f"\n{'='*50}")
    print(f"📊 測試結果: {passed}/{total} 通過")
    
    if passed == total:
        print("🎉 所有測試通過！系統運行正常。")
        return True
    else:
        print("⚠️  部分測試失敗，請檢查配置和環境。")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
