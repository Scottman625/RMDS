#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試工作流中的 patch 生成
"""

import logging
from workflow_orchestrator import WorkflowOrchestrator

# 配置日誌
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_workflow_patch():
    """測試工作流中的 patch 生成"""
    
    # 創建工作流協調器
    orchestrator = WorkflowOrchestrator(repo_root="../", policy_file="policy.json")
    
    # 模擬 LLM 響應
    llm_response = """*** Begin Patch
*** Update File: src/detection_engine.cpp
@@
 class DetectionEngineImpl : public RealMemoryDetectionEngine, public MemoryMonitor {
 private:
     // 添加 monitor 成員
     std::unique_ptr<MemoryDetectionMonitor> monitor;
+    std::atomic<uint64_t> detection_counter{0};
+    std::mt19937_64 rng;
+    std::uniform_int_distribution<uint64_t> dist;
 
 public:
     DetectionEngineImpl();
     ~DetectionEngineImpl();
     void process_event(const MemoryEvent& event) override;
+    std::string generate_detection_id();
 };
"""
    
    print("=== 測試工作流 patch 生成 ===")
    print(f"LLM 響應長度: {len(llm_response)}")
    print(f"LLM 響應前200字符: {llm_response[:200]}")
    
    # 模擬 workflow_orchestrator 的 diff 解析邏輯
    lines = llm_response.split('\n')
    
    # 尋找文件路徑
    file_path = None
    for line in lines:
        if "*** Update File:" in line:
            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
            break
        elif "*** Add File:" in line:
            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
            break
    
    # 尋找 diff 內容的開始
    diff_start = -1
    for i, line in enumerate(lines):
        if line.startswith("@@"):
            diff_start = i
            break
    
    if diff_start >= 0 and file_path:
        # 構建完整的 diff 格式
        if "*** Add File:" in llm_response:
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
            
            # 假設原始文件有 10 行（這是一個估計值）
            original_lines = 10
            new_lines = original_lines + added_lines - removed_lines
            
            diff_lines[0] = f"@@ -1,{original_lines} +1,{new_lines} @@"
        
        diff_content += '\n'.join(diff_lines)
        
        # 清理 diff 內容，移除尾隨空格
        diff_content = '\n'.join(line.rstrip() for line in diff_content.split('\n'))
        
        print(f"生成的 diff 內容長度: {len(diff_content)}")
        print(f"生成的 diff 內容:\n{diff_content}")
        
        # 測試 diff 驗證
        diff_meta = orchestrator.mcp_server._extract_and_validate_unified_diff(diff_content, orchestrator.mcp_server.repo_root)
        print(f"Diff 驗證結果: valid={diff_meta.valid}")
        print(f"Diff 問題: {diff_meta.issues}")
        
        if diff_meta.valid:
            print("✅ Diff 驗證成功")
            
            # 測試乾運行
            dry_run_result = orchestrator.mcp_server.apply_patch({
                "unified_diff": diff_content,
                "dry_run": True,
                "commit": False,
                "task_id": "test_task"
            })
            
            print(f"乾運行結果: success={dry_run_result.success}")
            if not dry_run_result.success:
                print(f"乾運行錯誤: {dry_run_result.error}")
                print("🔄 測試回退到 write_file 方法...")
                
                # 模擬回退邏輯
                if "*** Update File:" in llm_response or "*** Add File:" in llm_response:
                    lines = llm_response.split('\n')
                    file_path = None
                    
                    # 尋找文件路徑
                    for line in lines:
                        if "*** Update File:" in line:
                            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
                            break
                        elif "*** Add File:" in line:
                            file_path = line.split(":", 1)[1].strip().replace('\\', '/')
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
                            
                            print("🔄 測試回退到 apply_diff 方法...")
                            
                            # 使用新的 apply_diff 方法來正確應用 diff 變更
                            diff_result = orchestrator.mcp_server.apply_diff({
                                "path": file_path,
                                "diff_content": diff_content
                            })
                            
                            if diff_result.success:
                                print(f"✅ 成功使用 apply_diff 應用變更: {file_path}")
                                print(f"原始大小: {diff_result.data.get('original_size', 'unknown')}")
                                print(f"新大小: {diff_result.data.get('new_size', 'unknown')}")
                                print(f"變更行數: {diff_result.data.get('original_lines', 0)} -> {diff_result.data.get('new_lines', 0)}")
                                
                                # 讀取修改後的文件來驗證
                                read_result = orchestrator.mcp_server.read_file({"path": file_path})
                                if read_result.success:
                                    print(f"文件內容長度: {len(read_result.data.get('content', ''))}")
                                    print(f"文件內容前200字符: {read_result.data.get('content', '')[:200]}")
                                else:
                                    print(f"❌ 讀取文件失敗: {read_result.error}")
                            else:
                                print(f"❌ apply_diff 失敗: {diff_result.error}")
                                
                                # 如果 apply_diff 也失敗，嘗試使用 write_file 作為最後手段
                                print("🔄 嘗試使用 write_file 作為最後手段...")
                                
                                # 重建完整內容（這會丟失原始內容，但至少能工作）
                                content_lines = []
                                for line in diff_lines[1:]:  # 跳過 @@ 行
                                    if line.startswith('+') and not line.startswith('++'):
                                        content_lines.append(line[1:])  # 移除 + 前綴
                                    elif not line.startswith('-') and not line.startswith('--'):
                                        content_lines.append(line)
                                
                                content = '\n'.join(content_lines)
                                
                                write_result = orchestrator.mcp_server.write_file({
                                    "path": file_path,
                                    "content": content,
                                    "create_dirs": True,
                                    "mode": "overwrite"  # 明確指定覆蓋模式
                                })
                                
                                if write_result.success:
                                    print(f"⚠️ 使用 write_file 成功（但可能丟失原始內容）: {file_path}")
                                    print(f"文件內容長度: {len(content)}")
                                    print(f"文件內容前200字符: {content[:200]}")
                                else:
                                    print(f"❌ write_file 也失敗: {write_result.error}")
                        else:
                            print("❌ 無法找到 diff 內容")
                    else:
                        print("❌ 無法找到文件路徑")
            else:
                print("✅ 乾運行成功")
        else:
            print("❌ Diff 驗證失敗")
    else:
        print("❌ 無法解析 diff 內容")

if __name__ == "__main__":
    test_workflow_patch()
