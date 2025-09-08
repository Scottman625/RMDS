#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試 diff 格式修復功能
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from workflow_orchestrator import WorkflowOrchestrator

def test_diff_fix():
    """測試 diff 格式修復功能"""
    orchestrator = WorkflowOrchestrator(repo_root="..")
    
    # 測試用例1: 格式正確的 diff
    correct_diff = """--- a/src/test.cpp
+++ b/src/test.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
+#include <string>
 
 int main() {
     return 0;
 }"""
    
    # 測試用例2: 格式錯誤的 diff
    broken_diff = """--- a/src/test.cpp
+++ b/src/test.cpp
@@ -1,3 +1,4 @@
 #include <iostream>
+#include <string>
 
 int main() {
     return 0;
 }"""
    
    # 測試用例3: 完全錯誤的 diff
    invalid_diff = """Some random content
that is not a diff at all
but contains some + and - lines
+ added line
- removed line"""
    
    print("🧪 測試 diff 格式修復功能")
    print("=" * 50)
    
    # 測試正確的 diff
    print("\n📋 測試用例1: 格式正確的 diff")
    fixed1 = orchestrator._fix_diff_format(correct_diff)
    print(f"原始: {correct_diff}")
    print(f"修復後: {fixed1}")
    print(f"是否相同: {correct_diff == fixed1}")
    
    # 測試錯誤的 diff
    print("\n📋 測試用例2: 格式錯誤的 diff")
    fixed2 = orchestrator._fix_diff_format(broken_diff)
    print(f"原始: {broken_diff}")
    print(f"修復後: {fixed2}")
    print(f"是否相同: {broken_diff == fixed2}")
    
    # 測試無效的 diff
    print("\n📋 測試用例3: 完全錯誤的 diff")
    fixed3 = orchestrator._fix_diff_format(invalid_diff)
    print(f"原始: {invalid_diff}")
    print(f"修復後: {fixed3}")
    print(f"是否相同: {invalid_diff == fixed3}")
    
    print("\n✅ 測試完成")

if __name__ == "__main__":
    test_diff_fix()
