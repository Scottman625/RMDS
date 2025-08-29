#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試簡單的 patch 格式
"""

import subprocess
import tempfile
import os

def test_simple_patch():
    """測試簡單的 patch 格式"""
    
    # 創建一個簡單的測試文件
    test_file = "src/test_simple.cpp"
    os.makedirs("src", exist_ok=True)
    
    with open(test_file, 'w') as f:
        f.write("#include <iostream>\n")
        f.write("#include <string>\n")
        f.write("\n")
        f.write("std::string generate_detection_id() {\n")
        f.write("    return \"test\";\n")
        f.write("}\n")
    
    # 創建一個簡單的 patch
    patch_content = f"""--- a/src/test_simple.cpp
+++ b/src/test_simple.cpp
@@ -1,5 +1,6 @@
 #include <iostream>
 #include <string>
+#include <chrono>
 
 std::string generate_detection_id() {{
-    return "test";
+    return "test_modified";
 }}
 """
    
    print("=== 測試簡單 patch ===")
    print(f"Patch 內容:\n{patch_content}")
    
    # 測試 git apply --check
    try:
        result = subprocess.run(
            ["git", "apply", "--check"],
            input=patch_content,
            text=True,
            capture_output=True,
            cwd="../.."  # 回到 RMDS 根目錄
        )
        
        print(f"Git apply --check 結果: {result.returncode}")
        if result.stderr:
            print(f"錯誤: {result.stderr}")
        if result.stdout:
            print(f"輸出: {result.stdout}")
            
        if result.returncode == 0:
            print("✅ Patch 格式正確")
            
            # 實際應用 patch
            result = subprocess.run(
                ["git", "apply"],
                input=patch_content,
                text=True,
                capture_output=True,
                cwd="../.."  # 回到 RMDS 根目錄
            )
            
            print(f"Git apply 結果: {result.returncode}")
            if result.stderr:
                print(f"錯誤: {result.stderr}")
            if result.stdout:
                print(f"輸出: {result.stdout}")
                
            if result.returncode == 0:
                print("✅ Patch 應用成功")
                
                # 檢查文件內容
                with open(test_file, 'r') as f:
                    content = f.read()
                print(f"修改後的文件內容:\n{content}")
            else:
                print("❌ Patch 應用失敗")
        else:
            print("❌ Patch 格式錯誤")
            
    except Exception as e:
        print(f"❌ 測試失敗: {e}")

if __name__ == "__main__":
    test_simple_patch()
