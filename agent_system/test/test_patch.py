#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
測試補丁格式
"""

import subprocess
import tempfile
import os

def test_patch_format():
    """測試補丁格式是否正確"""
    
    # 創建一個測試補丁
    test_patch = """--- a/test_file.txt
+++ b/test_file.txt
@@ -0,0 +1,1 @@
+This is a test file
"""
    
    print("測試補丁內容:")
    print(test_patch)
    print("=" * 50)
    
    # 創建臨時文件
    with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
        f.write(test_patch)
        patch_file = f.name
    
    try:
        # 測試 git apply --check
        result = subprocess.run(
            ["git", "apply", "--check", patch_file],
            cwd="..",
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        
        print(f"Git apply --check 結果:")
        print(f"返回碼: {result.returncode}")
        print(f"標準輸出: {result.stdout}")
        print(f"標準錯誤: {result.stderr}")
        
        if result.returncode == 0:
            print("✅ 補丁格式正確")
        else:
            print("❌ 補丁格式有問題")
            
    finally:
        # 清理臨時文件
        os.unlink(patch_file)

if __name__ == "__main__":
    test_patch_format()
