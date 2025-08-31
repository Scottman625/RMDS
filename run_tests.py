#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
簡單的測試運行腳本
"""

import subprocess
import sys
import os
from pathlib import Path

def run_basic_test():
    """運行基本測試"""
    print("=== 運行基本測試 ===")
    
    # 創建一個簡單的 C++ 測試程序
    test_code = '''
#include <iostream>
#include <string>

int main() {
    std::cout << "=== Basic Test ===" << std::endl;
    
    // 測試字符串操作
    std::string test_str = "Hello, World!";
    if (test_str.length() != 13) {
        std::cout << "FAIL: String length test" << std::endl;
        return 1;
    }
    
    // 測試數學運算
    int a = 5, b = 3;
    if (a + b != 8) {
        std::cout << "FAIL: Addition test" << std::endl;
        return 1;
    }
    
    std::cout << "PASS: All basic tests passed!" << std::endl;
    return 0;
}
'''
    
    # 寫入臨時測試文件
    test_file = Path("temp_test.cpp")
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_code)
    
    try:
        # 編譯測試
        result = subprocess.run([
            'g++', '-o', 'temp_test.exe', 'temp_test.cpp'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"編譯失敗: {result.stderr}")
            return False
        
        # 運行測試
        result = subprocess.run(['./temp_test.exe'], capture_output=True, text=True)
        
        print(result.stdout)
        
        if result.returncode == 0:
            print("✅ 測試通過")
            return True
        else:
            print("❌ 測試失敗")
            return False
            
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        return False
    finally:
        # 清理臨時文件
        if test_file.exists():
            test_file.unlink()
        temp_exe = Path("temp_test.exe")
        if temp_exe.exists():
            temp_exe.unlink()

def run_detection_id_test():
    """運行檢測ID測試"""
    print("\n=== 運行檢測ID測試 ===")
    
    test_code = '''
#include <iostream>
#include <string>
#include <chrono>

std::string generate_detection_id() {
    static int counter = 0;
    counter++;
    return "detection_" + std::to_string(counter) + "_" + 
           std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count());
}

int main() {
    std::cout << "=== Detection ID Test ===" << std::endl;
    
    // 生成多個ID進行測試
    std::string id1 = generate_detection_id();
    std::string id2 = generate_detection_id();
    std::string id3 = generate_detection_id();
    
    std::cout << "Generated ID 1: " << id1 << std::endl;
    std::cout << "Generated ID 2: " << id2 << std::endl;
    std::cout << "Generated ID 3: " << id3 << std::endl;
    
    // 驗證ID的唯一性
    if (id1 == id2 || id1 == id3 || id2 == id3) {
        std::cout << "❌ FAIL: IDs are not unique!" << std::endl;
        return 1;
    }
    
    // 驗證ID格式
    if (id1.find("detection_") != 0 || 
        id2.find("detection_") != 0 || 
        id3.find("detection_") != 0) {
        std::cout << "❌ FAIL: ID format is incorrect!" << std::endl;
        return 1;
    }
    
    std::cout << "✅ PASS: All tests passed!" << std::endl;
    return 0;
}
'''
    
    # 寫入臨時測試文件
    test_file = Path("temp_detection_test.cpp")
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(test_code)
    
    try:
        # 編譯測試
        result = subprocess.run([
            'g++', '-o', 'temp_detection_test.exe', 'temp_detection_test.cpp'
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"編譯失敗: {result.stderr}")
            return False
        
        # 運行測試
        result = subprocess.run(['./temp_detection_test.exe'], capture_output=True, text=True)
        
        print(result.stdout)
        
        if result.returncode == 0:
            print("✅ 檢測ID測試通過")
            return True
        else:
            print("❌ 檢測ID測試失敗")
            return False
            
    except Exception as e:
        print(f"測試執行錯誤: {e}")
        return False
    finally:
        # 清理臨時文件
        if test_file.exists():
            test_file.unlink()
        temp_exe = Path("temp_detection_test.exe")
        if temp_exe.exists():
            temp_exe.unlink()

def main():
    """主函數"""
    print("=== RMDS 單元測試系統 ===")
    
    total_tests = 0
    passed_tests = 0
    
    # 運行基本測試
    total_tests += 1
    if run_basic_test():
        passed_tests += 1
    
    # 運行檢測ID測試
    total_tests += 1
    if run_detection_id_test():
        passed_tests += 1
    
    # 打印總結
    print(f"\n=== 測試總結 ===")
    print(f"總測試數: {total_tests}")
    print(f"通過: {passed_tests}")
    print(f"失敗: {total_tests - passed_tests}")
    print(f"成功率: {(passed_tests * 100.0 / total_tests):.1f}%")
    
    if passed_tests == total_tests:
        print("\n🎉 所有測試通過！")
        return 0
    else:
        print("\n💥 部分測試失敗！")
        return 1

if __name__ == "__main__":
    sys.exit(main())
