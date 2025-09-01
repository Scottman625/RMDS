#include "../include/crash_handler.hpp"
#include <iostream>
#include <thread>
#include <chrono>

using namespace RealMemoryDetection;

void test_access_violation() {
    std::cout << "測試訪問違規..." << std::endl;
    int* ptr = nullptr;
    *ptr = 42; // 這會導致訪問違規
}

void test_divide_by_zero() {
    std::cout << "測試除零錯誤..." << std::endl;
    int a = 1;
    int b = 0;
    int result = a / b; // 這會導致除零錯誤
    std::cout << "結果: " << result << std::endl;
}

void test_stack_overflow() {
    std::cout << "測試堆疊溢出..." << std::endl;
    char buffer[1024];
    test_stack_overflow(); // 遞歸調用導致堆疊溢出
}

void test_manual_dump() {
    std::cout << "測試手動生成 dump..." << std::endl;
    if (GenerateCrashDump("manual_test.dmp")) {
        std::cout << "手動 dump 生成成功" << std::endl;
    } else {
        std::cout << "手動 dump 生成失敗" << std::endl;
    }
}

int main() {
    std::cout << "=== 崩潰處理器測試程式 ===" << std::endl;
    
    // 初始化崩潰處理器
    InitializeCrashHandler();
    
    std::cout << "選擇測試類型:" << std::endl;
    std::cout << "1. 訪問違規 (Access Violation)" << std::endl;
    std::cout << "2. 除零錯誤 (Divide by Zero)" << std::endl;
    std::cout << "3. 堆疊溢出 (Stack Overflow)" << std::endl;
    std::cout << "4. 手動生成 dump" << std::endl;
    std::cout << "5. 顯示當前調用棧" << std::endl;
    std::cout << "0. 退出" << std::endl;
    std::cout << "請輸入選擇 (0-5): ";
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 1:
            test_access_violation();
            break;
        case 2:
            test_divide_by_zero();
            break;
        case 3:
            test_stack_overflow();
            break;
        case 4:
            test_manual_dump();
            break;
        case 5:
            std::cout << "當前調用棧:" << std::endl;
            std::cout << CrashHandler::GetCallStack() << std::endl;
            break;
        case 0:
            std::cout << "退出測試程式" << std::endl;
            break;
        default:
            std::cout << "無效選擇" << std::endl;
            break;
    }
    
    // 清理崩潰處理器
    CleanupCrashHandler();
    
    std::cout << "按任意鍵退出..." << std::endl;
    std::cin.ignore();
    std::cin.get();
    
    return 0;
}
