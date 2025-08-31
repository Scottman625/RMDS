#include <iostream>
#include <string>
#include <chrono>
#include <vector>
#include <algorithm>
#include <functional> // Added for std::function
#include <cmath> // Added for std::abs
#include <thread> // Added for std::this_thread

// 簡單的測試框架
class BasicTestFramework {
private:
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;

public:
    void run_test(const std::string& test_name, std::function<bool()> test_func) {
        total_tests++;
        std::cout << "Running test: " << test_name << " ... ";
        
        try {
            bool result = test_func();
            if (result) {
                std::cout << "PASS" << std::endl;
                passed_tests++;
            } else {
                std::cout << "FAIL" << std::endl;
                failed_tests++;
            }
        } catch (const std::exception& e) {
            std::cout << "FAIL (Exception: " << e.what() << ")" << std::endl;
            failed_tests++;
        }
    }

    void print_summary() {
        std::cout << "\n=== Test Summary ===" << std::endl;
        std::cout << "Total tests: " << total_tests << std::endl;
        std::cout << "Passed: " << passed_tests << std::endl;
        std::cout << "Failed: " << failed_tests << std::endl;
        std::cout << "Success rate: " << (total_tests > 0 ? (passed_tests * 100.0 / total_tests) : 0) << "%" << std::endl;
    }

    int get_exit_code() const {
        return failed_tests > 0 ? 1 : 0;
    }
};

// 測試函數
bool test_string_operations() {
    std::string test_str = "Hello, World!";
    
    // 測試字符串長度
    if (test_str.length() != 13) {
        return false;
    }
    
    // 測試字符串查找
    if (test_str.find("World") == std::string::npos) {
        return false;
    }
    
    // 測試字符串替換
    test_str.replace(7, 5, "Test");
    if (test_str != "Hello, Test!") {
        return false;
    }
    
    return true;
}

bool test_vector_operations() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    
    // 測試向量大小
    if (numbers.size() != 5) {
        return false;
    }
    
    // 測試向量訪問
    if (numbers[0] != 1 || numbers[4] != 5) {
        return false;
    }
    
    // 測試向量操作
    numbers.push_back(6);
    if (numbers.size() != 6 || numbers[5] != 6) {
        return false;
    }
    
    // 測試排序
    std::sort(numbers.begin(), numbers.end());
    for (size_t i = 1; i < numbers.size(); i++) {
        if (numbers[i] <= numbers[i-1]) {
            return false;
        }
    }
    
    return true;
}

bool test_chrono_operations() {
    auto start = std::chrono::high_resolution_clock::now();
    
    // 模擬一些工作
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // 檢查時間測量是否合理
    if (duration.count() < 100) { // 至少100微秒
        return false;
    }
    
    return true;
}

bool test_mathematical_operations() {
    // 測試基本數學運算
    int a = 10, b = 3;
    
    if (a + b != 13) return false;
    if (a - b != 7) return false;
    if (a * b != 30) return false;
    if (a / b != 3) return false; // 整數除法
    if (a % b != 1) return false;
    
    // 測試浮點運算
    double x = 10.0, y = 3.0;
    if (std::abs(x / y - 3.333333) > 0.000001) return false;
    
    return true;
}

bool test_memory_operations() {
    // 測試動態內存分配
    int* array = new int[10];
    if (!array) return false;
    
    // 初始化數組
    for (int i = 0; i < 10; i++) {
        array[i] = i * i;
    }
    
    // 檢查數組內容
    if (array[0] != 0) return false;
    if (array[3] != 9) return false;
    if (array[9] != 81) return false;
    
    delete[] array;
    return true;
}

bool test_algorithm_operations() {
    std::vector<int> numbers = {5, 2, 8, 1, 9, 3};
    
    // 測試排序
    std::sort(numbers.begin(), numbers.end());
    for (size_t i = 1; i < numbers.size(); i++) {
        if (numbers[i] <= numbers[i-1]) {
            return false;
        }
    }
    
    // 測試查找
    auto it = std::find(numbers.begin(), numbers.end(), 5);
    if (it == numbers.end()) {
        return false;
    }
    
    // 測試計數
    int count = std::count(numbers.begin(), numbers.end(), 5);
    if (count != 1) {
        return false;
    }
    
    return true;
}

int main() {
    std::cout << "=== Basic C++ Test Suite ===" << std::endl;
    std::cout << "Testing core C++ functionality...\n" << std::endl;
    
    BasicTestFramework test_framework;
    
    // 運行所有測試
    test_framework.run_test("String Operations", test_string_operations);
    test_framework.run_test("Vector Operations", test_vector_operations);
    test_framework.run_test("Chrono Operations", test_chrono_operations);
    test_framework.run_test("Mathematical Operations", test_mathematical_operations);
    test_framework.run_test("Memory Operations", test_memory_operations);
    test_framework.run_test("Algorithm Operations", test_algorithm_operations);
    
    // 打印測試摘要
    test_framework.print_summary();
    
    if (test_framework.get_exit_code() == 0) {
        std::cout << "\n✅ All tests passed!" << std::endl;
    } else {
        std::cout << "\n❌ Some tests failed!" << std::endl;
    }
    
    return test_framework.get_exit_code();
}
