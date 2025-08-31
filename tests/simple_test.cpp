#include <iostream>
#include <string>
#include <chrono>

// 簡單的檢測ID生成函數（從 test_detection_id.cpp 複製）
std::string generate_detection_id() {
    static int counter = 0;
    counter++;
    return "detection_" + std::to_string(counter) + "_" + 
           std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count());
}

// 簡單的測試函數
bool test_basic_functionality() {
    std::cout << "Testing basic functionality..." << std::endl;
    
    // 測試字符串操作
    std::string test_string = "Hello, World!";
    if (test_string.length() != 13) {
        std::cout << "FAIL: String length test" << std::endl;
        return false;
    }
    
    // 測試檢測ID生成
    std::string id1 = generate_detection_id();
    std::string id2 = generate_detection_id();
    
    if (id1 == id2) {
        std::cout << "FAIL: Detection ID should be unique" << std::endl;
        return false;
    }
    
    if (id1.find("detection_") != 0) {
        std::cout << "FAIL: Detection ID format incorrect" << std::endl;
        return false;
    }
    
    std::cout << "PASS: Basic functionality tests" << std::endl;
    return true;
}

bool test_mathematical_operations() {
    std::cout << "Testing mathematical operations..." << std::endl;
    
    // 測試基本數學運算
    int a = 5, b = 3;
    if (a + b != 8) {
        std::cout << "FAIL: Addition test" << std::endl;
        return false;
    }
    
    if (a * b != 15) {
        std::cout << "FAIL: Multiplication test" << std::endl;
        return false;
    }
    
    if (a / b != 1) {  // 整數除法
        std::cout << "FAIL: Division test" << std::endl;
        return false;
    }
    
    std::cout << "PASS: Mathematical operations tests" << std::endl;
    return true;
}

bool test_memory_operations() {
    std::cout << "Testing memory operations..." << std::endl;
    
    // 測試動態內存分配
    int* array = new int[10];
    if (!array) {
        std::cout << "FAIL: Memory allocation test" << std::endl;
        return false;
    }
    
    // 測試數組操作
    for (int i = 0; i < 10; i++) {
        array[i] = i;
    }
    
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += array[i];
    }
    
    if (sum != 45) {  // 0+1+2+...+9 = 45
        std::cout << "FAIL: Array operations test" << std::endl;
        delete[] array;
        return false;
    }
    
    delete[] array;
    std::cout << "PASS: Memory operations tests" << std::endl;
    return true;
}

int main() {
    std::cout << "=== Simple Test Suite ===" << std::endl;
    std::cout << "Running basic tests...\n" << std::endl;
    
    int total_tests = 0;
    int passed_tests = 0;
    
    // 運行測試
    total_tests++;
    if (test_basic_functionality()) {
        passed_tests++;
    }
    
    total_tests++;
    if (test_mathematical_operations()) {
        passed_tests++;
    }
    
    total_tests++;
    if (test_memory_operations()) {
        passed_tests++;
    }
    
    // 打印結果
    std::cout << "\n=== Test Results ===" << std::endl;
    std::cout << "Total tests: " << total_tests << std::endl;
    std::cout << "Passed: " << passed_tests << std::endl;
    std::cout << "Failed: " << (total_tests - passed_tests) << std::endl;
    std::cout << "Success rate: " << (passed_tests * 100.0 / total_tests) << "%" << std::endl;
    
    if (passed_tests == total_tests) {
        std::cout << "\n✅ All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed!" << std::endl;
        return 1;
    }
}
