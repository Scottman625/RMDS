#include <iostream>
#include <chrono>
#include <string>

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
