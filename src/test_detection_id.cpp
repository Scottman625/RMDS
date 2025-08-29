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
    std::cout << "Generated ID: " << generate_detection_id() << std::endl;
    return 0;
}

// 這是修改後的內容
