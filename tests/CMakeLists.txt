# 測試目錄CMakeLists.txt

# 啟用測試
enable_testing()

# 簡化攻擊測試可執行檔案 (不依賴 Google Test)
add_executable(simple_attack_test
    simple_attack_test.cpp
    attack_tests.cpp
)

# 連結主庫
target_link_libraries(simple_attack_test memory_detection_engine)

# 包含目錄
target_include_directories(simple_attack_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# 添加簡化攻擊測試
add_test(NAME SimpleAttackTest COMMAND simple_attack_test)

# 設定測試工作目錄
set_tests_properties(SimpleAttackTest PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# 攻擊測試可執行檔案 (不依賴 Google Test)
add_executable(attack_detection_tests
    test_attack_detection.cpp
    attack_tests.cpp
)

# 連結主庫
target_link_libraries(attack_detection_tests memory_detection_engine)

# 包含目錄
target_include_directories(attack_detection_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# 添加攻擊測試
add_test(NAME AttackDetectionTests COMMAND attack_detection_tests)

# 設定測試工作目錄
set_tests_properties(AttackDetectionTests PROPERTIES
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# 檢查是否找到 Google Test (可選)
if(GTest_FOUND)
    message(STATUS "Found Google Test, building additional tests")
    
    # 添加測試可執行檔案
    add_executable(memory_detection_tests
        test_main.cpp
        test_engine.cpp
        test_mte.cpp
        test_pattern_matcher.cpp
        test_performance.cpp
    )

    # 連結主庫
    target_link_libraries(memory_detection_tests memory_detection_engine)

    # 連結Google Test
    target_link_libraries(memory_detection_tests ${GTEST_LIBRARIES})
    message(STATUS "Linking tests with Google Test")

    # 包含目錄
    target_include_directories(memory_detection_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
    )

    # 添加測試
    add_test(NAME MemoryDetectionTests COMMAND memory_detection_tests)

    # 設定測試工作目錄
    set_tests_properties(MemoryDetectionTests PROPERTIES
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
else()
    message(STATUS "Google Test not found, only building attack detection tests")
endif() 