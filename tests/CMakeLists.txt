# 測試目錄配置

# 創建測試可執行文件
add_executable(test_suite
    basic_test.cpp
)

# 設定測試可執行文件屬性
set_target_properties(test_suite PROPERTIES
    OUTPUT_NAME "test_suite"
)

# 包含目錄
target_include_directories(test_suite PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# 鏈接靜態庫
target_link_libraries(test_suite
    memory_detection_engine
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(test_suite
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif()

# 添加測試
add_test(NAME test_suite COMMAND test_suite)

# 創建簡單的測試可執行文件
add_executable(simple_test
    simple_test.cpp
)

# 設定簡單測試可執行文件屬性
set_target_properties(simple_test PROPERTIES
    OUTPUT_NAME "simple_test"
)

# 包含目錄
target_include_directories(simple_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 鏈接靜態庫
target_link_libraries(simple_test
    memory_detection_engine
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(simple_test
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif()

# 添加簡單測試
add_test(NAME simple_test COMMAND simple_test)
