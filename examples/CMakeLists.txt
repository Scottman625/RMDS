# Examples CMakeLists.txt

# 簡化範例
add_executable(simple_example
    simple_example.cpp
)

# 基本使用範例
add_executable(basic_example
    basic_example.cpp
)

target_link_libraries(basic_example memory_detection_engine)

# 遊戲反外掛範例
add_executable(game_anticheat_example
    game_anticheat_example.cpp
)

target_link_libraries(game_anticheat_example memory_detection_engine)

# 金融交易系統範例
add_executable(financial_trading_example
    financial_trading_example.cpp
)

target_link_libraries(financial_trading_example memory_detection_engine)

# 性能測試範例
add_executable(performance_test_example
    performance_test_example.cpp
)

target_link_libraries(performance_test_example memory_detection_engine)

# 包含目錄
target_include_directories(basic_example PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(game_anticheat_example PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(financial_trading_example PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_include_directories(performance_test_example PRIVATE ${CMAKE_SOURCE_DIR}/include) 