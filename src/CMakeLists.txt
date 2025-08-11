# 真實記憶體攻擊檢測引擎源代碼

# 創建靜態庫
add_library(memory_detection_engine STATIC
    memory_detection_utils.cpp
    memory_detection_veh.cpp
    detection_engine.cpp
    memory_monitor.cpp
    logger.cpp
    performance_monitor.cpp
    process_lists.cpp
)

# 設定目標屬性
set_target_properties(memory_detection_engine PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# 包含目錄
target_include_directories(memory_detection_engine PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(memory_detection_engine
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif()

# 創建檢測引擎可執行檔
add_executable(real_detection_engine
    detection_engine.cpp
    logger.cpp
    performance_monitor.cpp
)

# 設定檢測引擎可執行檔屬性
set_target_properties(real_detection_engine PROPERTIES
    OUTPUT_NAME "real_detection_engine"
)

# 包含目錄
target_include_directories(real_detection_engine PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 鏈接靜態庫
target_link_libraries(real_detection_engine
    memory_detection_engine
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(real_detection_engine
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif()

# 創建攻擊模擬器可執行檔
add_executable(attack_simulator
    attack_simulator.cpp
)

# 設定攻擊模擬器屬性
set_target_properties(attack_simulator PROPERTIES
    OUTPUT_NAME "attack_simulator"
)

# 包含目錄
target_include_directories(attack_simulator PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(attack_simulator
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif()

# 創建記憶體監控器可執行檔
add_executable(memory_monitor
    memory_monitor_main.cpp
    memory_monitor.cpp
    logger.cpp
    performance_monitor.cpp
    process_lists.cpp
)

# 設定記憶體監控器屬性
set_target_properties(memory_monitor PROPERTIES
    OUTPUT_NAME "memory_monitor"
)

# 包含目錄
target_include_directories(memory_monitor PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# 鏈接靜態庫
target_link_libraries(memory_monitor
    memory_detection_engine
)

# 鏈接Windows API庫
if(WIN32)
    target_link_libraries(memory_monitor
        kernel32
        user32
        psapi
        dbghelp
        advapi32
        shell32
    )
endif() 