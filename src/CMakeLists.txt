# 源碼目錄CMakeLists.txt

# 包含目錄
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# 引擎核心
add_subdirectory(engine)

# MTE擴展支援
add_subdirectory(mte)

# LLVM插樁工具
add_subdirectory(llvm_instrument)

# 攻擊模式庫
add_subdirectory(patterns)

# 創建主庫
add_library(memory_detection_engine
    engine/memory_detection_engine.cpp
    engine/performance_monitor.cpp
    mte/mte_manager.cpp
    llvm_instrument/llvm_instrumentation.cpp
    patterns/pattern_matcher.cpp
    patterns/rop_patterns.cpp
    patterns/jop_patterns.cpp
    utils/logger.cpp
    utils/memory_utils.cpp
    utils/thread_utils.cpp
)

# 設定目標屬性
set_target_properties(memory_detection_engine PROPERTIES
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED ON
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# 條件性連結LLVM庫
if(LLVM_FOUND AND llvm_libs)
    target_link_libraries(memory_detection_engine ${llvm_libs})
    message(STATUS "Linking with LLVM libraries")
else()
    message(STATUS "LLVM libraries not available, some features will be disabled")
endif()

# 平台特定設定
if(WIN32)
    target_link_libraries(memory_detection_engine psapi)
elseif(UNIX)
    target_link_libraries(memory_detection_engine pthread)
endif() 