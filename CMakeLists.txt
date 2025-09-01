cmake_minimum_required(VERSION 3.20)
project(RealTimeMemoryAttackDetectEngine VERSION 1.0.0 LANGUAGES CXX)

# 設定C++17標準（兼容較舊的編譯器）
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 編譯器選項
if(MSVC)
    add_compile_options(/W4 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    # Windows API 相關定義
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
    
    # 調試符號和優化選項
    set(CMAKE_CXX_FLAGS_DEBUG "/Zi /Ob0 /Od /Oy- /MDd /RTC1")
    set(CMAKE_CXX_FLAGS_RELEASE "/Zi /O2 /MD /Oy-")
    
    # 啟用調試信息
    add_compile_options(/Zi)
    add_link_options(/DEBUG /INCREMENTAL:NO)
else()
    add_compile_options(-Wall -Wextra -g -O0)
endif()

# 設定 vcpkg 工具鏈
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
elseif(EXISTS "D:/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "D:/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# 包含目錄
include_directories(include)

# 啟用測試
enable_testing()

# 添加子目錄
add_subdirectory(src)
add_subdirectory(tests)

# 安裝規則
install(TARGETS memory_detection_engine real_detection_engine attack_simulator memory_monitor
    EXPORT RealMemoryDetectionEngineTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/ DESTINATION include) 