cmake_minimum_required(VERSION 3.20)
project(RealTimeMemoryAttackDetectEngine VERSION 1.0.0 LANGUAGES CXX)

# 設定C++23標準
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 編譯器選項
if(MSVC)
    add_compile_options(/W4 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra)
endif()

# 設定 vcpkg 工具鏈
if(DEFINED ENV{VCPKG_ROOT})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
elseif(EXISTS "D:/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "D:/vcpkg/scripts/buildsystems/vcpkg.cmake"
        CACHE STRING "Vcpkg toolchain file")
endif()

# 設定LLVM路徑 - 修正路徑設定
set(LLVM_DIR "C:/Program Files/LLVM/lib/cmake/llvm")
set(CMAKE_PREFIX_PATH "C:/Program Files/LLVM")

# 尋找LLVM
find_package(LLVM CONFIG QUIET)
if(LLVM_FOUND)
    message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
    message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
    message(STATUS "LLVM installation directory: ${LLVM_INSTALL_PREFIX}")

    # 設定LLVM相關變數
    llvm_map_components_to_libnames(llvm_libs
        core
        support
        irreader
        passes
        analysis
        target
        mcjit
        native
    )

    # 包含目錄
    include_directories(${LLVM_INCLUDE_DIRS})
    add_definitions(-DHAVE_LLVM=1)
else()
    message(WARNING "LLVM not found, some features will be disabled")
    message(STATUS "LLVM_DIR: ${LLVM_DIR}")
    message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
    set(llvm_libs "")
    add_definitions(-DHAVE_LLVM=0)
endif()

# 尋找Google Test (使用vcpkg)
find_package(GTest CONFIG QUIET)
if(GTest_FOUND)
    message(STATUS "Found Google Test via vcpkg")
    message(STATUS "GTest version: ${GTEST_VERSION}")
    message(STATUS "GTest libraries: ${GTEST_LIBRARIES}")
    set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main)
else()
    # 嘗試使用 find_package 的傳統方式
    find_package(GTest QUIET)
    if(GTest_FOUND)
        message(STATUS "Found Google Test via traditional find_package")
        set(GTEST_LIBRARIES ${GTEST_LIBRARIES})
    else()
        message(WARNING "Google Test not found, tests will be disabled")
        message(STATUS "Make sure vcpkg is properly configured")
        message(STATUS "Try: vcpkg install gtest")
        set(GTEST_LIBRARIES "")
    endif()
endif()

# 添加子目錄
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(examples)

# 安裝規則
install(TARGETS memory_detection_engine
    EXPORT MemoryDetectionEngineTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(DIRECTORY include/ DESTINATION include) 