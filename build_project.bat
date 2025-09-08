@echo off
echo 設置 Visual Studio 環境...

REM 嘗試設置 Visual Studio 2022 環境
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

REM 嘗試設置 Visual Studio 2019 環境
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    goto :build
)

echo 錯誤：未找到 Visual Studio 環境
pause
exit /b 1

:build
echo 開始編譯項目...
cd /d "D:\code\CyberSecirity\RMDS"

REM 清理構建目錄
if exist build (
    echo 清理構建目錄...
    rmdir /s /q build
)

REM 創建構建目錄
mkdir build
cd build

REM 配置 CMake
echo 配置 CMake...
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Debug

if %ERRORLEVEL% neq 0 (
    echo CMake 配置失敗
    pause
    exit /b 1
)

REM 編譯項目
echo 編譯項目...
cmake --build . --config Debug --parallel

if %ERRORLEVEL% neq 0 (
    echo 編譯失敗
    pause
    exit /b 1
)

echo 編譯成功！
echo.
echo 生成的文件：
dir /s *.exe
pause
