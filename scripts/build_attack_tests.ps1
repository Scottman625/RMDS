# 攻擊測試構建腳本
param(
    [string]$BuildType = "Release",
    [string]$VcpkgRoot = "D:/vcpkg"
)

# 設定控制台編碼為 UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host "=== Real-Time Memory Attack Detection Engine - Attack Test Suite ===" -ForegroundColor Green

# 檢查 vcpkg 路徑
if (Test-Path "$VcpkgRoot/scripts/buildsystems/vcpkg.cmake") {
    Write-Host "Found vcpkg: $VcpkgRoot" -ForegroundColor Green
} else {
    Write-Host "Warning: vcpkg not found, will try system paths" -ForegroundColor Yellow
}

# 設定環境變數
$env:VCPKG_ROOT = $VcpkgRoot

# 創建構建目錄
if (!(Test-Path "build")) {
    New-Item -ItemType Directory -Path "build" | Out-Null
    Write-Host "Created build directory: build" -ForegroundColor Green
}

# 配置 CMake
Write-Host "Configuring CMake..." -ForegroundColor Yellow
$cmakeArgs = @(
    "-B", "build",
    "-S", ".",
    "-DCMAKE_BUILD_TYPE=$BuildType",
    "-DCMAKE_TOOLCHAIN_FILE=$VcpkgRoot/scripts/buildsystems/vcpkg.cmake"
)

try {
    & cmake @cmakeArgs 2>&1 | ForEach-Object {
        if ($_ -match "warning" -or $_ -match "Warning") {
            Write-Host $_ -ForegroundColor Yellow
        } elseif ($_ -match "error" -or $_ -match "Error") {
            Write-Host $_ -ForegroundColor Red
        } else {
            Write-Host $_ -ForegroundColor White
        }
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "CMake configuration successful" -ForegroundColor Green
    } else {
        Write-Host "CMake configuration failed" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "CMake configuration error: $_" -ForegroundColor Red
    exit 1
}

# 構建簡化攻擊測試
Write-Host "Building simplified attack tests..." -ForegroundColor Yellow
try {
    $buildOutput = & cmake --build build --config $BuildType --target simple_attack_test 2>&1
    
    # 處理構建輸出，過濾亂碼
    $buildOutput | ForEach-Object {
        $line = $_
        if ($line -match "warning" -or $line -match "Warning") {
            Write-Host $line -ForegroundColor Yellow
        } elseif ($line -match "error" -or $line -match "Error") {
            Write-Host $line -ForegroundColor Red
        } elseif ($line -match "Building" -or $line -match "Linking") {
            Write-Host $line -ForegroundColor Cyan
        } elseif ($line -match "simple_attack_test\.exe") {
            Write-Host $line -ForegroundColor Green
        } else {
            # 過濾掉可能的亂碼字符
            $cleanLine = $line -replace '[^\x20-\x7E]', ''
            if ($cleanLine.Length -gt 0) {
                Write-Host $cleanLine -ForegroundColor White
            }
        }
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Simplified attack tests built successfully" -ForegroundColor Green
    } else {
        Write-Host "Simplified attack tests build failed" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Build error: $_" -ForegroundColor Red
    exit 1
}

# 檢查可執行文件
$exePath = "build/$BuildType/simple_attack_test.exe"
if (Test-Path $exePath) {
    Write-Host "Simplified attack test executable generated: $exePath" -ForegroundColor Green
    
    # 詢問是否運行測試
    $runTest = Read-Host "Do you want to run the simplified attack tests? (y/n)"
    if ($runTest -eq "y" -or $runTest -eq "Y") {
        Write-Host "Running simplified attack tests..." -ForegroundColor Yellow
        & $exePath
    }
} else {
    Write-Host "Warning: Simplified attack test executable not found" -ForegroundColor Yellow
}

Write-Host "Build script completed" -ForegroundColor Green 