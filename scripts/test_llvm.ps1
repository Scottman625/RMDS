# 測試 LLVM 路徑腳本
Write-Host "=== LLVM Path Test ===" -ForegroundColor Green

# 檢查 LLVM 安裝路徑
$llvmPaths = @(
    "C:\Program Files\LLVM",
    "C:\LLVM", 
    "D:\LLVM",
    "C:\Program Files (x86)\LLVM"
)

Write-Host "Checking LLVM installation paths..." -ForegroundColor Yellow

foreach ($path in $llvmPaths) {
    if (Test-Path $path) {
        Write-Host "Found LLVM at: $path" -ForegroundColor Green
        
        $cmakePath = "$path\lib\cmake\llvm"
        if (Test-Path $cmakePath) {
            Write-Host "  CMake config found at: $cmakePath" -ForegroundColor Green
        } else {
            Write-Host "  CMake config NOT found at: $cmakePath" -ForegroundColor Red
        }
        
        $includePath = "$path\include"
        if (Test-Path $includePath) {
            Write-Host "  Include directory found at: $includePath" -ForegroundColor Green
        } else {
            Write-Host "  Include directory NOT found at: $includePath" -ForegroundColor Red
        }
        
        $libPath = "$path\lib"
        if (Test-Path $libPath) {
            Write-Host "  Library directory found at: $libPath" -ForegroundColor Green
        } else {
            Write-Host "  Library directory NOT found at: $libPath" -ForegroundColor Red
        }
    } else {
        Write-Host "LLVM NOT found at: $path" -ForegroundColor Red
    }
}

Write-Host "`n=== Environment Variables ===" -ForegroundColor Green
Write-Host "LLVM_DIR: $env:LLVM_DIR" -ForegroundColor Cyan
Write-Host "CMAKE_PREFIX_PATH: $env:CMAKE_PREFIX_PATH" -ForegroundColor Cyan

Write-Host "`n=== LLVM Version Check ===" -ForegroundColor Green
try {
    $llvmVersion = & "C:\Program Files\LLVM\bin\llvm-config.exe" --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "LLVM version: $llvmVersion" -ForegroundColor Green
    } else {
        Write-Host "Could not get LLVM version" -ForegroundColor Red
    }
} catch {
    Write-Host "LLVM config not found or not accessible" -ForegroundColor Red
}

Write-Host "`nLLVM path test completed" -ForegroundColor Green 