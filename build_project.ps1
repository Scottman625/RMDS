# PowerShell 編譯腳本
Write-Host "🔨 開始編譯項目..." -ForegroundColor Green

# 設置專案路徑
$repoRoot = "D:\code\CyberSecirity\RMDS"
Set-Location $repoRoot

# 清理構建目錄
if (Test-Path "build") {
    Write-Host "清理構建目錄..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "build"
}

# 創建構建目錄
New-Item -ItemType Directory -Path "build" -Force | Out-Null
Set-Location "build"

# 嘗試設置 Visual Studio 環境
$vsPaths = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
)

$vsEnvSet = $false
foreach ($path in $vsPaths) {
    if (Test-Path $path) {
        Write-Host "設置 Visual Studio 環境: $path" -ForegroundColor Cyan
        cmd /c "`"$path`" && set" | ForEach-Object {
            if ($_ -match "^([^=]+)=(.*)$") {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }
        }
        $vsEnvSet = $true
        break
    }
}

if (-not $vsEnvSet) {
    Write-Host "警告：未找到 Visual Studio 環境" -ForegroundColor Yellow
}

# 配置 CMake
Write-Host "配置 CMake..." -ForegroundColor Cyan
$cmakeResult = cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Debug

if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake 配置失敗" -ForegroundColor Red
    exit 1
}

# 編譯項目
Write-Host "編譯項目..." -ForegroundColor Cyan
$buildResult = cmake --build . --config Debug --parallel

if ($LASTEXITCODE -ne 0) {
    Write-Host "編譯失敗" -ForegroundColor Red
    exit 1
}

Write-Host "編譯成功！" -ForegroundColor Green
Write-Host ""
Write-Host "生成的文件：" -ForegroundColor Cyan
Get-ChildItem -Recurse -Filter "*.exe" | ForEach-Object {
    Write-Host "  $($_.FullName)" -ForegroundColor White
}

Read-Host "按 Enter 鍵繼續"
