# Real-Time Memory Attack Detection Engine Build Script (Windows PowerShell)

param(
    [switch]$WithTests,
    [switch]$WithExamples,
    [switch]$Install,
    [switch]$Clean,
    [switch]$Help
)

# Color definitions
$Red = "Red"
$Green = "Green"
$Yellow = "Yellow"
$Blue = "Blue"
$White = "White"

# Functions for colored output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Red
}

# Check dependencies
function Check-Dependencies {
    Write-Info "Checking dependencies..."
    
    # Check CMake
    try {
        $cmakeVersion = cmake --version 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Error "CMake not found, please install CMake 3.20 or higher"
            exit 1
        }
        Write-Info "Found CMake: $($cmakeVersion.Split("`n")[0])"
    }
    catch {
        Write-Error "CMake not found, please install CMake 3.20 or higher"
        exit 1
    }
    
    # Check compiler
    $compilerFound = $false
    try {
        $gccVersion = g++ --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "Found GCC compiler"
            $compilerFound = $true
        }
    }
    catch { }
    
    try {
        $clangVersion = clang++ --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "Found Clang compiler"
            $compilerFound = $true
        }
    }
    catch { }
    
    if (-not $compilerFound) {
        Write-Error "No C++ compiler found, please install GCC or Clang"
        exit 1
    }
    
    # Check LLVM
    try {
        $llvmVersion = llvm-config --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "Found LLVM: $llvmVersion"
        } else {
            Write-Warning "LLVM not found, some features may not be available"
        }
    }
    catch {
        Write-Warning "LLVM not found, some features may not be available"
    }
    
    Write-Success "Dependency check completed"
}

# Create build directory
function Create-BuildDir {
    Write-Info "Creating build directory..."
    if (-not (Test-Path "build")) {
        New-Item -ItemType Directory -Path "build" | Out-Null
    }
    Set-Location "build"
}

# Configure project
function Configure-Project {
    Write-Info "Configuring project..."
    
    $cmakeArgs = @("-DCMAKE_BUILD_TYPE=Release")
    
    if ($WithTests) {
        $cmakeArgs += "-DBUILD_TESTS=ON"
        Write-Info "Enabling test build"
    }
    
    if ($WithExamples) {
        $cmakeArgs += "-DBUILD_EXAMPLES=ON"
        Write-Info "Enabling examples build"
    }
    
    $cmakeArgs += ".."
    
    & cmake @cmakeArgs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Project configuration successful"
    } else {
        Write-Error "Project configuration failed"
        exit 1
    }
}

# Build project
function Build-Project {
    Write-Info "Building project..."
    
    # Use multi-core compilation on Windows
    $jobs = [Environment]::ProcessorCount
    & cmake --build . --config Release --parallel $jobs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Build successful"
    } else {
        Write-Error "Build failed"
        exit 1
    }
}

# Run tests
function Run-Tests {
    if ($WithTests) {
        Write-Info "Running tests..."
        & cmake --build . --target test
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Tests passed"
        } else {
            Write-Error "Tests failed"
            exit 1
        }
    }
}

# Install
function Install-Project {
    if ($Install) {
        Write-Info "Installing project..."
        & cmake --build . --target install
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Installation successful"
        } else {
            Write-Error "Installation failed"
            exit 1
        }
    }
}

# Clean
function Clean-Build {
    if ($Clean) {
        Write-Info "Cleaning build files..."
        & cmake --build . --target clean
        Write-Success "Clean completed"
    }
}

# Show help
function Show-Help {
    Write-Host "Real-Time Memory Attack Detection Engine Build Script (Windows PowerShell)" -ForegroundColor $Blue
    Write-Host ""
    Write-Host "Usage: .\scripts\build.ps1 [options]" -ForegroundColor $White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor $White
    Write-Host "  -WithTests       Enable test build" -ForegroundColor $White
    Write-Host "  -WithExamples    Enable examples build" -ForegroundColor $White
    Write-Host "  -Install         Install to system" -ForegroundColor $White
    Write-Host "  -Clean           Clean build files" -ForegroundColor $White
    Write-Host "  -Help            Show this help message" -ForegroundColor $White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor $White
    Write-Host "  .\scripts\build.ps1                    # Basic build" -ForegroundColor $White
    Write-Host "  .\scripts\build.ps1 -WithTests         # Build and run tests" -ForegroundColor $White
    Write-Host "  .\scripts\build.ps1 -WithExamples      # Build examples" -ForegroundColor $White
    Write-Host "  .\scripts\build.ps1 -Install           # Build and install" -ForegroundColor $White
    Write-Host "  .\scripts\build.ps1 -Clean             # Clean build files" -ForegroundColor $White
}

# Main function
function Main {
    Write-Info "Starting Real-Time Memory Attack Detection Engine build..."
    
    if ($Help) {
        Show-Help
        return
    }
    
    # Check dependencies
    Check-Dependencies
    
    # Create build directory
    Create-BuildDir
    
    # Configure project
    Configure-Project
    
    # Build project
    Build-Project
    
    # Run tests
    Run-Tests
    
    # Install
    Install-Project
    
    # Clean
    Clean-Build
    
    Write-Success "Build completed!"
    Write-Info "Executables located at: build/bin/"
    Write-Info "Libraries located at: build/lib/"
}

# Execute main function
Main 