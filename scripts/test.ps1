# Simplified Test Script for Real-Time Memory Attack Detection Engine

param(
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

# Show help
function Show-Help {
    Write-Host "Simplified Test Script for Real-Time Memory Attack Detection Engine" -ForegroundColor $Blue
    Write-Host ""
    Write-Host "Usage: .\scripts\test.ps1 [options]" -ForegroundColor $White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor $White
    Write-Host "  -Clean           Clean build files before building" -ForegroundColor $White
    Write-Host "  -Help            Show this help message" -ForegroundColor $White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor $White
    Write-Host "  .\scripts\test.ps1                    # Build and run tests" -ForegroundColor $White
    Write-Host "  .\scripts\test.ps1 -Clean            # Clean and rebuild" -ForegroundColor $White
}

# Clean build directory
function Clean-Build {
    if (Test-Path "build") {
        Write-Info "Cleaning build directory..."
        Remove-Item -Recurse -Force "build"
        Write-Success "Build directory cleaned"
    }
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
    
    # Configure without LLVM to avoid dependency issues
    $cmakeArgs = @(
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_TESTS=ON",
        "-DBUILD_EXAMPLES=OFF"
    )
    
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
    & make -j$jobs
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Build successful"
    } else {
        Write-Error "Build failed"
        exit 1
    }
}

# Run tests
function Run-Tests {
    Write-Info "Running tests..."
    & make test
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Tests passed"
    } else {
        Write-Error "Tests failed"
        exit 1
    }
}

# Main function
function Main {
    Write-Info "Starting simplified test build..."
    
    if ($Help) {
        Show-Help
        return
    }
    
    # Clean if requested
    if ($Clean) {
        Clean-Build
    }
    
    # Create build directory
    Create-BuildDir
    
    # Configure project
    Configure-Project
    
    # Build project
    Build-Project
    
    # Run tests
    Run-Tests
    
    Write-Success "Test build completed!"
    Write-Info "Test results available in build directory"
}

# Execute main function
Main 