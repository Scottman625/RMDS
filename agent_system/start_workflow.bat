@echo off
chcp 65001 >nul
REM RMDS Agent System - Workflow Starter
REM Windows batch script for starting Agent workflows

setlocal enabledelayedexpansion

REM Set color codes
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "BLUE=[94m"
set "RESET=[0m"

echo %BLUE%========================================%RESET%
echo %BLUE%  RMDS Agent System - Workflow Starter  %RESET%
echo %BLUE%========================================%RESET%
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo %RED%Error: Python not found. Please install Python 3.8+%RESET%
    pause
    exit /b 1
)

REM Check if we're in the correct directory
if not exist "agent_system" (
    echo %RED%Error: agent_system directory not found. Make sure you're in the RMDS project root directory%RESET%
    echo %YELLOW%Current directory: %CD%%RESET%
    pause
    exit /b 1
)

REM Check agent_system directory and policy.json
if not exist "agent_system\policy.json" (
    echo %YELLOW%Warning: agent_system\policy.json not found%RESET%
    echo %YELLOW%Current directory: %CD%%RESET%
    pause
)

REM Check Python dependencies
echo %BLUE%Checking Python dependencies...%RESET%
cd agent_system
pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%Warning: Some dependencies failed to install, but basic functionality may still work%RESET%
)
cd ..

REM Create logs directory
if not exist "logs" mkdir logs

echo.
echo %GREEN%Environment check completed!%RESET%
echo.

:menu
echo %BLUE%Please select an operation:%RESET%
echo.
echo %YELLOW%1.%RESET% Run new workflow
echo %YELLOW%2.%RESET% List all workflows
echo %YELLOW%3.%RESET% Show workflow details
echo %YELLOW%4.%RESET% Exit
echo.

set /p choice="Enter option (1-4): "

if "%choice%"=="1" goto run_workflow
if "%choice%"=="2" goto list_workflows
if "%choice%"=="3" goto show_workflow
if "%choice%"=="4" goto exit
goto invalid_choice

:run_workflow
echo.
echo %BLUE%=== Run New Workflow ===%RESET%
echo.

echo.
echo %GREEN%Starting workflow...%RESET%
echo %BLUE%Task: %task%%RESET%
echo.

python agent_system/run_workflow.py run --task "%task%"
echo.
pause
goto menu

:list_workflows
echo.
echo %BLUE%=== List All Workflows ===%RESET%
echo.
python agent_system/run_workflow.py list
echo.
pause
goto menu

:show_workflow
echo.
echo %BLUE%=== Show Workflow Details ===%RESET%
echo.
set /p workflow_id="Enter workflow ID: "
if "%workflow_id%"=="" (
    echo %RED%Error: Workflow ID cannot be empty%RESET%
    pause
    goto show_workflow
)

echo.
python agent_system/run_workflow.py show --workflow-id "%workflow_id%"
echo.
pause
goto menu

:invalid_choice
echo %RED%Invalid option, please try again%RESET%
pause
goto menu

:exit
echo.
echo %GREEN%Thank you for using RMDS Agent System!%RESET%
echo.
pause
exit /b 0
