@echo off
REM RMDS Agent System - Workflow Starter
REM Windows 批處理腳本，用於啟動 Agent 工作流

setlocal enabledelayedexpansion

REM 設置顏色代碼
set "GREEN=[92m"
set "YELLOW=[93m"
set "RED=[91m"
set "BLUE=[94m"
set "RESET=[0m"

echo %BLUE%========================================%RESET%
echo %BLUE%  RMDS Agent System - Workflow Starter  %RESET%
echo %BLUE%========================================%RESET%
echo.

REM 檢查 Python 是否安裝
python --version >nul 2>&1
if errorlevel 1 (
    echo %RED%錯誤: 未找到 Python，請先安裝 Python 3.8+%RESET%
    pause
    exit /b 1
)

REM 檢查是否在正確的目錄
if not exist "policy.json" (
    echo %YELLOW%警告: 未找到 policy.json，請確保在 RMDS 項目根目錄中運行此腳本%RESET%
    echo %YELLOW%當前目錄: %CD%%RESET%
    pause
)

REM 檢查 agent_system 目錄
if not exist "agent_system" (
    echo %RED%錯誤: 未找到 agent_system 目錄%RESET%
    pause
    exit /b 1
)

REM 檢查 Python 依賴
echo %BLUE%檢查 Python 依賴...%RESET%
cd agent_system
pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
    echo %YELLOW%警告: 部分依賴安裝失敗，但可能不影響基本功能%RESET%
)
cd ..

REM 創建日誌目錄
if not exist "logs" mkdir logs

echo.
echo %GREEN%環境檢查完成！%RESET%
echo.

REM 顯示使用選項
echo %BLUE%請選擇操作:%RESET%
echo.
echo %YELLOW%1.%RESET% 運行新工作流
echo %YELLOW%2.%RESET% 列出所有工作流
echo %YELLOW%3.%RESET% 查看工作流詳情
echo %YELLOW%4.%RESET% 退出
echo.

set /p choice="請輸入選項 (1-4): "

if "%choice%"=="1" goto run_workflow
if "%choice%"=="2" goto list_workflows
if "%choice%"=="3" goto show_workflow
if "%choice%"=="4" goto exit
goto invalid_choice

:run_workflow
echo.
echo %BLUE%=== 運行新工作流 ===%RESET%
echo.
set /p task="請輸入任務描述: "
if "%task%"=="" (
    echo %RED%錯誤: 任務描述不能為空%RESET%
    pause
    goto run_workflow
)

echo.
echo %GREEN%啟動工作流...%RESET%
echo %BLUE%任務: %task%%RESET%
echo.

python agent_system/run_workflow.py run --task "%task%"
echo.
pause
goto menu

:list_workflows
echo.
echo %BLUE%=== 列出所有工作流 ===%RESET%
echo.
python agent_system/run_workflow.py list
echo.
pause
goto menu

:show_workflow
echo.
echo %BLUE%=== 查看工作流詳情 ===%RESET%
echo.
set /p workflow_id="請輸入工作流 ID: "
if "%workflow_id%"=="" (
    echo %RED%錯誤: 工作流 ID 不能為空%RESET%
    pause
    goto show_workflow
)

echo.
python agent_system/run_workflow.py show --workflow-id "%workflow_id%"
echo.
pause
goto menu

:invalid_choice
echo %RED%無效選項，請重新選擇%RESET%
pause
goto menu

:menu
cls
echo %BLUE%========================================%RESET%
echo %BLUE%  RMDS Agent System - Workflow Starter  %RESET%
echo %BLUE%========================================%RESET%
echo.
echo %BLUE%請選擇操作:%RESET%
echo.
echo %YELLOW%1.%RESET% 運行新工作流
echo %YELLOW%2.%RESET% 列出所有工作流
echo %YELLOW%3.%RESET% 查看工作流詳情
echo %YELLOW%4.%RESET% 退出
echo.

set /p choice="請輸入選項 (1-4): "

if "%choice%"=="1" goto run_workflow
if "%choice%"=="2" goto list_workflows
if "%choice%"=="3" goto show_workflow
if "%choice%"=="4" goto exit
goto invalid_choice

:exit
echo.
echo %GREEN%感謝使用 RMDS Agent System！%RESET%
echo.
pause
exit /b 0
