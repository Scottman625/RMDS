@echo off
chcp 65001 >nul
echo ========================================
echo Universal Memory Attack Detection Engine Test
echo ========================================
echo.
echo This script will start the adaptive detection engine
echo The detection engine will adjust sensitivity based on process type:
echo - System processes: Higher thresholds, reduce false positives
echo - User processes: Medium thresholds
echo - High-risk processes: Lower thresholds, easier detection
echo - Attack simulator: Lowest thresholds, ensure detection
echo.
pause

echo.
echo Starting universal detection engine (admin privileges)...
powershell -Command "Start-Process -FilePath 'build\src\Release\real_detection_engine.exe' -Verb RunAs -WorkingDirectory '%~dp0'"

echo.
echo Waiting 3 seconds for detection engine to initialize...
timeout /t 3 /nobreak

echo.
echo Starting attack simulator...
cd build\src\Release
start "Attack Simulator" attack_simulator.exe

echo.
echo ========================================
echo Test Instructions:
echo ========================================
echo 1. Detection engine now supports universal detection
echo 2. System processes use higher thresholds to avoid false positives
echo 3. High-risk processes use lower thresholds
echo 4. Attack simulator uses lowest thresholds
echo 5. Enter numbers (1-5) in attack simulator to trigger attacks
echo 6. Observe detection engine output for different process categories
echo.
echo Press any key to exit...
pause 