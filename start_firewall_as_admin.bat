@echo off
echo ===================================================================
echo  Net-Firewall 1-Click Administrator Launcher
echo ===================================================================

net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run_server
) else (
    echo [INFO] Requesting Administrator Privileges via Windows UAC...
    powershell -Command Start-Process cmd -ArgumentList '/k cd /d %~dp0 & python app.py & python restore_internet.py' -Verb runAs
    exit /b
)

:run_server
cd /d %~dp0
python app.py
python restore_internet.py
pause
