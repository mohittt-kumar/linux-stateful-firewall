@echo off
echo ===================================================================
echo  Starting Linux Stateful Network Firewall Management Console...
echo ===================================================================
python app.py
echo.
echo [CLEANUP] Ensuring Windows browser proxy is disabled...
python restore_internet.py
pause
