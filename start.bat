@echo off
echo ============================================
echo  CTF Toolkit - Quick Start
echo ============================================

if not exist .venv\Scripts\activate.bat (
    echo [ERROR] Virtual environment not found. Run install.bat first.
    pause
    exit /b 1
)

:: Start the web server in a background window
echo [1/2] Starting the dashboard...
start "CTF Toolkit Server" /min cmd /c "call .venv\Scripts\activate.bat && ctf web start"

:: Give it a moment, then open the browser
echo [2/2] Opening http://localhost:8080 ...
timeout /t 3 /nobreak >nul
start "" http://localhost:8080

echo.
echo  The dashboard runs in the "CTF Toolkit Server" window.
echo  Close that window to stop it.
pause
exit /b 0