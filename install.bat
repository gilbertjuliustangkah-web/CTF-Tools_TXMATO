@echo off
echo ============================================
echo  CTF Toolkit - Windows Setup
echo ============================================

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 not found. Install from https://python.org
    pause
    exit /b 1
)

:: Create virtual environment
echo.
echo [1/3] Creating virtual environment...
python -m venv .venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create venv
    pause
    exit /b 1
)

:: Activate and install
echo [2/3] Installing dependencies...
call .venv\Scripts\activate.bat
pip install -e . --quiet
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)

:: Create workspace dir
echo [3/3] Setting up workspace...
if not exist workspace mkdir workspace

echo.
echo ============================================
echo  Done! To use:
echo.
echo    .venv\Scripts\activate
echo    ctf --help
echo    ctf web start
echo ============================================
pause
