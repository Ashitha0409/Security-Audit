@echo off
rem --------------------------------------------------
rem Run CyberShield (Windows CMD)
rem --------------------------------------------------

rem 1) Ensure we are in the project root (folder containing this .bat file)
cd /d "%~dp0"

rem 2) Create virtualenv if missing
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment. Ensure Python is installed and in PATH.
        pause
        exit /b 1
    )
)

rem 3) Activate venv
call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment.
    pause
    exit /b 1
)

rem 4) Install/update dependencies (using backend requirements for minimal set)
echo Installing dependencies...
pip install -r backend\requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause
    exit /b 1
)

rem 5) (Optional) Set your AI key here
rem set ANTHROPIC_API_KEY=your_api_key_here

rem 6) Run the web app in background
echo Starting CyberShield web app...
start "" python backend\app.py

rem 7) Wait a bit for the app to start
timeout /t 3 /nobreak >nul

rem 8) Open browser
start "" "http://localhost:5000"

echo CyberShield is running at http://localhost:5000
echo Press any key to stop the app...
pause >nul

rem 9) Kill the background process (if still running)
taskkill /f /im python.exe >nul 2>&1

echo Done.
