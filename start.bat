@echo off
title Phishing Website Detector - Setup and Start
color 0A

set "BASE=%~dp0"
set "PROJECT_DIR=%BASE%PhishingWebsiteDetector"
set "VENV_DIR=%PROJECT_DIR%\.venv"
set "MODEL_FILE=%PROJECT_DIR%\backend\model\phishing_model.pkl"
set "PYTHON=python"

echo ============================================
echo   Phishing Website Detector - Auto Setup
echo ============================================
echo.

:: Check Python
%PYTHON% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)
echo [OK] Python found.

:: Create virtual environment if not exists
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo [STEP] Creating virtual environment...
    %PYTHON% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

:: Kill any existing Flask server on port 5000
echo [STEP] Stopping any existing server on port 5000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING 2^>nul') do taskkill /F /PID %%a >nul 2>&1
echo [OK] Port 5000 is free.

:: Activate venv
call "%VENV_DIR%\Scripts\activate.bat"

:: Install dependencies
echo [STEP] Installing dependencies...
pip install -q flask flask-cors scikit-learn joblib numpy pandas
echo [OK] Dependencies installed.

:: Train model if not exists
if exist "%MODEL_FILE%" goto skip_training

echo.
echo [STEP] Training ML model (this takes 1-2 minutes)...
cd /d "%PROJECT_DIR%\ml"
python preprocess.py
if errorlevel 1 (
    echo [ERROR] Preprocessing failed.
    pause
    exit /b 1
)
python train_model.py
if errorlevel 1 (
    echo [ERROR] Training failed.
    pause
    exit /b 1
)
echo [OK] Model trained and saved.
goto start_server

:skip_training
echo [OK] Model already exists. Skipping training.

:start_server
echo.
echo ============================================
echo   Starting Flask API on http://127.0.0.1:5000
echo   Press Ctrl+C to stop the server
echo ============================================
echo.
cd /d "%PROJECT_DIR%\backend"
python app.py

pause
