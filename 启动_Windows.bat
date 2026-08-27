@echo off
chcp 65001 >nul 2>&1
title 教务管理系统
cd /d "%~dp0"
setlocal enabledelayedexpansion

echo.
echo ========================================
echo   Class Management System
echo ========================================

:: ---------- Check / Install Python ----------
set PYTHON=
py --version >nul 2>&1
if %errorlevel% equ 0 ( set PYTHON=py ) else (
    python --version >nul 2>&1
    if %errorlevel% equ 0 ( set PYTHON=python )
)

if "%PYTHON%"=="" (
    echo.
    echo [INFO] Python not detected.
    echo [1/4] Detecting system...
    ver | find "10.0" >nul && echo   Windows 10/11 detected || (
        ver | find "6.1" >nul && echo   Windows 7 detected || echo   Windows detected
    )
    echo [2/4] Trying to download Python 3.12...
    echo.
    echo (Copy this link to your browser if download fails:)
    echo https://mirrors.tuna.tsinghua.edu.cn/python/3.12.10/python-3.12.10-amd64.exe
    echo.

    set "MIRROR=https://mirrors.tuna.tsinghua.edu.cn/python/3.12.10/python-3.12.10-amd64.exe"
    set "OUT=%TEMP%\python-installer.exe"
    set DOWNLOADED=0

    echo Trying: bitsadmin + TUNA mirror...
    bitsadmin /transfer "PythonDownload" /download /priority high "%MIRROR%" "%OUT%" 2>&1
    if exist "%OUT%" (set DOWNLOADED=1) else (echo FAILED)

    if !DOWNLOADED! equ 0 (
        echo Trying: certutil + TUNA mirror...
        certutil -urlcache -split -f "%MIRROR%" "%OUT%" 2>&1
        if exist "%OUT%" (set DOWNLOADED=1) else (echo FAILED)
    )

    if !DOWNLOADED! equ 0 (
        echo Trying: PowerShell + TUNA mirror...
        powershell -Command "$wc=New-Object net.webclient; try{echo downloading...;$wc.DownloadFile('%MIRROR%','%OUT%');echo ok}catch{echo error: $_.Exception.Message;exit 1}"
        if exist "%OUT%" (set DOWNLOADED=1) else (echo FAILED)
    )

    if !DOWNLOADED! equ 0 (
        echo.
        echo All download methods failed.
        echo The school network may be blocking file downloads.
        echo.
        echo Solution: Download Python manually:
        echo 1. Open this link in your browser:
        echo    https://mirrors.tuna.tsinghua.edu.cn/python/3.12.10/python-3.12.10-amd64.exe
        echo 2. Save the installer
        echo 3. Run this script again
        echo.
        pause
        exit /b 1
    )
    echo [2/4] Installing Python...
    start /wait "" "%TEMP%\python-installer.exe" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1
    set "PATH=%LOCALAPPDATA%\Programs\Python\Python312\;%LOCALAPPDATA%\Programs\Python\Python312\Scripts\;%PATH%"
    set PYTHON=python
    echo [OK] Python installed.
)

:: ---------- Create venv ----------
if not exist "venv\Scripts\python.exe" (
    echo.
    echo [3/4] Creating virtual environment...
    %PYTHON% -m venv venv
    if %errorlevel% neq 0 (
        echo [INFO] Trying pip virtualenv...
        pip install virtualenv >nul 2>&1
        virtualenv venv
    )
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create venv.
        pause
        exit /b 1
    )
)

:: ---------- Install dependencies (requirements.txt 为准，含 cryptography/docx 等) ----------
venv\Scripts\python -c "import flask, flask_sqlalchemy, cryptography, openpyxl, xlrd" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [3/4] Installing dependencies (may take a few minutes)...
    venv\Scripts\pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ --timeout 60 -r requirements.txt
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Failed to install dependencies.
        echo Please check the error messages above ^(usually network or pip issues^).
        echo If it mentions "Could not find a version", run:
        echo   venv\Scripts\pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ --upgrade pip
        pause
        exit /b 1
    )
)

:: ---------- Verify critical dependencies ----------
echo.
echo Checking dependencies...
venv\Scripts\python -c "import flask; import flask_sqlalchemy; import cryptography; import openpyxl; import xlrd" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Critical dependencies missing. Run:
    echo   venv\Scripts\pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ -r requirements.txt
    pause
    exit /b 1
)

:: ---------- Syntax check ----------
venv\Scripts\python -c "import py_compile; py_compile.compile('app.py', doraise=True)" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] app.py has syntax errors. The program file may be damaged.
    pause
    exit /b 1
)

:: ---------- Ensure directories ----------
if not exist "instance" mkdir instance
if not exist "static\uploads" mkdir static\uploads

:: ---------- Launch ----------
echo.
echo [4/4] Starting server in background...
echo.

:: 启动后台服务（pythonw 无控制台窗口；日志写入 server.log）
start /b "" "venv\Scripts\pythonw.exe" app.py --port 5801

:: 等待端口就绪（最多 20 秒）
set PORT_OK=0
for /l %%i in (1,1,20) do (
    timeout /t 1 /nobreak >nul
    powershell -Command "try{$c=New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1',5801); $c.Close(); exit 0}catch{exit 1}" >nul 2>&1
    if !errorlevel! equ 0 (
        set PORT_OK=1
        goto :port_ok
    )
)
:port_ok
if "%PORT_OK%"=="1" (
    echo.
    echo ========================================
    echo   Server is running!
    echo   Open browser to: http://localhost:5801
    echo   Login: admin / admin123
    echo   Close this window safely - server keeps running
    echo   To stop: double-click stop_server.bat
    echo ========================================
) else (
    echo.
    echo [WARNING] Server did not respond within 20 seconds.
    echo.
    echo Possible causes, check in order:
    echo   1. An old instance is still running on port 5801 - run stop_server.bat first
    echo      then start again.
    echo   2. Python could not start app.py. Run this command in this window
    echo      to see the real error message:
    echo        venv\Scripts\python app.py --port 5801
    echo      ^(keep that window open while using the system^)
    echo   3. Dependencies not fully installed. Run:
    echo        venv\Scripts\pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ --timeout 60 -r requirements.txt
    echo.
)
pause
