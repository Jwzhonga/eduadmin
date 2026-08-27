@echo off
echo Stopping ClassManager server...

:: Find and kill pythonw running app.py
for /f "tokens=2 delims=," %%a in ('tasklist /fi "imagename eq pythonw.exe" /fo csv /nh 2^>nul') do (
    taskkill /f /pid %%a >nul 2>&1
)

echo [OK] Server stopped.
pause
