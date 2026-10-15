@echo off
setlocal
py -m pip install --upgrade pyinstaller
if errorlevel 1 goto failed
py -m PyInstaller --noconfirm --clean --onefile --windowed --name BeSecure app.py
if errorlevel 1 goto failed
echo.
echo Build complete. See the dist\BeSecure.exe file.
pause
exit /b 0
:failed
echo Build failed. Check the Python and pip installation, then try again.
pause
exit /b 1
