@echo off
title Secure Password Vault
echo Starting Secure Vault...

:: Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed!
    echo Downloading portable Python...
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.8/python-3.11.8-embed-amd64.zip' -OutFile '%temp%\python.zip'"
    powershell -Command "Expand-Archive '%temp%\python.zip' -DestinationPath '%temp%\python_portable'"
    set PATH=%temp%\python_portable;%PATH%
)

:: Install required packages
echo Installing required packages...
%temp%\python_portable\python.exe -m pip install cryptography --target=%temp%\python_portable\Lib\site-packages

:: Run the vault
%temp%\python_portable\python.exe password_manager.py

pause
