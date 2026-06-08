@echo off
echo Installing requirements...
pip install -r requirements.txt

echo Building for 32-bit...
pyinstaller --onefile --windowed --name "SecureVault_x86" password_manager.py

echo Building for 64-bit...
pyinstaller --onefile --windowed --name "SecureVault_x64" password_manager.py

echo Build complete! Check the 'dist' folder.
pause