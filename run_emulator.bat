@echo off
setlocal

set ROOT_DIR=%~dp0
set EMU_EXE=%ROOT_DIR%emulator\Program Files\Microsoft Device Emulator\1.0\DeviceEmulator.exe
set BIN_IMG=%ROOT_DIR%emulator\rom\PPC_USA.bin
set SKIN_XML=%ROOT_DIR%emulator\rom\Pocket_PC.xml
set SHARED_DIR=%ROOT_DIR%bin

if not exist "%EMU_EXE%" (
    echo [!] Emulator executable not found: %EMU_EXE%
    exit /b 1
)

if not exist "%BIN_IMG%" (
    echo [!] Windows Mobile ROM image not found: %BIN_IMG%
    exit /b 1
)

echo [*] Launching Windows Mobile 5.0 / Windows CE ARM Emulator...
echo [*] ROM: %BIN_IMG%
echo [*] Shared folder mapped to \Storage Card: %SHARED_DIR%
echo [*] Press Ctrl+Alt+Break to release host cursor.

cd /d "%ROOT_DIR%emulator\rom"
start "" "%EMU_EXE%" "%BIN_IMG%" /skin "Pocket_PC.xml" /memsize 128 /sharedfolder "%SHARED_DIR%"
