@echo off
setlocal

set ROOT_DIR=%~dp0
set EMU_EXE=%ROOT_DIR%emulator\Program Files\Microsoft Device Emulator\1.0\DeviceEmulator.exe
set BIN_IMG=%ROOT_DIR%emulator\images\Pocket_PC\PPC_2003_SE_WWE.bin
set SHARED_DIR=%ROOT_DIR%bin

if not exist "%EMU_EXE%" (
    echo [!] Emulator executable not found: %EMU_EXE%
    exit /b 1
)

if not exist "%BIN_IMG%" (
    echo [!] Windows CE ROM image not found: %BIN_IMG%
    exit /b 1
)

echo [*] Launching Windows CE / Pocket PC 2003 SE Emulator...
echo [*] Shared folder mapped to \Storage Card: %SHARED_DIR%
echo [*] Press Ctrl+Alt+Break to release host cursor.

start "" "%EMU_EXE%" "%BIN_IMG%" /memsize 128 /sharedfolder "%SHARED_DIR%"
