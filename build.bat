@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul 2>&1
set "PATH=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;%PATH%"
set "INCLUDE=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared;%~dp0include;%INCLUDE%"
set "LIB=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64;%LIB%"

if not exist bin mkdir bin

echo [*] Compiling CEgram CLI for PC (x64)...
cl.exe /nologo /W3 /O2 /I"include" ^
    src\core\mini-gmp.c ^
    src\core\transport.c ^
    src\core\crypto.c ^
    src\core\rsa_keys.c ^
    src\core\aes.c ^
    src\core\tl.c ^
    src\core\tinf.c ^
    src\core\mtproto.c ^
    src\platform\cli\main.c ^
    ws2_32.lib advapi32.lib ^
    /Fe:bin\cegram_cli.exe /Fo:bin\

if errorlevel 1 (
    echo [!] CLI build failed!
    exit /b 1
)

echo [*] Compiling CEgram GUI (Win32 / WinCE simulation)...
cl.exe /nologo /W3 /O2 /I"include" ^
    src\core\mini-gmp.c ^
    src\core\transport.c ^
    src\core\crypto.c ^
    src\core\rsa_keys.c ^
    src\core\aes.c ^
    src\core\tl.c ^
    src\core\tinf.c ^
    src\core\mtproto.c ^
    src\platform\wince\gui_main.c ^
    ws2_32.lib advapi32.lib user32.lib gdi32.lib comctl32.lib ^
    /Fe:bin\cegram_gui.exe /Fo:bin\

if errorlevel 1 (
    echo [!] GUI build failed!
    exit /b 1
)

echo.
echo [!] All builds successful:
echo     - bin\cegram_cli.exe
echo     - bin\cegram_gui.exe
echo.
