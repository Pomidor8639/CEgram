@echo off
setlocal

echo [*] Setting up Visual Studio 2022 environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" > nul
if errorlevel 1 (
    echo [!] Failed to load vcvars64.bat. Please check your Visual Studio installation.
    exit /b 1
)

if not exist bin mkdir bin

echo [*] Compiling CEgram CLI for PC (x64)...
cl.exe /nologo /W3 /O2 /I"include" ^
    src\core\mini-gmp.c ^
    src\core\transport.c ^
    src\core\crypto.c ^
    src\core\rsa_keys.c ^
    src\core\aes.c ^
    src\core\tl.c ^
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
