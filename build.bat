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
    src\core\mtproto.c ^
    src\platform\cli\main.c ^
    ws2_32.lib advapi32.lib ^
    /Fe:bin\cegram_cli.exe /Fo:bin\

if errorlevel 1 (
    echo [!] Build failed!
    exit /b 1
)

echo.
echo [!] Build successful: bin\cegram_cli.exe
echo.
