@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   CEgram - Windows CE Cross-Compilation (ARM / x86)
echo ========================================================

if not exist bin mkdir bin

set ROOT_DIR=%~dp0
set ARM_DIR=%ROOT_DIR%toolchain\armmingw32ce
set X86_DIR=%ROOT_DIR%toolchain\x86mingw32ce

if not exist "%ARM_DIR%\bin\arm-mingw32ce-gcc.exe" (
    echo [!] ARM toolchain not detected in toolchain\armmingw32ce.
    goto check_x86
)

echo [*] Compiling CEgram GUI for Windows CE (ARM)...
set PATH=%ARM_DIR%\bin;%PATH%
"%ARM_DIR%\bin\arm-mingw32ce-gcc.exe" ^
    -B"%ARM_DIR%\libexec\gcc\arm-mingw32ce\4.4.0" ^
    -B"%ARM_DIR%\arm-mingw32ce\bin" ^
    -B"%ARM_DIR%\arm-mingw32ce\lib" ^
    -isystem "%ARM_DIR%\lib\gcc\arm-mingw32ce\4.4.0\include" ^
    -isystem "%ARM_DIR%\arm-mingw32ce\include" ^
    -L"%ARM_DIR%\arm-mingw32ce\lib" ^
    -L"%ARM_DIR%\lib\gcc\arm-mingw32ce\4.4.0" ^
    -I"%ROOT_DIR%include" ^
    -D_WIN32_WCE=0x0420 -DUNICODE -D_UNICODE -O2 -Wall ^
    "%ROOT_DIR%src\core\mini-gmp.c" ^
    "%ROOT_DIR%src\core\transport.c" ^
    "%ROOT_DIR%src\core\crypto.c" ^
    "%ROOT_DIR%src\core\rsa_keys.c" ^
    "%ROOT_DIR%src\core\aes.c" ^
    "%ROOT_DIR%src\core\tl.c" ^
    "%ROOT_DIR%src\core\mtproto.c" ^
    "%ROOT_DIR%src\platform\wince\gui_main.c" ^
    -o "%ROOT_DIR%bin\cegram_gui_arm.exe" ^
    -lws2 -lcommctrl

if errorlevel 1 (
    echo [!] Failed to compile ARM GUI binary!
) else (
    echo [+] Built bin\cegram_gui_arm.exe
)

echo [*] Compiling CEgram CLI for Windows CE (ARM)...
"%ARM_DIR%\bin\arm-mingw32ce-gcc.exe" ^
    -B"%ARM_DIR%\libexec\gcc\arm-mingw32ce\4.4.0" ^
    -B"%ARM_DIR%\arm-mingw32ce\bin" ^
    -B"%ARM_DIR%\arm-mingw32ce\lib" ^
    -isystem "%ARM_DIR%\lib\gcc\arm-mingw32ce\4.4.0\include" ^
    -isystem "%ARM_DIR%\arm-mingw32ce\include" ^
    -L"%ARM_DIR%\arm-mingw32ce\lib" ^
    -L"%ARM_DIR%\lib\gcc\arm-mingw32ce\4.4.0" ^
    -I"%ROOT_DIR%include" ^
    -D_WIN32_WCE=0x0420 -DUNICODE -D_UNICODE -O2 -Wall ^
    "%ROOT_DIR%src\core\mini-gmp.c" ^
    "%ROOT_DIR%src\core\transport.c" ^
    "%ROOT_DIR%src\core\crypto.c" ^
    "%ROOT_DIR%src\core\rsa_keys.c" ^
    "%ROOT_DIR%src\core\aes.c" ^
    "%ROOT_DIR%src\core\tl.c" ^
    "%ROOT_DIR%src\core\mtproto.c" ^
    "%ROOT_DIR%src\platform\cli\main.c" ^
    -o "%ROOT_DIR%bin\cegram_cli_arm.exe" ^
    -lws2

if errorlevel 1 (
    echo [!] Failed to compile ARM CLI binary!
) else (
    echo [+] Built bin\cegram_cli_arm.exe
)

:check_x86
if not exist "%X86_DIR%\bin\i386-mingw32ce-gcc.exe" (
    echo [!] x86 toolchain not detected in toolchain\x86mingw32ce.
    goto done
)

echo [*] Compiling CEgram GUI for Windows CE (x86 CEPC)...
set PATH=%X86_DIR%\bin;%PATH%
"%X86_DIR%\bin\i386-mingw32ce-gcc.exe" ^
    -B"%X86_DIR%\libexec\gcc\i386-mingw32ce\4.4.0" ^
    -B"%X86_DIR%\i386-mingw32ce\bin" ^
    -B"%X86_DIR%\i386-mingw32ce\lib" ^
    -isystem "%X86_DIR%\lib\gcc\i386-mingw32ce\4.4.0\include" ^
    -isystem "%X86_DIR%\i386-mingw32ce\include" ^
    -L"%X86_DIR%\i386-mingw32ce\lib" ^
    -L"%X86_DIR%\lib\gcc\i386-mingw32ce\4.4.0" ^
    -I"%ROOT_DIR%include" ^
    -D_WIN32_WCE=0x0420 -DUNICODE -D_UNICODE -O2 -Wall ^
    "%ROOT_DIR%src\core\mini-gmp.c" ^
    "%ROOT_DIR%src\core\transport.c" ^
    "%ROOT_DIR%src\core\crypto.c" ^
    "%ROOT_DIR%src\core\rsa_keys.c" ^
    "%ROOT_DIR%src\core\aes.c" ^
    "%ROOT_DIR%src\core\tl.c" ^
    "%ROOT_DIR%src\core\mtproto.c" ^
    "%ROOT_DIR%src\platform\wince\gui_main.c" ^
    -o "%ROOT_DIR%bin\cegram_gui_x86ce.exe" ^
    -lws2 -lcommctrl

if errorlevel 1 (
    echo [!] Failed to compile x86 GUI binary!
) else (
    echo [+] Built bin\cegram_gui_x86ce.exe
)

echo [*] Compiling CEgram CLI for Windows CE (x86 CEPC)...
"%X86_DIR%\bin\i386-mingw32ce-gcc.exe" ^
    -B"%X86_DIR%\libexec\gcc\i386-mingw32ce\4.4.0" ^
    -B"%X86_DIR%\i386-mingw32ce\bin" ^
    -B"%X86_DIR%\i386-mingw32ce\lib" ^
    -isystem "%X86_DIR%\lib\gcc\i386-mingw32ce\4.4.0\include" ^
    -isystem "%X86_DIR%\i386-mingw32ce\include" ^
    -L"%X86_DIR%\i386-mingw32ce\lib" ^
    -L"%X86_DIR%\lib\gcc\i386-mingw32ce\4.4.0" ^
    -I"%ROOT_DIR%include" ^
    -D_WIN32_WCE=0x0420 -DUNICODE -D_UNICODE -O2 -Wall ^
    "%ROOT_DIR%src\core\mini-gmp.c" ^
    "%ROOT_DIR%src\core\transport.c" ^
    "%ROOT_DIR%src\core\crypto.c" ^
    "%ROOT_DIR%src\core\rsa_keys.c" ^
    "%ROOT_DIR%src\core\aes.c" ^
    "%ROOT_DIR%src\core\tl.c" ^
    "%ROOT_DIR%src\core\mtproto.c" ^
    "%ROOT_DIR%src\platform\cli\main.c" ^
    -o "%ROOT_DIR%bin\cegram_cli_x86ce.exe" ^
    -lws2

if errorlevel 1 (
    echo [!] Failed to compile x86 CLI binary!
) else (
    echo [+] Built bin\cegram_cli_x86ce.exe
)

:done
echo.
echo ========================================================
echo   Compilation complete. Binaries located in bin\
echo ========================================================
