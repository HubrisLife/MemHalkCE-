@echo off
setlocal

echo.
echo  MemHawk CE - Build Script
echo  Requires: MinGW-w64 with g++ on PATH
echo  Install via MSYS2: pacman -S mingw-w64-x86_64-gcc
echo.

:: Check for compiler
where g++ >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] g++ not found on PATH.
    echo.
    echo  Install MSYS2 from https://www.msys2.org/
    echo  Then run: pacman -S mingw-w64-x86_64-gcc
    echo  And add C:\msys64\mingw64\bin to your PATH.
    echo.
    pause
    exit /b 1
)

echo  Compiler: 
g++ --version | findstr /i "g++"

echo.
echo  Building MemHawkCE.exe ...
echo.

g++ -std=c++17 -O2 -mwindows ^
    -o MemHawkCE.exe ^
    main.cpp scanner.cpp ^
    -lcomctl32 -lcomdlg32 -lshlwapi -lshell32 -lpsapi -lole32 ^
    -static-libgcc -static-libstdc++ ^
    -Wno-cast-function-type

if %ERRORLEVEL% neq 0 (
    echo.
    echo  [FAILED] Build errors above.
    pause
    exit /b 1
)

echo.
echo  [SUCCESS] MemHawkCE.exe built successfully.
echo.
echo  Remember to run as Administrator when using MemHawk.
echo.

endlocal
pause
