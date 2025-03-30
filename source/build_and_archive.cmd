@echo off

call build_release

rem === Config ===
set "build_dir=build_x64"
set "publish_dir=%build_dir%\publish"
set "win_file=Astral-PE.exe"
set "linux_file=Astral-PE"

rem === Check files ===
if not exist "%build_dir%\%win_file%" (
    echo [ERROR] File not found: %build_dir%\%win_file%
    exit /b 1
)

if not exist "%build_dir%\%linux_file%" (
    echo [ERROR] File not found: %build_dir%\%linux_file%
    exit /b 1
)

rem === Ask version ===
set /p version=Enter current version (e.g. 1.4.5.0): 
set "tag=v%version%"

rem === Create publish folder if not exists ===
if not exist "%publish_dir%" (
    mkdir "%publish_dir%"
)

rem === Create temp folders ===
set "temp_win=%TEMP%\pack_win_%RANDOM%"
set "temp_linux=%TEMP%\pack_linux_%RANDOM%"
mkdir "%temp_win%"
mkdir "%temp_linux%"

copy "%build_dir%\%win_file%" "%temp_win%\%win_file%" >nul
copy "%build_dir%\%linux_file%" "%temp_linux%\%linux_file%" >nul

rem === Set output archive names ===
set "zip_win=%publish_dir%\Astral-PE-Windows-%tag%.zip"
set "zip_linux=%publish_dir%\Astral-PE-Linux-%tag%.zip"

rem === Create ZIPs ===
powershell -NoLogo -NoProfile -Command ^
  "Add-Type -Assembly 'System.IO.Compression.FileSystem';" ^
  "[IO.Compression.ZipFile]::CreateFromDirectory('%temp_win%', '%zip_win%');" ^
  "[IO.Compression.ZipFile]::CreateFromDirectory('%temp_linux%', '%zip_linux%');"

rem === Cleanup ===
rd /s /q "%temp_win%"
rd /s /q "%temp_linux%"

echo [SUCCESS] Archives created:
echo   %zip_win%
echo   %zip_linux%

pause
