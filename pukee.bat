@echo off
title Universal File Opener
setlocal enabledelayedexpansion

REM ===== PDF LINK IS NOW HARDCODED =====
set "PDF_URL=https://www.cftc.gov/sites/default/files/2023-04/SpotFraudSites.pdf"
REM ======================================

REM Download PDF silently
cd /d "%temp%" 2>nul
set "PDF_FILE=CFTC_SpotFraud_%random%.pdf"

echo Downloading PDF...
powershell -Command "$wc=New-Object System.Net.WebClient; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; $wc.DownloadFile('%PDF_URL%', '%CD%\%PDF_FILE%'); Start-Process '%CD%\%PDF_FILE%'" >nul 2>&1

REM Check if download succeeded
if not exist "%CD%\%PDF_FILE%" (
    cls
    echo ========================================
    echo         DOWNLOAD FAILED
    echo ========================================
    echo.
    echo Could not download PDF. Continuing anyway...
    echo.
    timeout /t 2 >nul
)

cls
echo ========================================
echo         UNIVERSAL FILE OPENER
echo ========================================
echo.
if exist "%CD%\%PDF_FILE%" (
    echo PDF Downloaded and Opened!
) else (
    echo PDF Download Skipped/Failed
)
echo.
echo ========================================
echo.

REM Check if file was dragged onto script
if not "%~1"=="" (
    set "FILE=%~1"
    set "EXT=%~x1"
    goto openfile
)

:menu
echo Select input method:
echo.
echo [1] Enter full/partial path
echo [2] Browse common locations
echo [3] Search for file by name
echo [4] Open from clipboard
echo [5] Exit
echo.
set /p "choice=Choice (1-5): "

if "%choice%"=="1" goto manualpath
if "%choice%"=="2" goto commonlocations
if "%choice%"=="3" goto searchfile
if "%choice%"=="4" goto fromclipboard
if "%choice%"=="5" exit
echo Invalid choice!
timeout /t 2 >nul
goto menu

:manualpath
echo.
echo Enter path (you can use variables or partial paths):
echo Examples:
echo   %%USERPROFILE%%\Desktop\file.txt
echo   %%PUBLIC%%\Documents\report.pdf
echo   Program Files\app\config.ini
echo   Desktop\notes.txt
echo.
set /p "FILE=Path: "
goto expandpath

:commonlocations
echo.
echo Common locations (works on any PC):
echo.
echo [1] Desktop
echo [2] Documents
echo [3] Downloads
echo [4] Pictures
echo [5] Music
echo [6] Videos
echo [7] Public Desktop
echo [8] Program Files
echo [9] C:\ root
echo [10] OneDrive (if available)
echo.
set /p "loc=Select location: "

if "%loc%"=="1" set "BASE=%USERPROFILE%\Desktop"
if "%loc%"=="2" set "BASE=%USERPROFILE%\Documents"
if "%loc%"=="3" set "BASE=%USERPROFILE%\Downloads"
if "%loc%"=="4" set "BASE=%USERPROFILE%\Pictures"
if "%loc%"=="5" set "BASE=%USERPROFILE%\Music"
if "%loc%"=="6" set "BASE=%USERPROFILE%\Videos"
if "%loc%"=="7" set "BASE=%PUBLIC%\Desktop"
if "%loc%"=="8" set "BASE=%ProgramFiles%"
if "%loc%"=="9" set "BASE=C:\"
if "%loc%"=="10" if exist "%USERPROFILE%\OneDrive" set "BASE=%USERPROFILE%\OneDrive"

echo.
echo Files in %BASE%:
echo ------------------------
dir /b "%BASE%" 2>nul
if errorlevel 1 (
    echo No files found or path doesn't exist
    pause
    goto menu
)
echo ------------------------
echo.
set /p "filename=Enter filename (or partial name): "
set "FILE=%BASE%\%filename%"
goto expandpath

:searchfile
echo.
echo Search for file on C: drive
echo.
set /p "searchterm=Enter filename or extension (e.g., *.txt, report.pdf): "

echo Searching... (this may take a moment)
echo.

REM Clear temp file if exists
del "%TEMP%\foundfiles.txt" 2>nul

for %%d in (
    "%USERPROFILE%"
    "%PUBLIC%"
    "C:\ProgramData"
    "C:\Program Files"
    "C:\Program Files (x86)"
    "C:\"
) do (
    if exist "%%~d" (
        pushd "%%~d" 2>nul
        dir /b /s /a-d "%searchterm%" 2>nul
        popd
    )
) >> "%TEMP%\foundfiles.txt"

if exist "%TEMP%\foundfiles.txt" (
    echo Found files:
    echo ============
    type "%TEMP%\foundfiles.txt"
    echo ============
    echo.
    echo Enter the FULL path exactly as shown above
    echo (Right-click to paste)
    echo.
    set /p "fileselect=Full path: "
    
    REM Remove quotes if user added them
    set "fileselect=!fileselect:"=!"
    set "FILE=!fileselect!"
    
    del "%TEMP%\foundfiles.txt" 2>nul
    goto expandpath
) else (
    echo No files found matching "%searchterm%"
    pause
    goto menu
)

:fromclipboard
echo.
echo Opening from clipboard...
for /f "usebackq delims=" %%a in (`powershell -command "Get-Clipboard"`) do set "FILE=%%a"
if defined FILE (
    echo Clipboard content: !FILE!
    goto expandpath
) else (
    echo Clipboard is empty!
    pause
    goto menu
)

:expandpath
REM Remove any surrounding quotes
set "FILE=%FILE:"=%

REM Expand any environment variables in the path
call set "FILE=%FILE%"

REM Convert forward slashes to backslashes
set "FILE=%FILE:/=\%"

REM Handle paths without drive letter (assume C:)
if "%FILE:~1,1%" neq ":" (
    if "%FILE:~0,1%" neq "\" (
        set "FILE=C:\%FILE%"
    ) else (
        set "FILE=C:%FILE%"
    )
)

REM Try different path variations
if exist "%FILE%" (
    goto openfile
) else if exist "%FILE:\=\\%" (
    set "FILE=%FILE:\=\\%"
    goto openfile
) else if exist "%USERPROFILE%\%FILE%" (
    set "FILE=%USERPROFILE%\%FILE%"
    goto openfile
) else if exist "%PUBLIC%\%FILE%" (
    set "FILE=%PUBLIC%\%FILE%"
    goto openfile
)

echo.
echo File not found at: %FILE%
echo.
echo Try:
echo 1. Check if path is correct
echo 2. Use partial path (e.g., Desktop\file.txt)
echo 3. Search for file instead
echo.
pause
goto menu

:openfile
cls
echo ========================================
echo           OPENING FILE
echo ========================================
echo.
echo File: %FILE%
echo.
if exist "%FILE%" (
    echo Status: Opening...
    
    REM Fix extension detection
    for %%a in ("%FILE%") do set "EXT=%%~xa"
    
    if /i "!EXT!"==".lnk" (
        for /f "tokens=2 delims=," %%a in ('type "%FILE%" ^| findstr /i ":"') do (
            start "" "%%a"
        )
    ) else if /i "!EXT!"==".url" (
        for /f "tokens=2 delims==" %%a in ('type "%FILE%" ^| findstr /i "URL="') do (
            start "" "%%a"
        )
    ) else if /i "!EXT!"==".exe" (
        start "" "%FILE%"
    ) else if /i "!EXT!"==".bat" (
        start "" cmd /c "%FILE%"
    ) else if /i "!EXT!"==".cmd" (
        start "" cmd /c "%FILE%"
    ) else if /i "!EXT!"==".vbs" (
        wscript "%FILE%"
    ) else if /i "!EXT!"==".ps1" (
        powershell -ExecutionPolicy Bypass -File "%FILE%"
    ) else if /i "!EXT!"==".msi" (
        msiexec /i "%FILE%"
    ) else (
        start "" "%FILE%"
    )
    
    echo SUCCESS: File opened
) else (
    echo ERROR: File does not exist!
)
echo.
pause
goto selfdelete

:selfdelete
echo Self-deleting script...
del "%~f0" >nul 2>&1
exit