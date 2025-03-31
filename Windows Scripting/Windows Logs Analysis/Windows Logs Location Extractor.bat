@echo off
title Log File Locator - Comprehensive Scan
color 0A
setlocal enabledelayedexpansion

:: Set output file on Desktop
set "outputFile=%USERPROFILE%\Desktop\LogFiles_Report_%date:~-4,4%-%date:~-7,2%-%date:~-10,2%.txt"

echo Comprehensive Log File Search
echo Scanning entire system for log files...
echo This may take several minutes...
echo.
echo Results will be saved to: %outputFile%
echo.

:: Clear previous output file if it exists
if exist "%outputFile%" del "%outputFile%"

:: Define common log file extensions
set "extensions=.log .txt .csv .xml .json .evt .etl .dmp .tmp .dat .out .err .debug .audit .trace"

:: Get all drive letters
echo Detecting available drives...
for /f "skip=1" %%d in ('wmic logicaldisk get caption') do (
    if exist %%d (
        echo Scanning drive %%d...
        for %%e in (%extensions%) do (
            echo Searching for *%%e files on %%d...
            for /f "delims=" %%f in ('dir /s /b /a-d "%%d\*%%e" 2^>nul') do (
                echo %%f >> "%outputFile%"
            )
        )
    )
)

:: Special check for Windows Event Logs
echo Checking Windows Event Logs...
for /f "delims=" %%l in ('dir /s /b "%SystemRoot%\System32\winevt\Logs\*" 2^>nul') do (
    echo %%l >> "%outputFile%"
)

:: Check common log directories
echo Checking common log directories...
for %%d in (
    "%SystemRoot%\Logs"
    "%ProgramData%\Microsoft\Windows\WER\ReportArchive"
    "%ProgramData%\Microsoft\Windows Defender\Support"
    "%LOCALAPPDATA%\Temp"
    "%USERPROFILE%\AppData\Local\Temp"
    "%USERPROFILE%\Documents"
) do (
    if exist "%%d" (
        echo Checking: %%d
        for /f "delims=" %%f in ('dir /s /b "%%d\*" 2^>nul') do (
            echo %%f >> "%outputFile%"
        )
    )
)

:: Generate summary
echo Generating summary...
set "total=0"
for /f %%i in ('type "%outputFile%" ^| find /c /v ""') do set "total=%%i"

echo. >> "%outputFile%"
echo ============================================ >> "%outputFile%"
echo LOG FILE SEARCH SUMMARY >> "%outputFile%"
echo ============================================ >> "%outputFile%"
echo Scan completed: %date% %time% >> "%outputFile%"
echo Total log files found: %total% >> "%outputFile%"
echo Output file: %outputFile% >> "%outputFile%"
echo ============================================ >> "%outputFile%"

:: Display completion message
echo.
echo ============================================
echo SCAN COMPLETED SUCCESSFULLY
echo ============================================
echo Total log files found: %total%
echo Full report saved to your Desktop:
echo %outputFile%
echo.
pause