@echo off
setlocal enabledelayedexpansion

:: Get current date and time for unique folder names
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set datetime=%%I
set timestamp=%datetime:~0,4%-%datetime:~4,2%-%datetime:~6,2%_%datetime:~8,2%-%datetime:~10,2%

:: Set log folder on Desktop
set logFolder=%USERPROFILE%\Desktop\WindowsLogs_%timestamp%
mkdir "%logFolder%"

echo Extracting all Windows logs to %logFolder%...
echo.

:: Get a list of all available logs
for /f "delims=" %%L in ('wevtutil el') do (
    echo Exporting %%L log...
    wevtutil epl "%%L" "%logFolder%\%%L.evtx"
    wevtutil qe "%%L" /f:text > "%logFolder%\%%L.txt"
)

echo All logs have been extracted successfully!
echo Logs are stored in: %logFolder%
pause
