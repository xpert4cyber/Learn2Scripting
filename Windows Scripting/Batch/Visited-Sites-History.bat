@echo off
setlocal enabledelayedexpansion

:: Define output file
set outputFile=%CD%\browsing_history.txt
set dbCopyFolder=%CD%\BrowserHistoryBackup

:: Create backup folder
if not exist "%dbCopyFolder%" mkdir "%dbCopyFolder%"

:: Extract Chrome History
set chromeDB="%LOCALAPPDATA%\Google\Chrome\User Data\Default\History"
if exist %chromeDB% (
    copy /Y %chromeDB% "%dbCopyFolder%\Chrome_History.db"
    echo [✔] Chrome history copied to %dbCopyFolder%\Chrome_History.db >> "%outputFile%"
) else (
    echo [X] Chrome history not found >> "%outputFile%"
)

:: Extract Edge History
set edgeDB="%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History"
if exist %edgeDB% (
    copy /Y %edgeDB% "%dbCopyFolder%\Edge_History.db"
    echo [✔] Edge history copied to %dbCopyFolder%\Edge_History.db >> "%outputFile%"
) else (
    echo [X] Edge history not found >> "%outputFile%"
)

:: Extract Firefox History
for /d %%D in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
    set firefoxDB="%%D\places.sqlite"
    if exist !firefoxDB! (
        copy /Y !firefoxDB! "%dbCopyFolder%\Firefox_History.db"
        echo [✔] Firefox history copied to %dbCopyFolder%\Firefox_History.db >> "%outputFile%"
        goto :done
    )
)
echo [X] Firefox history not found >> "%outputFile%"

:done
echo.
echo [*] History databases saved in %dbCopyFolder%
echo [*] Open the following website to extract data:
echo    🔗 https://sqliteviewer.app/
echo.
start https://sqliteviewer.app/
start "" "%dbCopyFolder%"

pause
