@echo off
setlocal

:: Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Please run this script as Administrator.
    pause
    exit
)

echo Cleaning Windows junk files and optimizing system...

:: Cleaning Temp folders
echo Cleaning Windows Temp folder...
rd /s /q C:\Windows\Temp
md C:\Windows\Temp

echo Cleaning User Temp folder...
rd /s /q %temp%
md %temp%

:: Cleaning Prefetch
echo Cleaning Prefetch folder...
rd /s /q C:\Windows\Prefetch
md C:\Windows\Prefetch

:: Emptying Recycle Bin (Alternative Method)
echo Emptying Recycle Bin...
rd /s /q C:\$Recycle.Bin

:: Removing Windows Update Cache
echo Cleaning Windows Update Cache...
net stop wuauserv
rd /s /q C:\Windows\SoftwareDistribution
md C:\Windows\SoftwareDistribution
net start wuauserv

:: Running Disk Cleanup (Silent Mode)
echo Running Disk Cleanup...
cleanmgr /sagerun:1

:: Optimize and Defragment Drives
echo Optimizing drives...
defrag C: /O
defrag D: /O

:: Flush DNS cache
echo Flushing DNS Cache...
ipconfig /flushdns

echo System cleanup and optimization completed!
pause
