@echo off

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Ce script doit etre execute en tant qu’administrateur.
    pause
    exit /b
)

ver | findstr /i "10.0" >nul
if errorlevel 1 (
    echo Script teste que sur Windows Server 2022/2025.
    pause
    exit /b
)

setlocal EnableDelayedExpansion
                  
echo.
echo            Script Windows Server by Ryder-Blase     
echo             ==================================
echo.

echo Charger la ruche du User Default...
reg load "HKLM\DefUser" "C:\Users\Default\NTUSER.DAT" >nul 2>&1

echo Deleting Application Compatibility Appraiser...
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f >nul 2>&1

echo Suppression de OneDrive...
C:\Windows\System32\OneDriveSetup.exe /uninstall >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f >nul 2>&1

echo Nettoyage de la Taskbar...
reg add "HKLM\DefUser\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f >nul 2>&1
reg delete "HKLM\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f >nul 2>&1

echo Restauration du clique droit de Windows 10 (Legacy)...
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /d "" /f >nul 2>&1
reg add "HKLM\DefUser\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /d "" /f >nul 2>&1

:: Get Windows build number using PowerShell (since wmic is deprecated)
for /f %%a in ('powershell -NoProfile -Command "[Environment]::OSVersion.Version.Build"') do (
    set "build=%%a"
)

:: Show build number
echo Build number detected: !build!

:: Validate number
set /a buildCheck=!build! 2>nul
if "!buildCheck!"=="" (
    echo Build number is not a valid number.
    pause
    exit /b 1
)

if !buildCheck! GEQ 22000 (
    echo Windows 11 or Server 2022+ detected. Installing StartAllBack...
    powershell -Command "Invoke-WebRequest -Uri 'https://startisback.sfo3.cdn.digitaloceanspaces.com/StartAllBack_3.9.8_setup.exe' -OutFile '%TEMP%\startallback.exe'" >nul 2>&1
    start /wait "" "%TEMP%\startallback.exe" >nul 2>&1
) else (
    echo Windows 10 or lower detected. Installing StartIsBack...
    powershell -Command "Invoke-WebRequest -Uri 'https://startisback.sfo3.cdn.digitaloceanspaces.com/StartIsBackPlusPlus_setup.exe' -OutFile '%TEMP%\startisback.exe'" >nul 2>&1
    start /wait "" "%TEMP%\startisback.exe" >nul 2>&1
)
echo Desactivation du Shell etc ... (SystemApps)
taskkill /f /im ShellExperienceHost.exe >nul 2>&1
NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy" "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy.old" 
taskkill /f /im StartMenuExperienceHost.exe >nul 2>&1
NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy.old" 
taskkill /f /im SearchApp.exe >nul 2>&1 
NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy" "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy.old" 
taskkill /f /im TextInputHost.exe >nul 2>&1
NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy" "C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy.old" 
NSudo.exe -U:T -P:E cmd.exe /c reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Settings\Network" /v ReplaceVan /t REG_DWORD /d 2 /f 
NSudo.exe -U:T -P:E cmd.exe /c reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v EnableMtcUvc /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseWin32TrayClockExperience /t REG_DWORD /d 1 /f >nul 2>&1
taskkill /f /im ShellHost.exe >nul 2>&1
NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\System32\ShellHost.exe" "C:\Windows\System32\ShellHost.exe.old"

echo Desactivation de la GUI du Winlogon...
REM NSudo.exe -U:T -P:E cmd.exe /c move "C:\Windows\System32\Windows.UI.Logon.dll" "C:\Windows\System32\Windows.UI.Logon.dll.old"

echo Deleting Customer Experience Improvement Program...
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f >nul 2>&1

echo Desactivation de .NET Optimization Service (NGEN)...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\NGEN" /v "C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\NGEN" /v "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorsvw.exe" /t REG_DWORD /d 0 /f >nul 2>&1

echo Desactivation de NVMe Perf Throttling...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Classpnp" /v NVMeDisablePerfThrottling /t REG_DWORD /d 1 /f >nul 2>&1

echo Desactivation de FTH (Fault Tolerant Heap)...
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1

echo Supression de Galerie du nav panel de l'explorateur de fichier...
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\DefUser\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f >nul 2>&1
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /f >nul 2>&1

echo Supression de Accueil du nav panel de l'explorateur de fichier...
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f >nul 2>&1

echo Desactivation de SysMain... 
sc config "SysMain" start=disabled >nul 2>&1
sc stop SysMain >nul 2>&1

echo Desactivation de DiagTrack... 
sc config "DiagTrack" start=disabled >nul 2>&1
sc stop DiagTrack >nul 2>&1

echo Desactivation de FontCache... 
sc config "FontCache" start=disabled >nul 2>&1
sc stop FontCache >nul 2>&1

echo Suppression de NDU (Network Monitoring Services)
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /f >nul 2>&1

echo Desactivation de Microsoft Edge Update...
sc config "edgeupdate" start=disabled >nul 2>&1
sc stop edgeupdate >nul 2>&1
sc config "edgeupdatem" start=disabled >nul 2>&1
sc stop edgeupdatem >nul 2>&1

echo Application de SvcHostSplit pour reduire le nombre de SvcHost...
for /f "tokens=*" %%p in ('powershell -NoProfile -Command "& {(Get-CimInstance -ClassName Win32_OperatingSystem).TotalVisibleMemorySize}"') do (
    set m=%%p
    goto :done
)
:done
set "HEX=%m%"

set /A DEC=0x%HEX%

reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d "%DEC%" /f >nul 2>&1	

echo Changement des priorite CPU du Scheduler...
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ForegroundBoost" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadBoostType" /t REG_DWORD /d "2" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadSchedulingModel" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "AdjustDpcThreshold" /t REG_DWORD /d "800" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "DeepIoCoalescingEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IdealDpcRate" /t REG_DWORD /d "800" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "SchedulerAssistThreadFlagOverride" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v "LowLatencyMode" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "EnableGroupAwareScheduling" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "EnablePriorityBoost" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ThreadPrioritization" /t REG_DWORD /d 255 /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "RealTimePriorityBoost" /t REG_DWORD /d 1 /f >nul 2>&1

echo Desactivation de Windows Search...
sc config "WSearch" start=disabled >nul 2>&1
sc stop "WSearch" >nul 2>&1

echo Set Print Spooler to Manual...
sc config "Spooler" start=demand >nul 2>&1
sc stop "Spooler" >nul 2>&1

echo Applying SystemProfile MMCSS Tweaks.
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d 1 /f >nul 2>&1

echo Activation de Verbose...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v verbosestatus /t REG_DWORD /d 1 /f >nul 2>&1

echo Executive Tweak
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v AdditionalCriticalWorkerThreads /t REG_DWORD /d "%NUMBER_OF_PROCESSORS%" /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v AdditionalDelayedWorkerThreads /t REG_DWORD /d "%NUMBER_OF_PROCESSORS%" /f >nul 2>&1

echo Application de WLAN Tweaks...
reg add "HKLM\SOFTWARE\Microsoft\Wlansvc" /v L2NAWLANMode /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Wlansvc" /v AllowAPMode /t REG_BINARY /d 01000000 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Wlansvc" /v DisableBackgroundScanOptimization /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Wlansvc" /v ShowDeniedNetworks /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Wlansvc" /v AllowVirtualStationExtensibility /t REG_DWORD /d 0 /f >nul 2>&1

echo SerializeTimerExpiration Tweaks
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" /v SerializeTimerExpiration /t REG_DWORD /d 1 /f >nul 2>&1

echo Interrupt Steering Tweaks
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringMode" /t REG_DWORD /d 1 /f >nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringTargetProc" /t REG_DWORD /d 1 /f >nul 2>&1

echo Application de Disk Tweaks...
fsutil behavior set disableLastAccess 1 >NUL 2>nul
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>nul
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>nul
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f >NUL 2>nul
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f >NUL 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "QueueDepth" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceFlush" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ImmediateData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "IoQueueDepth" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "QueueDepth" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxReadSplit" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NvmeMaxWriteSplit" /t REG_DWORD /d "4" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceFlush" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ImmediateData" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxSegmentsPerCommand" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingCmds" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ForceEagerWrites" /t REG_DWORD /d "1" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxQueuedCommands" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "MaxOutstandingIORequests" /t REG_DWORD /d "256" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "NumberOfRequests" /t REG_DWORD /d "1500" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoSubmissionQueueCount" /t REG_DWORD /d "3" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "IoQueueDepth" /t REG_DWORD /d "64" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "HostMemoryBufferBytes" /t REG_DWORD /d "1500" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\StorNVMe\Parameters\Device" /v "ArbitrationBurst" /t REG_DWORD /d "256" /f >nul 2>&1
fsutil behavior set memoryusage 2 >NUL 2>nul
fsutil behavior set mftzone 2 >NUL 2>nul
fsutil behavior set disabledeletenotify 0 >NUL 2>nul
fsutil behavior set encryptpagingfile 0 >NUL 2>nul
fsutil behavior set disable8dot3 1 >NUL 2>nul
call :ControlSet "Control\FileSystem" "NtfsDisable8dot3NameCreation" "1"

fsutil behavior set disablecompression 1 >nul

wmic logicaldisk where "DriveType='3' and DeviceID='%systemdrive%'" get DeviceID 2>&1 | find "%systemdrive%" >nul && set "storageType=SSD" || set "storageType=HDD"

if "%storageType%" equ "SSD" (
    fsutil behavior set disableLastAccess 0
    call :ControlSet "Control\FileSystem" "NtfsDisableLastAccessUpdate" "2147483648"
) >nul

if "%storageType%" equ "HDD" (
    fsutil behavior set disableLastAccess 1
    call :ControlSet "Control\FileSystem" "NtfsDisableLastAccessUpdate" "2147483649"
) >nul

goto :EOF

:ControlSet
rem Set registry key values
rem Parameters: %1 - registry path, %2 - key name, %3 - key value
reg add "HKLM\SYSTEM\CurrentControlSet\%1" /v %2 /t REG_DWORD /d %3 /f 


echo Desactivation de Hibernation...
powercfg -h off >nul 2>&1

echo Application de Boot Tweaks... (Speed up the Winlogon)
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f >nul 2>&1
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_SZ /d "0" /f >nul 2>&1
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "RunStartupScriptSync" /t REG_DWORD /d "0" /f >nul 2>&1
bcdedit /set bootmenupolicy legacy >nul 2>&1
Reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1
reg add "HKLM\DefUser\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f >nul 2>&1

echo Application de Shutdown Tweaks... (Speed up the Shutdown)
Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKLM\DefUser\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
Reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
reg add "HKLM\DefUser\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f >nul 2>&1
Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1
reg add "HKLM\DefUser\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f >nul 2>&1

echo Activation de Ultimate Performance Plan... 
powercfg /duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg /SETACTIVE 99999999-9999-9999-9999-999999999999 >nul 2>&1

echo Desactivation de MemoryCompression... (Reduce CPU Usage)
PowerShell -Command "Disable-MMAgent -MemoryCompression" >nul 2>&1
PowerShell -Command "Disable-MMAgent -PageCombining" >nul 2>&1

echo Desactivation de ReservedStorage WinSxS...
dism /Online /Set-ReservedStorageState /State:Disabled >nul 2>&1

echo Nettoyage de WinSxS...
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase >nul 2>&1

echo Supression du dossier temporaire C:\Perflogs...
rmdir /q /s "C:\Perflogs" >nul 2>&1

echo Remove %APPDATA%\Edge Folder...
rmdir /q /s "%LOCALAPPDATA%\Microsoft\Edge\" >nul 2>&1

echo Supression des fichiers temporaires...
del /q /f /s %TEMP%\* >nul 2>&1
del /q /f /s C:\Windows\Temp\* >nul 2>&1
del /q /f /s C:\Users\%USERNAME%\AppData\Local\Temp\* >nul 2>&1

echo Supression des Logs...
del /f /q C:\Windows\System32\winevt\Logs\* >nul 2>&1

REM Compacting Windows... (Optional use more CPU)
REM compact /compactos:always >nul 2>&1

echo Application des Tweaks pour skip OOBE (Pour utiliser le script depuis OOBE)...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v DisableVoice /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v HideEULAPage /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v HideOEMRegistrationScreen /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v HideOnlineAccountScreens /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v HideWirelessSetupInOOBE /t REG_DWORD /d 1 /f >nul 2>&1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v ProtectYourPC /t REG_DWORD /d 3 /f >nul 2>&1
REM reg add HKEY_LOCAL_MACHINE\SYSTEM\Setup /v OOBEInProgress /t REG_DWORD /d 0 /f >nul 2>&1
REM reg add HKEY_LOCAL_MACHINE\SYSTEM\Setup /v OOBEInProgressDriverUpdatesPostponed /t REG_DWORD /d 0 /f >nul 2>&1
REM reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v LaunchUserOOBE /f >nul 2>&1
REM reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v DefaultAccountAction /f >nul 2>&1
REM reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v RecoveryOOBEEnabled /f >nul 2>&1
REM reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v DefaultAccountSAMName /f >nul 2>&1
REM reg delete HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE /v DefaultAccountSID /f >nul 2>&1
REM net user /del defaultuser0 >nul 2>&1
REM net user Administrateur /active:yes

echo Installation de WinMemoryCleaner pour clear /ModifiedPageList /ProcessesWorkingSet /StandbyList /SystemWorkingSet ...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/IgorMundstein/WinMemoryCleaner/releases/download/2.8/WinMemoryCleaner.exe' -OutFile '%SYSTEMDRIVE%\WinMemoryCleaner.exe'" >nul 2>&1
C:\WinMemoryCleaner.exe /ModifiedPageList /ProcessesWorkingSet /StandbyList /SystemWorkingSet >nul 2>&1
copy /y startup.vbs "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\startup.vbs" >nul 2>&1
mkdir "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" >nul 2>&1
copy /y startup.vbs "C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\startup.vbs" >nul 2>&1
copy /y startup.vbs "\Microsoft\Windows\Start Menu\Programs\Startup\startup.vbs" >nul 2>&1
copy /y startup.bat "C:\Startup.bat" >nul 2>&1


echo Decharger la ruche...
reg unload "HKLM\DefUser" >nul 2>&1

echo Redemarrer le PC avec shutdown /t 0 /r
pause
shutdown /t 0 /r




