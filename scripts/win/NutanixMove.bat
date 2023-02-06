REM Copyright (c) 2018 Nutanix Inc. All rights reserved.
REM Version: 4.7.0

@echo off
set TMPDIR=%SYSTEMDRIVE%\Nutanix\Temp
set SCRIPTSDIR=%SYSTEMDRIVE%\Nutanix\Move\download\scripts
set DOWNLOADDIR=%SYSTEMDRIVE%\Nutanix\Move\download
set UNINSTALLDIR=%SYSTEMDRIVE%\Nutanix\Uninstall\scripts
set SCHEDSCRIPT=%TMPDIR%\NutanixMove.bat
set LOGDIR=%SYSTEMDRIVE%\Nutanix\log
set CONFIGUREONSTARTCONFIG=%TMPDIR%\TaskNutanixMoveOnStartConfig.xml
set RESULT_FILE=%TMPDIR%\NutanixMoveResult.out
set SRCUUID_FILE=%TMPDIR%\source_uuid.txt
set LOG=%TMPDIR%\%~n0-log.txt
set ARG_0=%~f0

set rebootVM=false
set RETRY_DUMP=%TMPDIR%\retry-dump.txt
set RETRIES=5
set COUNTER=0
if not exist %TMPDIR% mkdir %TMPDIR%
if not exist %DOWNLOADDIR% mkdir %DOWNLOADDIR%
if not exist %SCRIPTSDIR% mkdir %SCRIPTSDIR%
if not exist %UNINSTALLDIR% mkdir %UNINSTALLDIR%
if not exist %LOGDIR% mkdir %LOGDIR%
set RETAIN_IP_SCRIPT=""
set WMIUTIL=""
set CONFIGURE_TEMP_DISK_SCRIPT=""
set UNINSTALL_VMWARE_TOOLS_SCRIPT=""
set CLEANUP_SCRIPT=""
set CONFIGURE_TEMP_DISK_SCRIPT_FINAL_PATH=%SCRIPTSDIR%\TempDiskConfiguration.ps1
set RETAIN_IP_SCRIPT_FINAL_PATH=%SCRIPTSDIR%\RetainIP.ps1
set WMIUTIL_FINAL_PATH=%DOWNLOADDIR%\wmi-net-util.exe
set UNINSTALL_VMWARE_TOOLS_SCRIPT_FINAL_PATH=%SCRIPTSDIR%\UninstallVMwareTools.ps1
set CLEANUP_SCRIPT_FINAL_PATH=%UNINSTALLDIR%\cleanup_installation.ps1
set EXIST_FLAG=false
:loop
IF NOT "%1"=="" (
    IF "%1"=="--xml" (
        if exist "%2" (
            set XML_PATH=%2
        ) else (
            echo Invalid XML path
            exit /b 1
        )
        SHIFT
    ) ELSE IF "%1"=="--retain-ip" (
        if exist "%2" if exist "%3" (
            set RETAIN_IP_SCRIPT=%~f2
            set WMIUTIL=%~f3
        ) else (
            echo Invalid RETAINIP script/ WMIUTIL path
            exit /b 1
        )
        SHIFT
        SHIFT
    ) ELSE IF "%1"=="--configure-temp-disk" (
        if exist "%2" (
            set CONFIGURE_TEMP_DISK_SCRIPT=%~f2
        ) else (
            echo Invalid CONFIGURE_TEMP_DISK script path
            exit /b 1
        )
        SHIFT
    ) ELSE IF "%1"=="--uninstall-vmware-tools" (
        if exist "%2" (
            set UNINSTALL_VMWARE_TOOLS_SCRIPT=%~f2
        ) else (
            echo Invalid UNINSTALL_VMWARE_TOOLS script path
            exit /b 1
        )
        SHIFT
    ) ELSE IF "%1"=="--cleanup" (
        if exist "%2" (
            set CLEANUP_SCRIPT=%~f2
        ) else (
            echo Invalid CLEANUP script path
            exit /b 1
        )
        SHIFT
    ) ELSE IF "%1"=="--reboot" (
        rebootVM=true
    )
    SHIFT
    GOTO :loop
)
Setlocal EnableDelayedExpansion
call :LogIt >> %LOG%
exit /b %errorlevel%

:LogIt
    @echo on
    echo %date% %time%
    echo Starting %~dpnx0

    wmic computersystem get manufacturer | findstr Manufacturer > nul
        if %errorlevel% NEQ 0 (
            echo wmic/findstr command failed
            exit /b %errorlevel%
        )

    if exist %SRCUUID_FILE% (
        REM Get the second line of the wmic command which is the uuid.
        for /f "skip=1delims= " %%t in ('wmic csproduct get uuid') do set "vmuuid=%%t"& goto printuuid
        :printuuid
            echo Device UUID is : %vmuuid%

        REM Read src uuid from file
        set /p srcuuid=< %SRCUUID_FILE%
        REM remove trailing spaces - if any.
        set "srcuuid=%srcuuid: =%"

        REM source UUID and VM UUID are equal, hence this is source device
        if "%srcuuid%" == "%vmuuid%" (
            goto do_source
        )else (
            goto do_target
        )
    ) else (
        goto do_source
    )
    @echo off
    goto :eof

    :do_source
        schtasks /query /tn TaskNutanixMove 2>NUL
        if %errorlevel% NEQ 1 (
            if exist %SCHEDSCRIPT% if exist %CONFIGUREONSTARTCONFIG% (
                schtasks /query /tn TaskNutanixMoveOnStart 2>NUL
                if %errorlevel% NEQ 1 (
                    echo TaskNutanixMove already scheduled
                    echo success > %RESULT_FILE%
                    exit /b
                )
            )
            echo Deleting the old task TaskNutanixMove
            schtasks /delete /tn TaskNutanixMove /F
        )
        CALL :CopyAndRunFileSource %CONFIGURE_TEMP_DISK_SCRIPT%, %SCRIPTSDIR%, %CONFIGURE_TEMP_DISK_SCRIPT_FINAL_PATH%, source
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %UNINSTALL_VMWARE_TOOLS_SCRIPT%, %SCRIPTSDIR%, %UNINSTALL_VMWARE_TOOLS_SCRIPT_FINAL_PATH%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %WMIUTIL%, %DOWNLOADDIR%, %WMIUTIL_FINAL_PATH%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %RETAIN_IP_SCRIPT%, %SCRIPTSDIR%, %RETAIN_IP_SCRIPT_FINAL_PATH%, source, %WMIUTIL_FINAL_PATH%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %CLEANUP_SCRIPT%, %UNINSTALLDIR%, %CLEANUP_SCRIPT_FINAL_PATH%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %ARG_0%, %TMPDIR%, %SCHEDSCRIPT%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        CALL :CopyAndRunFileSource %XML_PATH%, %TMPDIR%, %CONFIGUREONSTARTCONFIG%
        if %errorlevel% NEQ 0 ( exit /b %errorlevel% )

        echo Scheduling task TaskNutanixMove
        schtasks /create /tn TaskNutanixMove /sc MINUTE /mo 1 /RL HIGHEST /RU SYSTEM /NP /F /tr "%SCHEDSCRIPT%"
        if %errorlevel% NEQ 0 (
            echo Task creation failed
            echo failed to create schedule > %RESULT_FILE%
            exit /b %errorlevel%
        )
        schtasks /query /tn TaskNutanixMoveOnStart 2>NUL
        if %errorlevel% NEQ 1 (
            schtasks /delete /tn TaskNutanixMoveOnStart /F
        )
        schtasks /create /tn TaskNutanixMoveOnStart /XML %CONFIGUREONSTARTCONFIG%
        if %errorlevel% NEQ 0 (
            echo Task creation failed
            echo Failed to create schedule on start > %RESULT_FILE%
            exit /b %errorlevel%
        )
        echo Completed %~dpnx0
        echo %date% %time%
        echo success > %RESULT_FILE%

        REM write the source UUID to file
        for /f "skip=1delims= " %%t in ('wmic csproduct get uuid') do set "vmuuid=%%t"& goto printtofile
        :printtofile
            echo %vmuuid% >> %SRCUUID_FILE%
        copy /y %LOG% %LOGDIR%
        goto :eof
    :do_target
        set RETRY=false
        CALL :RunFileTarget %CONFIGURE_TEMP_DISK_SCRIPT_FINAL_PATH%, target
        if %errorlevel% EQU 0 if %EXIST_FLAG% == true (
            set rebootVM=true
        )

        CALL :RunFileTarget %UNINSTALL_VMWARE_TOOLS_SCRIPT_FINAL_PATH%, target
        if %errorlevel% EQU 0 if %EXIST_FLAG% == true (
            set rebootVM=true
        )

        CALL :RunFileTarget %RETAIN_IP_SCRIPT_FINAL_PATH%, target, %WMIUTIL_FINAL_PATH%
        if %errorlevel% NEQ 0 (
            set RETRY=true
        )

        if exist %CLEANUP_SCRIPT_FINAL_PATH%% (
            if %RETRY% == false (
                powershell.exe -ExecutionPolicy Bypass -Command "$xtractLiteIP = 'localhost'; $isAWSInstance = $false; $doVirtioCleanup = $false; %CLEANUP_SCRIPT_FINAL_PATH% -xtractLiteIP $xtractLiteIP -isAWSInstance:$isAWSInstance -doVirtioCleanup:$doVirtioCleanup"
                if %errorlevel% NEQ 0 (
                    echo Cleanup script execution failed
                    exit /b %errorlevel%
                )
            )
        )
        if %RETRY% == true (
            set ARGUMENT=""
            REM In case of Retry, if any post migration script requires reboot, VM will be rebooted after successful completion
            if %rebootVM% == true (
                set ARGUMENT="--reboot"
            )
            echo Nutanix Move task failed still proceeding with retries
            if exist "%RETRY_DUMP%" (
                set /P COUNTER=<"%RETRY_DUMP%"
                set /A COUNTER+=1
            ) else (
                echo Deleting the task TaskNutanixMove
                schtasks /delete /tn TaskNutanixMove /F
                schtasks /delete /tn TaskNutanixMoveOnStart /F
                echo scheduling another TaskNutanixMove task in AHV so that during failure it gets to execute wmi utility again.
                schtasks /create /tn TaskNutanixMove /sc MINUTE /mo 1 /RL HIGHEST /RU SYSTEM /NP /F /tr "%SCHEDSCRIPT% %ARGUMENT%"
                if !errorlevel! NEQ 0 (
                echo Task creation failed
                exit /b !errorlevel!
                )
            )
            echo !COUNTER! > "%RETRY_DUMP%"
            if !COUNTER! GEQ %RETRIES% (
                echo %RETRIES% retries exhausted. Deleting TaskNutanixMove
                schtasks /delete /tn TaskNutanixMove /F
            )
            echo Completed %~dpnx0
            echo %date% %time%
            goto :eof
        )
        schtasks /query /tn TaskNutanixMove 2>NUL
        if %errorlevel% NEQ 1 (
            echo Deleting the task TaskNutanixMove
            schtasks /delete /tn TaskNutanixMove /F
            if %errorlevel% NEQ 0 (
                echo Task deletion failed
                exit /b %errorlevel%
            )
        )
        schtasks /query /tn TaskNutanixMoveOnStart 2>NUL
        if %errorlevel% NEQ 1 (
            echo Deleting the task TaskNutanixMoveOnStart
            schtasks /delete /tn TaskNutanixMoveOnStart /F
            if %errorlevel% NEQ 0 (
                echo Task deletion failed
                exit /b %errorlevel%
            )
        )

        echo Completed %~dpnx0
        echo %date% %time%
        copy /y %LOG% %LOGDIR%
        if %rebootVM% == true (
            echo Rebooting system
            shutdown /r /f /t 00
        )
        exit /b 0
:CopyAndRunFileSource
    set ARG=%1
    set ARG_2=%2
    set ARG_3=%3
    set ARG_4="%4"
    set ARG_5="%5"
    REM Copy File if argument specified in batch file run and destination file doesn't exist
    if NOT !ARG!=="" if NOT exist !ARG_3! (
        copy /y !ARG! !ARG_2!
        if !errorlevel! NEQ 0 (
            echo Copy failed
            echo failed to copy file %~1 > %RESULT_FILE%
            exit /b !errorlevel!
        )
    )
    REM Run file if any argument specified in call
    if exist !ARG_3! if NOT !ARG_4!=="" (
        powershell.exe -ExecutionPolicy Bypass !ARG_3! !ARG_4! !ARG_5!
        if !errorlevel! NEQ 0 (
            echo Execute !ARG_3! failed
            echo failed to execute file !ARG_3! > %RESULT_FILE%
            exit /b !errorlevel!
        )
    )
    exit /b 0

:RunFileTarget
    set EXIST_FLAG=false
    set ARG=%1
    set ARG_2="%2"
    set ARG_3="%3"
    REM Run if file exists
    if exist !ARG! (
        set EXIST_FLAG=true
        powershell.exe -ExecutionPolicy Bypass !ARG! !ARG_2! !ARG_3!
        if !errorlevel! EQU 0 (
            del !ARG!
        )
        exit /b !errorlevel!
    )
    exit /b 0
