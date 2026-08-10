@REM
@REM Copyright(c) 2011-2026 Intel Corporation
@REM
@REM SPDX-License-Identifier: BSD-3-Clause
@REM

@echo off 

set svn_ver=%1%
set rel_dir_name=mpa_manager_v1.27.101.1
set TOOLSFOLDER=.\..\..\..\..\installer_tools\Tools\standalone_build_se\sign
set SIGNTOOL="%TOOLSFOLDER%\SignFile.exe"
set SIGNCERT=%TOOLSFOLDER%\Certificates\intel-ca.crt
set flag=0

echo "Please copy mp_uefi.dll to current directory!"

del /Q %rel_dir_name%\*
rd %rel_dir_name% 

mkdir %rel_dir_name%
echo:
echo ========= copy the binary Files  ===============
CALL :COPY_FILE ..\x64\release\mpa_manage.exe %rel_dir_name%
CALL :COPY_FILE ..\x64\release\mp_uefi.dll %rel_dir_name%
CALL :COPY_FILE ..\License.txt %rel_dir_name%



echo:
echo ========= Signing the binary Files  ===============
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %rel_dir_name%\mpa_manage.exe
%SIGNTOOL% -cafile %SIGNCERT% -ha SHA256 %rel_dir_name%\mp_uefi.dll



IF /I "%flag%" NEQ "0" (
echo "%flag%"
       goto exit
) else (
        powershell Compress-Archive -Path '%rel_dir_name%\*' -DestinationPath '%rel_dir_name%.zip' -Force 
        echo *** SGX MPA_manage zip package Build Succesful. Bye bye.***  
        goto finish
)



:COPY_FILE
echo f | xcopy %1 %2 /Y /F
IF /I "%ERRORLEVEL%" NEQ "0" (
        set /A flag = %ERRORLEVEL%
        goto copy_failure
)
EXIT /B 

:copy_failure
echo ------------------------------------------
echo -        Failed to copy files            -
echo ------------------------------------------
EXIT /B

:exit
echo ------------------------------------------
echo -  Some error happens, please check it.  -
echo ------------------------------------------

:finish


