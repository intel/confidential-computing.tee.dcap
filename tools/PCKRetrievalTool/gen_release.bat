@REM
@REM Copyright(c) 2011-2026 Intel Corporation
@REM
@REM SPDX-License-Identifier: BSD-3-Clause
@REM

@echo off 

set svn_ver=%1%
set rel_dir_name=PCKIDRetrievalTool_v1.27.101.1
set TOOLSFOLDER=.\..\..\..\installer_tools\Tools\standalone_build_se\sign
set SIGNTOOL="%TOOLSFOLDER%\SignFile.exe"
set flag=0

echo "Please copy sgx_urts.dll, sgx_launch.dll and sgx_enclave_common.dll to current directory!"

del /Q %rel_dir_name%\*
rd %rel_dir_name% 

mkdir %rel_dir_name%
echo:
echo ========= copy the binary Files  ===============
CALL :COPY_FILE x64\release\PCKIDRetrievalTool.exe %rel_dir_name%
CALL :COPY_FILE ..\..\..\PSW_installer\InstallBinaries\x64\onecore\sgx_urts.dll %rel_dir_name%
CALL :COPY_FILE ..\..\..\PSW_installer\InstallBinaries\x64\onecore\sgx_launch.dll %rel_dir_name%
CALL :COPY_FILE ..\..\..\PSW_installer\InstallBinaries\x64\onecore\sgx_enclave_common.dll %rel_dir_name%
CALL :COPY_FILE ..\SGXPlatformRegistration\x64\release\mp_uefi.dll %rel_dir_name%
CALL :COPY_FILE ..\..\QuoteGeneration\psw\ae\data\prebuilt\win\pce.signed.dll %rel_dir_name%
CALL :COPY_FILE ..\..\QuoteGeneration\psw\ae\data\prebuilt\win\id_enclave.signed.dll %rel_dir_name%
CALL :COPY_FILE network_setting.conf %rel_dir_name%
CALL :COPY_FILE README_standalone.txt %rel_dir_name%\README.txt
CALL :COPY_FILE License.txt %rel_dir_name%



echo:
echo ========= Signing the binary Files  ===============
%SIGNTOOL% -ha SHA256 %rel_dir_name%\PCKIDRetrievalTool.exe
%SIGNTOOL% -ha SHA256 %rel_dir_name%\sgx_urts.dll
%SIGNTOOL% -ha SHA256 %rel_dir_name%\sgx_launch.dll
%SIGNTOOL% -ha SHA256 %rel_dir_name%\sgx_enclave_common.dll
%SIGNTOOL% -ha SHA256 %rel_dir_name%\mp_uefi.dll



IF /I "%flag%" NEQ "0" (
echo "%flag%"
       goto exit
) else (
        powershell Compress-Archive -Path '%rel_dir_name%\*' -DestinationPath '%rel_dir_name%.zip' -Force 
        echo *** SGX PCK Cert ID Retrieal zip package Build Succesful. Bye bye.***  
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



