Rem
Rem Copyright(c) 2011-2026 Intel Corporation
Rem
Rem SPDX-License-Identifier: BSD-3-Clause
Rem

setlocal enabledelayedexpansion

set PFM=%1
set CFG=%2

set top_dir=%~dp0
set sgxssl_dir=%top_dir%\sgxssl

set openssl_out_dir=%sgxssl_dir%\openssl_source
set openssl_ver_name=openssl-3.0.20
set sgxssl_github_archive=https://github.com/intel/intel-sgx-ssl/archive

set sgxssl_ver_name=3.0_Rev5.3
set sgxssl_ver=%sgxssl_ver_name%
set build_script=%sgxssl_dir%\Windows\build_package.cmd

set server_url_path=https://www.openssl.org/source/old/3.0/

set full_openssl_url=%server_url_path%/%openssl_ver_name%.tar.gz
set sgxssl_chksum=a01139042282584c4d3064bbb19c99094898205d8202c7ccc7339326531e59d4
set openssl_chksum=c80a01dfc70ece4dc21168932c37739042d404d46ccc81a5986dd75314ecda6f

if not exist %sgxssl_dir% (
	mkdir %sgxssl_dir%
)

if not exist %build_script% (
	call powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-WebRequest -URI %sgxssl_github_archive%/%sgxssl_ver_name%.zip -OutFile %sgxssl_dir%\%sgxssl_ver_name%.zip"
	call powershell -Command "$sgxsslfilehash = Get-FileHash %sgxssl_dir%\%sgxssl_ver_name%.zip; Write-Output $sgxsslfilehash.Hash | out-file -filepath %sgxssl_dir%\check_sum_sgxssl.txt -encoding ascii"
	findstr /i %sgxssl_chksum% %sgxssl_dir%\check_sum_sgxssl.txt>nul
	if !errorlevel! NEQ 0  (
        echo "File %sgxssl_dir%\%sgxssl_ver_name%.zip checksum failure"
        del /f /q %sgxssl_dir%\%sgxssl_ver_name%.zip
        exit /b 1
	)
	call powershell -Command "Expand-Archive -LiteralPath '%sgxssl_dir%\%sgxssl_ver_name%.zip' -DestinationPath %sgxssl_dir%"
    xcopy /y "%sgxssl_dir%\intel-sgx-ssl-%sgxssl_ver%" %sgxssl_dir% /e
	del /f /q %sgxssl_dir%\%sgxssl_ver_name%.zip
	rmdir /s /q %sgxssl_dir%\intel-sgx-ssl-%sgxssl_ver%
)

if not exist %openssl_out_dir%\%openssl_ver_name%.tar.gz (
	call powershell -Command "Invoke-WebRequest -URI %full_openssl_url% -OutFile %openssl_out_dir%\%openssl_ver_name%.tar.gz"
)
call powershell -Command " $opensslfilehash = Get-FileHash %openssl_out_dir%\%openssl_ver_name%.tar.gz; Write-Output $opensslfilehash.Hash | out-file -filepath %sgxssl_dir%\check_sum_openssl.txt -encoding ascii"
findstr /i %openssl_chksum% %sgxssl_dir%\check_sum_openssl.txt>nul
if !errorlevel! NEQ 0  (
	echo "File %openssl_out_dir%\%openssl_ver_name%.tar.gz checksum failure"
	del /f /q %openssl_out_dir%\%openssl_ver_name%.tar.gz
	exit /b 1
)

if not exist %sgxssl_dir%\Windows\package\lib\%PFM%\%CFG%\libsgx_tsgxssl.lib (
	cd %sgxssl_dir%\Windows\
	cmd /C (echo | call %build_script% %PFM%_%CFG% %openssl_ver_name% no-clean SIM)
	if !errorlevel! NEQ 0  (
		echo "Error calling %build_script% %PFM%_%CFG% %openssl_ver_name% no-clean SIM"
		exit /b 1
	)
    xcopy /E /H /y %sgxssl_dir%\Windows\package %top_dir%\package\

	cd ..\
)

cd %top_dir%
exit /b 0
