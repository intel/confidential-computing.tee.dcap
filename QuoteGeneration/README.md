Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Generation Library Quick Start Guide
================================================

For Windows* OS
-----------------
## Prerequisites
- Ensure that you have the following required operating systems:
   * Windows* Server 2019 (Long-Term Servicing Channel)
   * Windows* Server 2022 (Long-Term Servicing Channel)
   * Windows* Server 2025 (Long-Term Servicing Channel)
- Ensure that you have the following required hardware:
  * 3rd+ Generation Intel(R) Xeon(R) Scalable Processor
  * Intel(R) Xeon(R) D Processors from the 17xx and 27xx series
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- Configure the system with the **SGX hardware enabled** option.
- Ensure that you have installed Microsoft Visual C++ Compiler* version 14.14 or higher provided by Microsoft Visual Studio* 2017 version 15.7
- Ensure that you have installed Windows Driver Kit for Win 10, version 10.0.17763.
- Ensure that you have installed latest Intel(R) SGX SDK Installer which could be downloaded from the [Intel(R) SGX SDK](https://software.intel.com/en-us/sgx-sdk/download)
- Use the script to download prebuilt binaries to prebuilt folder:
```
    download_prebuilt.bat
```

## How to build
- In the top directory, open the Microsoft Visual Studio* solution `SGX_DCAP.sln` and run a build.
- The Intel(R) SGX DCAP NuGet* package generation depends on a standalone tool `nuget.exe`. To build the Intel(R) SGX DCAP NuGet* package:
   1.  Download the standalone tool `nuget.exe` from [nuget.org/downloads](https://nuget.org/downloads) and put it to `installer\win\` folder or add the folder where you placed `nuget.exe` to your PATH environment variable.
   2.  Go to `installer\win\` folder and run the following command from the Command Prompt:
```
    DCAP_Components.bat
```
   The target NuGet* package `DCAP_Components.<version>.nupkg` will be generated in the same folder.
- To build the Intel(R) SGX DCAP INF installers, go to `installer\win\Dcap\` folder and run the following commands from the Visual Studio Command Prompt:
```
    dcap_copy_file.bat
    dcap_generate.bat <version>
```
  The target INF installers `sgx_dcap.inf` and `sgx_dcap_dev.inf` will be generated in the same folder.
**NOTE**:`sgx_dcap_dev.inf` is for Windows* Server 2016 LTSC and `sgx_dcap.inf` is for Windows* Server 2019 LTSC.

## How to install
   Refer to the *"Installation Instructions"* section in the [Intel(R) Software Guard Extensions: Data Center Attestation Primitives Installation Guide For Windows* OS](https://download.01.org/intel-sgx/sgx-dcap/1.25/windows/docs/Intel_SGX_DCAP_Windows_SW_Installation_Guide.pdf) to install the right packages on your platform.


For Linux* OS
-----------------
## Prerequisites
- Ensure that you have the following required operating systems:
  * Ubuntu\* Server (64-bit): 22.04, 24.04, 26.04 LTS
  * Red Hat Enterprise Linux\* Server (64-bit): 9.6, 9.8, 10.0, 10.2
  * CentOS\* Stream (64-bit): 9, 10
  * SUSE Linux Enterprise Server\* (64-bit): 15 SP7, 16
  * Anolis\* OS (64-bit): 8.10
  * Azure\* Linux (64-bit): 3.0
  * Debian\* (64-bit): 10, 12, 13
- Ensure that you have the following required hardware:
  * 3rd+ Generation Intel(R) Xeon(R) Scalable Processor
  * Intel(R) Xeon(R) D Processors from the 17xx and 27xx series
  * 8th Generation Intel(R) Core(TM) Processor or newer with **Flexible Launch Control** support*
  * Intel(R) Atom(TM) Processor with **Flexible Launch Control** support*
- Configure the system with the **SGX hardware enabled** option.
- Use the following command(s) to install the required tools to build the Intel(R) SGX software:
  * On Ubuntu 22.04, 24.04, and 26.04
  ```
    $ sudo apt-get install build-essential wget python-is-python3 debhelper zip libcurl4-openssl-dev pkgconf libboost-dev libboost-system-dev libboost-thread-dev protobuf-c-compiler libprotobuf-c-dev protobuf-compiler
  ```
  * On Red Hat Enterprise Linux 9 and 10
  ```
    $ sudo yum groupinstall 'Development Tools'
    $ sudo yum install wget python3 python3-pip rpm-build zip pkgconf boost-devel protobuf-lite-devel protobuf-c-compiler protobuf-c-devel
  ```
  * On CentOS Stream 9 and 10
  ```
    $ sudo dnf group install 'Development Tools'
    $ sudo dnf install wget python3 python3-pip rpm-build zip pkgconf boost-devel protobuf-lite-devel protobuf-c-compiler protobuf-c-devel
  ```
- Install latest prebuilt Intel(R) SGX SDK Installer from [01.org](https://01.org/intel-software-guard-extensions/downloads)
```
  $ ./sgx_linux_x64_sdk_${version}.bin
```
  In case you want to build Intel(R) SGX Installer, follow the instructions to build a compatible SDK and PSW on master branch of GitHub [Intel SGX for Linux*](https://github.com/intel/linux-sgx).
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)
```
  $ ./download_prebuilt.sh
```

## Build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library Package
- To set the environment variables, enter the following command:
```
  $ source ${SGX_PACKAGES_PATH}/sgxsdk/environment
```
- To build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library, enter the following command:
```
   $ make
```
- To clean the files generated by previous `make` command, enter the following command:
```
  $ make clean
```
- To rebuild the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library, enter the following command:
```
  $ make rebuild
```
- To build debug libraries, enter the following command:
```
  $ make DEBUG=1
```
- To build the Intel(R) SGX DCAP Quote Generation Library and the Intel(R) SGX Default Quote Provider Library installers, enter the following command:
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ make deb_pkg
  ```
  You can find the generated installers located under `installer/linux/deb/`.
  **Note**: On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04, the above command also generates another debug symbol package with extension name of `.ddeb` for debug purpose.
  **Note**: The above command builds the installers with default configuration firstly and then generates the target installers. To build the installers without optimization and with full debug information kept in the libraries, enter the following command:
  ```
  $ make deb_pkg DEBUG=1
  ```
  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ make rpm_pkg
  ```
  You can find the generated installers located under `installer/linux/rpm/`.
  **Note**: The above command builds the installers with default configuration firstly and then generates the target installers. To build the installers without optimization and with full debug information kept in the libraries, enter the following command:
  ```
    $ make rpm_pkg DEBUG=1
  ```

## Install the Intel(R) SGX DCAP Quote Generation Library Package
- Install prebuilt Intel(R) SGX common loader and other prerequisites from [01.org](https://01.org/intel-software-guard-extensions/downloads)
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ sudo dpkg -i --force-overwrite libsgx-ae-pce_*.deb libsgx-ae-qe3_*.deb libsgx-ae-id-enclave_*.deb libsgx-ae-qve_*.deb libsgx-enclave-common_*.deb libsgx-urts_*.deb
  ```
  **NOTE**: Sometimes we will split old package into smaller ones or move files between different packages. In such cases, you need to add `--force-overwrite` to overwrite existing files. If you're doing a fresh install, you can omit this option.

  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ sudo rpm -ivh libsgx-ae-pce*.rpm libsgx-ae-qe3*.rpm libsgx-ae-id-enclave*.rpm libsgx-ae-qve*.rpm libsgx-enclave-common*.rpm libsgx-urts*.rpm
  ```
  **NOTE**: If you're not doing a fresh install, please replace option `-i` to `-U` to avoid some conflict errors.

- For production systems, package should be installed by the following command:
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ sudo dpkg -i libsgx-dcap-ql_*.deb
  ```
  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ sudo rpm -ivh libsgx-dcap-ql*.rpm
  ```

- For development systems, another two packages should be installed by the following commands:
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ sudo dpkg -i libsgx-dcap-ql-dev_*.deb
    $ sudo dpkg -i libsgx-dcap-ql-dbgsym_*.deb
  ```
  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ sudo rpm -ivh libsgx-dcap-ql-devel*.rpm
    $ sudo rpm -ivh libsgx-dcap-ql-debuginfo*.rpm
  ```

## Install the Intel(R) SGX Default Quote Provider Library Package
- For production systems, package should be installed by the following commands:
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ sudo dpkg -i libsgx-dcap-default-qpl_*.deb
    $ sudo dpkg -i sgx-dcap-pccs_*.deb
  ```
  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ sudo rpm -ivh libsgx-dcap-default-qpl*.rpm
    $ sudo rpm -ivh sgx-dcap-pccs*.rpm
  ```
  Please refer to /opt/intel/sgx-dcap-pccs/README.md for more details about the installation of sgx-dcap-pccs.
- For development systems, another two packages should be installed by the following commands:
  * On Ubuntu 22.04, Ubuntu 24.04, and Ubuntu 26.04:
  ```
    $ sudo dpkg -i libsgx-dcap-default-qpl-dev*.deb libsgx-headers*.deb
    $ sudo dpkg -i libsgx-dcap-default-qpl-dbgsym*.deb
  ```
  * On Red Hat Enterprise Linux 9 and 10, CentOS Stream 9 and 10:
  ```
    $ sudo rpm -ivh libsgx-dcap-default-qpl-devel*.rpm libsgx-headers*.rpm
    $ sudo rpm -ivh libsgx-dcap-default-qpl-debuginfo*.rpm
  ```
## TDX Attestation Support
- From version 1.14, TDX attestation feature is added into DCAP. Corresponding packages will be built along with the DCAP Quote Generation Library and DCAP Quote Verification Library. Currently, TDX attestation support has been verified on Red Hat Enterprise Linux 8.5 and CentOS Stream 8 only.
