Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Generation SampleCode
================================================

## Linux
See [Supported Linux operating systems](../README.md#supported-linux-operating-systems).

## Requirements:
* make
* gcc
* g++
* bash shell
* libubsan (only for DEBUG builds of the app and its DCAP dependencies)
## Prerequisite:
* Linux kernel v5.11 and above
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Development Packages

`libsgx-enclave-common-dev`, `libsgx-dcap-ql-dev` and `libsgx-dcap-default-qpl-dev`. Or `libsgx-enclave-common-devel`, `libsgx-dcap-ql-devel` and `libsgx-dcap-default-qpl-devel`
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)
* If you want to use "out-of-process" quote generation, you need to install `libsgx-quote-ex-dev` or `libsgx-quote-ex-devel` package in Intel(R) SGX PSW Packages

*Please refer to [SGX DCAP Linux installation guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install above dependencies*

## Apps with "in-process" quote
If your app uses Intel(R) SGX AESM service for "out-of-process" quote generation (quote generated in AESM process using Intel(R) signed PCE and QE), then the AESM installer will do the configuration described here and you can ignore this section.

If your app is doing so-called "in-process" quote generation, i.e., it loads provisioning/quoting enclaves by itself including Intel(R) signed PCE, QE, then the app needs to be run with an uid in `sgx_prv` group.

Use below command to add the user running the process to `sgx_prv` group, then run app again:
```
$ sudo usermod -a -G sgx_prv <user name>
```
Note that you need to open another terminal to make above command take effect.

*Note:* Without proper access, the app will fail on loading the provisioning enclaves with error. e.g. `SGX_ERROR_SERVICE_INVALID_PRIVILEGE(0x4004)` from enclave loader.

## Build and run QuoteGenerationSample to generate SGX ECDSA quote
Prepare Enclave test key(two options):
1. Install openssl first, then the project will generate a test key `Enclave_private_sample.pem` automatically when you build the project.
2. Rename your test key(3072-bit RSA private key) to `Enclave_private_sample.pem` and put it under the `Enclave` folder.

Release build:
```
$ make
```
Or Debug build:
```
$ make SGX_DEBUG=1
```
SGX_QPL_LOGGING will be set to 1 by default, enabling error level logging for for QCNL&QPL. SGX_QPL_LOGGING can be set to 2 for info log level, 0 for no QCNL&QPL log.
SGX_TRACE_LOGGING will be set to 0 by default, no SGX log. SGX_TRACE_LOGGING can be set to 1 for SGX error log, 2 for SGX info log, 3 for SGX debug log, 4 for SGX trace log.

Run application in "in-proc" mode:
```
$ ./app
```
Run application in "out-of-proc" mode:
```
$ SGX_AESM_ADDR=1 ./app
```
**Note**: Our libdcap_quoteprov.so is not built with Intel(R) Control Flow Enforcement Technology(CET) feature. If the sample is built with CET feature(it can be enabled by the compiler's default setting) and it is running on a CET enabled platform, you may encounter such an error message(or something similar): "Couldn't find the platform library. rebuild shared object with SHSTK support enabled". It means the system glibc enforces that a CET-enabled application can't load a non-CET shared library. You need to rebuild the sample by adding `-fcf-protection=none` option explicitly to disable CET.

## Windows
See [Supported Windows operating systems](../README.md#supported-windows-operating-systems).

## Requirements:
* Microsoft Visual Studio 2019 or newer.

## Prerequisite:
* Intel(R) SGX DCAP Driver
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to [SGX DCAP Windows installation guide](https://software.intel.com/en-us/sgx/sdk) to install above dependencies*

*Note that you need to sign in IDZ first, then download & extract product "Intel(R) Software Guard Extensions Data Center Attestation Primitives"*
*Note that If you don’t have your own Quote Provider library and would like to use the default Quote Provider library provided by Intel, you need copy dcap_quoteprov.dll and sgx_default_qcnl_wrapper.dll to Windows system directory

## Build and run QuoteGenerationSample to generate an ECDSA quote
1. Open VS solution QuoteGenerationSample.sln, build with `Debug/Release | x64` configuration
If you are using the default Quote Provider library provided by Intel, you can enable logging by setting
The SGX_QPL_LOGGING in `App`->`Configuration Properties` -> `C/C++` -> `Preprocessor` will be set to 1 by default, enabling error level logging for for QCNL&QPL. SGX_QPL_LOGGING can be set to 2 for info log level, 0 for no QCNL&QPL log.
2. Run App.exe
