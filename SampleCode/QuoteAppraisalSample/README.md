Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Quote Appraisal SampleCode
================================================

## Linux
See [Supported Linux operating systems](../README.md#supported-linux-operating-systems).

Purpose of Quote Appraisal Sample Code
--------------------------------------
The sample code demonstrates two quote appraisal solutions:
* **QVL Appraisal**: A library-based solution for verifying/appraising quotes using the `libsgx_dcap_quoteverify.so` library.
* **QAE Appraisal**: An SGX enclave-based solution for verifying/appraising quotes using the QvE and QAE enclaves.

QVL Appraisal
-------------
Requirements:
* make
* gcc
* g++
* openssl (`openssl-devel` on RPM-based systems, `libssl-dev` on DEB-based systems)
* bash shell

Prerequisite:
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP Quote Verification Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)
* Intel(R) TEE Apraisal Tool
  - install tee-appraisal-tool package on the development machine

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.20.*

1. Generate SGX or TDX quote with certification data 
  * Generate a sample quote for SGX
```
    $ cd SampleCode/QuoteGenerationSample/
    $ make
    $ ./app
```
  * Generate a sample quote for TDX
   - install libtdx-attest package in TD VM
   - make and run /opt/intel/tdx-quote-generation-sample/ in TD VM

2. Customize the appraisal policy
  * SGX Enclave Policy
   - Run the following command using the tool `tee_appraisal_tool` to generate the enclave policy for reference

   ```
      $ tee_appraisal_tool gen_payload -in {path_to_the_enclave}  -out {path_to_the_enclave_policy}
   ```
   - Customize the generated policies based on your requirements.

  * TENANT TD Policy
   - Run the following command using the tool `tee_appraisal_tool` to generate the tenant TD policy for reference

   ```
      $ tee_appraisal_tool gen_payload -in {path_to_the_td_report}  -out {path_to_the_tenant_td_policy}
   ```
   - Customize the generated policies based on your requirements.

  * Platform Policy
   - Sample platform policies are provided in Policies/ folder. Please customize the policy in the sample policies before running the sample.

3. Generate an ECDSA signing key
  * The sample code generates the key automatically. If you want to generate your own ECDSA signing key, run the following command:
   ```
    $ openssl ecparam -name secp384r1 -genkey -out {path_to_the_key}
   ```
  * The sample code uses the key to sign appraisal policies automatically. Here is the command to sign appraisal policy for your reference:
   ```
    $ tee_appraisal_tool sign_policy -in {path_to_appraisal_policy} -key {path_to_the_key} -out {path_to_signed_policy}
   ```
  * ***In production environment, you should use your own policy and policy signing key [Not required for runing this sample]***

4. Build and run the sample code in Debug build
   ```
   <change directory to QVLAppraisal folder>
   $ make SGX_DEBUG=1
   $ ./app
   ```

5. Build and run the sample code in Release build
   ```
   <change directory to QVLAppraisal folder>
   $ make
   $ ./app
   ```

QAE Appraisal
-------------
Requirements:
* make
* gcc
* g++
* openssl (`openssl-devel` on RPM-based systems, `libssl-dev` on DEB-based systems)
* bash shell

Prerequisite:
* Intel(R) SGX SDK Packages
* Intel(R) SGX Platform Software Packages
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP Quote Verification Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)
* Intel(R) TEE Apraisal Tool
  - install tee-appraisal-tool package on the development machine

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/sgx-dcap/#version#/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf" to install above dependencies*<br/>
*Note that you need to change **\#version\#** to actual version number in URL, such as 1.20.*

1. Generate SGX or TDX quote with certification data
  * Generate a sample quote for SGX
```
    $ cd SampleCode/QuoteGenerationSample/
    $ make
    $ ./app
```
  * Generate a sample quote for TDX
   - install libtdx-attest package in TD VM
   - make and run /opt/intel/tdx-quote-generation-sample/ in TD VM

2. Customize the appraisal policy
  * SGX Enclave Policy
   - Run the following command using the tool `tee_appraisal_tool` to generate the enclave policy for reference

   ```
      $ tee_appraisal_tool gen_payload -in {path_to_the_enclave}  -out {path_to_the_enclave_policy}
   ```
   - Customize the generated policies based on your requirements.

  * Platform Policy
   - Sample platform policies are provided in Policies/ folder. Please customize the policy in the sample policies before running the sample.

3. Generate an ECDSA signing key
  * The sample code generates the key automatically. If you want to generate your own ECDSA signing key, run the following command:
   ```
    $ openssl ecparam -name secp384r1 -genkey -out {path_to_the_private_key}
   ```
    And then generate the public key from the ECDSA signing key:
   ```
    $ openssl ec -in {path_to_the_private_key} -pubout -out {path_to_the_public_key}
   ```

  * The sample code uses the key to sign appraisal policies automatically. Here is the command to sign appraisal policy for your reference:
   ```
    $ tee_appraisal_tool sign_policy -in {path_to_appraisal_policy} -key {path_to_the_key} -out {path_to_signed_policy}
   ```
  * ***In production environment, you should use your own policy and policy signing key [Not required for runing this sample]***

4. Customize the user's enclave
   User's enclave is used to work with QvE/QAE for local attestation. Add the following two steps to build an enclave:
  * Include "sgx_dcap_tvl.edl" in enclave EDL File
  * Add "-lsgx_dcap_tvl -lsgx_tcxx" to the Enclave link flags 

5. Build and run the sample code in Debug build
   ```
   <change directory to QAEAppraisal folder>
   $ make SGX_DEBUG=1
   $ ./app
   ```

6. Build and run the sample code in Release build
   ```
   <change directory to QAEAppraisal folder>
   $ make
   $ ./app
   ```

**Note**: Our libdcap_quoteprov.so is not built with Intel(R) Control Flow Enforcement Technology(CET) feature. If the sample is built with CET feature(it can be enabled by the compiler's default setting) and it is running on a CET enabled platform, you may encounter such an error message(or something similar): "Couldn't find the platform library. rebuild shared object with SHSTK support enabled". It means the system glibc enforces that a CET-enabled application can't load a non-CET shared library. You need to rebuild the sample by adding  -fcf-protection=none option explicitly to disable CET.
