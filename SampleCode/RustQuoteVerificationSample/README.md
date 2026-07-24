Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Rust Quote Verification SampleCode
================================================

## Linux
See [Supported Linux operating systems](../README.md#supported-linux-operating-systems).

## Requirements:
* make
* gcc
* g++
* bash shell
* clang
* Rust and Cargo

## Prerequisite:
* Linux kernel v5.11 and above
* Intel(R) SGX SDK
* Intel(R) SGX DCAP Packages
* Intel(R) SGX DCAP PCCS (Provisioning Certificate Caching Service)

*Please refer to SGX DCAP Linux installation guide "https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf" to install above dependencies*<br/>
*Note that you need to install **libsgx-dcap-quote-verify-dev** for this package.*

1. Generate an ECDSA quote with certification data of type 5 using *QuoteGenerationSample*
```
   $ cd ../QuoteGenerationSample/
   $ make
   $ ./app
```

2. Build and run *RustQuoteVerificationSample* to verify a given quote

   Trusted quote verification is processed inside the Intel(R) QvE. In this sample, we borrowed enclave from [QuoteVerificationSample](../QuoteVerificationSample) to perform quote verification.

   Go to *QuoteVerificationSample* and build *enclave.signed.so*. 
   ```
   $ cd ../QuoteVerificationSample/
   $ make SGX_DEBUG=1
   ```

   Go back to *RustQuoteVerificationSample* and build static library for *Enclave_u.o*.
   ```
   $ cd ../RustQuoteVerificationSample/
   $ ar rs libenclave_untrusted.a ../QuoteVerificationSample/App/Enclave_u.o
   ```

   
   Build the and run with default quote path:
   ```
   $ cargo build
   $ ./target/debug/app
   ```

   Or run with specified quote path:

   ```
   $ ./target/debug/app --quote </path/to/quote.dat [default=../QuoteGenerationSample/quote.dat]>
   ```
   You can also combine building and running with a single Cargo command:
   ```
   $ cargo run
   ```
   and to specify quote path:
   ```
   $ cargo run -- --quote </path/to/quote.dat>
   ```

3. Build and run *RustQuoteVerificationSample* in TD VM:

```
cargo run --features TD_ENV
```
