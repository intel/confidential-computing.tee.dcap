# Intel®️ TEE Quote Verification

This is the Rust wrapper for Intel®️ TEE Quote Verification Library. 

This crate is for **Linux only**.

## Prerequisite
Please refer to the prerequisite of [`intel-tee-quote-verification-sys`](https://crates.io/crates/intel-tee-quote-verification-sys).

## Compatibility

Crate versioning is independent of the DCAP release version.
Use the table below to pick the right crate for your installed native library.

| `intel-tee-quote-verification-rs` | DCAP release |
|---|---|
| 0.4.x | 1.27 |
| 0.3.x | 1.19 – 1.26 |
| 0.2.2 | 1.17 – 1.18 |
| 0.2.1 | 1.16 |
| 0.1.x | 1.14 – 1.15 |

Install the native library from [01.org](https://download.01.org/intel-sgx/latest/linux-latest/)
or your distro's SGX DCAP packages (e.g. `libsgx-dcap-quote-verify-dev` on Ubuntu/Debian).

## Sample Code
A [sample code](https://github.com/intel/confidential-computing.tee.dcap/tree/main/SampleCode/RustQuoteVerificationSample) of how to use this crate to provide quote verification.
