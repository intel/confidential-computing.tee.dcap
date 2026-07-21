# Intel®️ TEE Quote Verification FFI Bindings

This is the raw FFI bindings of Intel®️ TEE Quote Verification Library.

This crate is for **Linux only**.

## Prerequisite
- Please install **Clang**, which is required by [Rust bindgen](https://rust-lang.github.io/rust-bindgen/requirements.html).

- Please install the following **SGX DCAP** prerequisite:
    - Intel®️ SGX DCAP Driver
    - Intel®️ SGX SDK
    - Intel®️ SGX DCAP Packages
    - Intel®️ SGX DCAP PCCS (Provisioning Certificate Caching Service)

- Please refer to [SGX DCAP Linux installation guide](https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf) to install above dependencies.
> Please make sure that DCAP quote verification developer package is installed, e.g. `libsgx-dcap-quote-verify-dev` on Ubuntu and Debian.

## Compatibility

Crate versioning is independent of the DCAP release version.
Use the table below to pick the right crate for your installed native library.

| `intel-tee-quote-verification-sys` | DCAP release |
|---|---|
| 0.3.x | 1.27 |
| 0.2.1 | 1.17 – 1.26 |
| 0.2.0 | 1.16 |
| 0.1.x | 1.14 – 1.15 |