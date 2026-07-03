Intel(R) Software Guard Extensions Data Center Attestation Primitives (Intel(R) SGX DCAP) Rust TDQuote Generation SampleCode
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
* Intel(R) SGX SDK

*Note that you need to install **libtdx-attest-dev** for this package.*

Build and run *RustTDQuoteGenerationSample* to generate a TD quote

```
$ cargo build
$ ./target/debug/app
```

You can also combine building and running with a single Cargo command:
```
$ cargo run
```
