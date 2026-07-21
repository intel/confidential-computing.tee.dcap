# Changelog

All notable changes to `intel-tee-quote-verification-sys` are documented here.

## [0.3.0] - DCAP 1.27

### Changed
- Updated metadata (description, documentation links, homepage).

### Fixed
- Removed redundant `use bindgen;` import (clippy::single_component_path_imports).
- Suppressed `clippy::missing_safety_doc` for bindgen-generated unsafe helpers.

## [0.2.1] - DCAP 1.17

### Fixed
- Build succeeds when `SGX_SDK` environment variable is unset (headers located
  via default system paths as fallback).
- Bumped `bindgen` dependency to 0.65.

## [0.2.0] - DCAP 1.16

### Added
- Updated FFI bindings to match DCAP 1.16 native library.

## [0.1.0] - DCAP 1.14

### Added
- Initial release: raw FFI bindings for `libsgx_dcap_quoteverify` generated via
  `bindgen` from `sgx_dcap_quoteverify.h`.
- `links = "sgx_dcap_quoteverify"` to enforce single-crate ownership of the
  native library at link time.
