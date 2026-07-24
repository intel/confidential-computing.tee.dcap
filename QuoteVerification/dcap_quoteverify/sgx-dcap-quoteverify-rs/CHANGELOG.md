# Changelog

All notable changes to `intel-tee-quote-verification-rs` are documented here.

## [0.4.0] - DCAP 1.27

### Changed
- **Breaking:** `QuoteCollateral::from` (the blanket `From<sgx_ql_qve_collateral_t>` impl) has been
  replaced with `unsafe fn QuoteCollateral::from_raw(&sgx_ql_qve_collateral_t)`. The previous
  safe impl silently dereferenced caller-controlled raw pointers; callers must now use the unsafe
  constructor and uphold the documented pointer/size/union preconditions.
- **Breaking:** `tee_verify_quote` is now `unsafe fn`. Callers must ensure the
  quote buffer and supplemental data pointers satisfy the documented preconditions.

### Added
- Supplemental-data fields for TDX platform TCB reporting (supplemental data v3
  minor version 5): `tcb_date_current`, `tcb_status_current`, `sa_list_current`.

## [0.3.0] - DCAP 1.19

### Changed
- `tee_qv_get_collateral` now returns `Result<QuoteCollateral, quote3_error_t>`
  (owned safe struct) instead of `Result<Vec<u8>, quote3_error_t>` (raw bytes).

## [0.2.2] - DCAP 1.17

### Added
- `QuoteCollateral` struct: safe owned wrapper for `sgx_ql_qve_collateral_t`
  collateral data with named fields for all certificate chains, CRLs, and TCB
  info. `tee_qv_get_collateral` now returns this struct.

## [0.2.1] - DCAP 1.16

### Changed
- `tdx_ql_qve_collateral_t` renamed to `tdx_ql_qv_collateral_t` following the
  upstream DCAP 1.16 native library rename.

### Notes
- First version published to crates.io; 0.2.0 was never published.

## [0.2.0] - DCAP 1.16 (unpublished)

### Added
- `tee_verify_quote`: unified TEE (SGX + TDX) quote verification.
- `tee_qv_get_collateral`: retrieve quote verification collateral.
- `tee_get_supplemental_data_version_and_size`: query supplemental data size.

### Changed
- `sgx_qv_get_quote_supplemental_data_size` and
  `tdx_qv_get_quote_supplemental_data_size` now return `Result<u32, quote3_error_t>`
  instead of taking an `&mut u32` out-parameter.
- `sgx_qv_set_path` now takes `path: &str` instead of `CString`.

## [0.1.0] - DCAP 1.14

### Added
- Initial release: safe Rust wrapper for `libsgx_dcap_quoteverify`.
- `sgx_qv_verify_quote`, `tdx_qv_verify_quote`: SGX and TDX quote verification.
- `sgx_qv_set_enclave_load_policy`, `sgx_qv_set_path`.
