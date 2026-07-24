/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

//! This is the Intel SGX DCAP Quote Provider Library for Rust.
#![allow(non_camel_case_types)]

pub use qpl_sys::quote3_error_t;
pub use qpl_sys::sgx_cpu_svn_t;
pub use qpl_sys::sgx_isv_svn_t;
pub use qpl_sys::sgx_ql_config_version_t;

use bitflags::bitflags;
use qpl_sys::sgx_ql_config_t;
use qpl_sys::sgx_ql_pck_cert_id_t;
use qpl_sys::sgx_ql_qve_collateral_t;
use std::ffi::CStr;
use std::option::Option;
use std::slice;

pub use qpl_sys::sgx_ql_log_level_t as tee_qpl_log_level;
pub use qpl_sys::sgx_ql_logging_callback_t as tee_qpl_logging_callback;

pub enum tee_qpl_type {
    TEE_QPL_TYPE_SGX,
    TEE_QPL_TYPE_TDX,
}

pub struct tee_qpl_pck_cert_id {
    pub qe3_id: Vec<u8>,
    pub cpu_svn: sgx_cpu_svn_t,
    pub pce_isv_svn: sgx_isv_svn_t,
    pub encrypted_ppid: Option<Vec<u8>>,
    pub crypto_suite: u8,
    pub pce_id: u16,
}

pub struct tee_qpl_config {
    pub version: sgx_ql_config_version_t,
    pub cert_cpu_svn: sgx_cpu_svn_t,
    pub cert_pce_isv_svn: sgx_isv_svn_t,
    pub cert_data: Vec<u8>,
}

pub struct tee_qpl_qve_collateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: Vec<i8>,
    pub root_ca_crl: Vec<i8>,
    pub pck_crl: Vec<i8>,
    pub tcb_info_issuer_chain: Vec<i8>,
    pub tcb_info: Vec<i8>,
    pub qe_identity_issuer_chain: Vec<i8>,
    pub qe_identity: Vec<i8>,
}

pub struct tee_qpl_qve_id {
    pub qve_identity: String,
    pub qve_identity_issuer_chain: String,
}

bitflags! {
    pub struct tee_qpl_cache_type: u32 {
        const TEE_QPL_CACHE_CERTIFICATE = qpl_sys::_sgx_qpl_cache_type_t_SGX_QPL_CACHE_CERTIFICATE;
        const TEE_QPL_CACHE_QV_COLLATERAL = qpl_sys::_sgx_qpl_cache_type_t_SGX_QPL_CACHE_QV_COLLATERAL;
        const TEE_QPL_CACHE_MULTICERTS = qpl_sys::_sgx_qpl_cache_type_t_SGX_QPL_CACHE_MULTICERTS;
        const _ = !0;
    }
}

/// This function retrieves the quote configuration for a given PCK certificate ID.
///
/// # Arguments
///
/// * `pck_cert_id` - A reference to the PCK certificate ID.
///
/// # Returns
///
/// * A `Result` which is:
///     * `Ok(tee_qpl_config)` - The quote configuration.
///     * `Err(quote3_error_t)` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_ql_get_quote_config` and
/// `sgx_ql_free_quote_config` functions from the `qpl_sys` module, which are FFI functions
/// that interact with the SGX SDK. The caller must ensure that the provided PCK certificate ID
/// is valid and that it has been correctly initialized.
pub fn tee_qpl_get_quote_config(
    pck_cert_id: &tee_qpl_pck_cert_id,
) -> Result<tee_qpl_config, quote3_error_t> {
    let mut qe3_id = pck_cert_id.qe3_id.clone();
    let mut cpu_svn = pck_cert_id.cpu_svn;
    let mut isv_svn = pck_cert_id.pce_isv_svn;
    let mut temp_size = 0;
    let mut encrypted_ppid: *mut u8 = std::ptr::null_mut();
    // Clone into a named binding so the Vec (and its backing buffer) stays alive
    // for the entire duration of the FFI call below. Without this, the temporary
    // returned by ppid.clone() would be dropped immediately, leaving a dangling pointer.
    // Only set the pointer when the buffer is non-empty; the C QCNL layer requires
    // p_encrypted_ppid to be null when encrypted_ppid_size is 0.
    let mut ppid_buf: Vec<u8> = Vec::new();
    if let Some(ppid) = pck_cert_id.encrypted_ppid.as_ref() {
        if !ppid.is_empty() {
            ppid_buf = ppid.clone();
            temp_size = ppid_buf.len();
            encrypted_ppid = ppid_buf.as_mut_ptr();
        }
    }
    let cert_id = sgx_ql_pck_cert_id_t {
        p_qe3_id: qe3_id.as_mut_ptr(),
        qe3_id_size: qe3_id.len() as u32,
        p_platform_cpu_svn: &mut cpu_svn,
        p_platform_pce_isv_svn: &mut isv_svn,
        p_encrypted_ppid: encrypted_ppid,
        encrypted_ppid_size: temp_size as u32,
        crypto_suite: pck_cert_id.crypto_suite,
        pce_id: pck_cert_id.pce_id,
    };
    let mut p_config: *mut sgx_ql_config_t = std::ptr::null_mut();
    unsafe {
        let result = qpl_sys::sgx_ql_get_quote_config(&cert_id, &mut p_config);
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                let ql_config = tee_qpl_config {
                    version: p_config.as_ref().unwrap().version,
                    cert_cpu_svn: p_config.as_ref().unwrap().cert_cpu_svn,
                    cert_pce_isv_svn: p_config.as_ref().unwrap().cert_pce_isv_svn,
                    cert_data: slice::from_raw_parts(
                        p_config.as_ref().unwrap().p_cert_data,
                        p_config
                            .as_ref()
                            .unwrap()
                            .cert_data_size
                            .try_into()
                            .unwrap(),
                    )
                    .to_vec(),
                };
                qpl_sys::sgx_ql_free_quote_config(p_config);
                Ok(ql_config)
            }
            _ => Err(result),
        }
    }
}

/// This function retrieves the quote verification collateral for a given TEE type, FMSPC, PCK CA, and optional custom parameter.
///
/// # Arguments
///
/// * `tee_type` - The TEE type.
/// * `fmspc` - A reference to the FMSPC.
/// * `pck_ca` - A string slice representing the PCK CA.
/// * `custom_param` - An optional reference to a vector of bytes representing the custom parameter.
///
/// # Returns
///
/// * A `Result` which is:
///     * `Ok(tee_qpl_qve_collateral)` - The quote verification collateral.
///     * `Err(quote3_error_t)` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_ql_get_quote_verification_collateral_with_params` and
/// `tdx_ql_get_quote_verification_collateral_with_params` functions from the `qpl_sys` module, which are FFI functions
/// that interact with the SGX SDK. The caller must ensure that the provided TEE type, FMSPC, PCK CA, and custom parameter
/// are valid and that they have been correctly initialized.
pub fn tee_qpl_get_quote_verification_collateral(
    tee_type: tee_qpl_type,
    fmspc: &Vec<u8>,
    pck_ca: &str,
    custom_param: Option<&Vec<u8>>,
) -> Result<tee_qpl_qve_collateral, quote3_error_t> {
    let mut p_collateral: *mut sgx_ql_qve_collateral_t = std::ptr::null_mut();
    match std::ffi::CString::new(pck_ca) {
        Ok(pck_ca) => unsafe {
            let result: quote3_error_t;
            let mut raw_custom_param: *const std::ffi::c_void = std::ptr::null();
            let mut raw_custom_param_size: u16 = 0;
            if let Some(p) = custom_param {
                raw_custom_param_size = p.len() as u16;
                raw_custom_param = p.as_ptr() as *const std::ffi::c_void;
            }
            match tee_type {
                tee_qpl_type::TEE_QPL_TYPE_SGX => {
                    result = qpl_sys::sgx_ql_get_quote_verification_collateral_with_params(
                        fmspc.as_ptr() as *const u8,
                        fmspc.len() as u16,
                        pck_ca.as_ptr() as *const i8,
                        raw_custom_param,
                        raw_custom_param_size,
                        &mut p_collateral,
                    );
                }
                tee_qpl_type::TEE_QPL_TYPE_TDX => {
                    result = qpl_sys::tdx_ql_get_quote_verification_collateral_with_params(
                        fmspc.as_ptr() as *const u8,
                        fmspc.len() as u16,
                        pck_ca.as_ptr() as *const i8,
                        raw_custom_param,
                        raw_custom_param_size,
                        &mut p_collateral,
                    );
                }
            }
            match result {
                quote3_error_t::SGX_QL_SUCCESS => {
                    let collateral = tee_qpl_qve_collateral {
                        major_version: p_collateral
                            .as_ref()
                            .unwrap()
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .major_version,
                        minor_version: p_collateral
                            .as_ref()
                            .unwrap()
                            .__bindgen_anon_1
                            .__bindgen_anon_1
                            .minor_version,
                        tee_type: p_collateral.as_ref().unwrap().tee_type,
                        pck_crl_issuer_chain: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().pck_crl_issuer_chain,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .pck_crl_issuer_chain_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        root_ca_crl: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().root_ca_crl,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .root_ca_crl_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        pck_crl: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().pck_crl,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .pck_crl_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        tcb_info_issuer_chain: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().tcb_info_issuer_chain,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .tcb_info_issuer_chain_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        tcb_info: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().tcb_info,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .tcb_info_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        qe_identity_issuer_chain: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().qe_identity_issuer_chain,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .qe_identity_issuer_chain_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                        qe_identity: slice::from_raw_parts(
                            p_collateral.as_ref().unwrap().qe_identity,
                            p_collateral
                                .as_ref()
                                .unwrap()
                                .qe_identity_size
                                .try_into()
                                .unwrap(),
                        )
                        .to_vec(),
                    };
                    qpl_sys::sgx_ql_free_quote_verification_collateral(p_collateral);
                    Ok(collateral)
                }
                _ => Err(result),
            }
        },
        _ => Err(quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER),
    }
}

pub fn tee_qpl_get_qve_identity() -> Result<tee_qpl_qve_id, quote3_error_t> {
    let mut p_qve_identity: *mut i8 = std::ptr::null_mut();
    let mut p_qve_identity_issuer_chain: *mut i8 = std::ptr::null_mut();
    let mut qve_identity_size: u32 = 0;
    let mut qve_identity_issuer_chain_size: u32 = 0;
    unsafe {
        let result = qpl_sys::sgx_ql_get_qve_identity(
            &mut p_qve_identity as *mut *mut i8,
            &mut qve_identity_size as *mut u32,
            &mut p_qve_identity_issuer_chain as *mut *mut i8,
            &mut qve_identity_issuer_chain_size as *mut u32,
        );
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                let qve_identity: String = CStr::from_ptr(p_qve_identity as *const i8)
                    .to_string_lossy()
                    .into_owned();
                let qve_identity_issuer_chain: String =
                    CStr::from_ptr(p_qve_identity_issuer_chain as *const i8)
                        .to_string_lossy()
                        .into_owned();
                qpl_sys::sgx_ql_free_qve_identity(p_qve_identity, p_qve_identity_issuer_chain);
                let qve_id = tee_qpl_qve_id {
                    qve_identity,
                    qve_identity_issuer_chain,
                };
                Ok(qve_id)
            }
            _ => Err(result),
        }
    }
}

/// This function retrieves the QVE identity.
///
/// # Returns
///
/// * A `Result` which is:
///     * `Ok(tee_qpl_qve_id)` - The QVE identity.
///     * `Err(quote3_error_t)` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_ql_get_qve_identity` and
/// `sgx_ql_free_qve_identity` functions from the `qpl_sys` module, which are FFI functions
/// that interact with the SGX SDK. The caller must ensure that the QVE identity and issuer chain
/// have been correctly initialized.
pub fn tee_qpl_get_root_ca_crl() -> Result<String, quote3_error_t> {
    let mut p_root_ca_crl: *mut u8 = std::ptr::null_mut();
    let mut root_ca_crl_size: u16 = 0;
    unsafe {
        let result = qpl_sys::sgx_ql_get_root_ca_crl(
            &mut p_root_ca_crl as *mut *mut u8,
            &mut root_ca_crl_size as *mut u16,
        );
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                let root_ca_crl: String = CStr::from_ptr(p_root_ca_crl as *const i8)
                    .to_string_lossy()
                    .into_owned();
                qpl_sys::sgx_ql_free_root_ca_crl(p_root_ca_crl);
                Ok(root_ca_crl)
            }
            _ => Err(result),
        }
    }
}

/// This function clears the cache of a given type.
///
/// # Arguments
///
/// * `cache_type` - The type of the cache to clear.
///
/// # Returns
///
/// * A `quote3_error_t` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_qpl_clear_cache` function from the `qpl_sys` module,
/// which is an FFI function that interacts with the SGX SDK. The caller must ensure that the cache type is valid.
pub fn tee_qpl_clear_cache(cache_type: tee_qpl_cache_type) -> quote3_error_t {
    unsafe { qpl_sys::sgx_qpl_clear_cache(cache_type.bits()) }
}

/// This function initializes the global state.
///
/// # Returns
///
/// * A `quote3_error_t` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_qpl_global_init` function from the `qpl_sys` module,
/// which is an FFI function that interacts with the SGX SDK.
pub fn tee_qpl_global_init() -> quote3_error_t {
    unsafe { qpl_sys::sgx_qpl_global_init() }
}

/// This function cleans up the global state.
///
/// # Returns
///
/// * A `quote3_error_t` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_qpl_global_cleanup` function from the `qpl_sys` module,
/// which is an FFI function that interacts with the SGX SDK.
pub fn tee_qpl_global_cleanup() -> quote3_error_t {
    unsafe { qpl_sys::sgx_qpl_global_cleanup() }
}

/// This function sets a logging callback with a given log level.
///
/// # Arguments
///
/// * `cb` - The logging callback to set.
/// * `loglevel` - The log level to set for the callback.
///
/// # Returns
///
/// * A `quote3_error_t` - An error code indicating what went wrong.
///
/// # Safety
///
/// This function contains unsafe code. It calls the `sgx_ql_set_logging_callback` function from the `qpl_sys` module,
/// which is an FFI function that interacts with the SGX SDK. The caller must ensure that the logging callback and log level are valid.
pub fn tee_qpl_set_logging_callback(
    cb: tee_qpl_logging_callback,
    loglevel: tee_qpl_log_level,
) -> quote3_error_t {
    unsafe { qpl_sys::sgx_ql_set_logging_callback(cb, loglevel) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_qpl_get_quote_config() {
        let cert_id = tee_qpl_pck_cert_id {
            qe3_id: vec![
                0x89, 0xa7, 0x7d, 0x35, 0x52, 0xe6, 0x03, 0xd3, 0x66, 0x43, 0x5b, 0x56, 0xd2, 0x02,
                0x6c, 0x0b,
            ],
            cpu_svn: {
                qpl_sys::_sgx_cpu_svn_t {
                    svn: [
                        0x8, 0x8, 0xf, 0xe, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0,
                    ],
                }
            },
            pce_isv_svn: 0xe,
            encrypted_ppid: Some(vec![
                0x34, 0xe8, 0xce, 0x6a, 0x97, 0xd3, 0x33, 0x75, 0xd9, 0xee, 0xbf, 0xa4, 0x83, 0x31,
                0xae, 0x32, 0xde, 0xdc, 0xf6, 0x91, 0x07, 0xd4, 0x1b, 0x54, 0x9a, 0x08, 0x8a, 0x21,
                0x0b, 0xdd, 0x81, 0x85, 0xc8, 0x22, 0x09, 0x4a, 0xaa, 0xd7, 0xbd, 0x32, 0x69, 0x76,
                0xcf, 0x8c, 0x09, 0x6a, 0x2d, 0xa2, 0xf5, 0x77, 0x78, 0x01, 0xd5, 0x53, 0xb5, 0xb2,
                0x61, 0x87, 0x6c, 0xf8, 0x8c, 0x73, 0x5a, 0x35, 0xe4, 0x8d, 0xe9, 0x56, 0xa4, 0x2c,
                0x6e, 0xd4, 0xc4, 0x01, 0x8e, 0x87, 0x13, 0xc1, 0x6e, 0x49, 0xf1, 0x3b, 0x02, 0xf4,
                0xe3, 0x08, 0x3f, 0x18, 0x50, 0x5a, 0xf2, 0x88, 0x45, 0x49, 0x29, 0x76, 0x33, 0x61,
                0xa0, 0xc1, 0x36, 0x7c, 0xca, 0x94, 0x53, 0xf6, 0xd4, 0xf6, 0xaa, 0x2f, 0x24, 0x14,
                0xbc, 0xe1, 0x56, 0xbf, 0x31, 0x4d, 0x5f, 0x92, 0xa4, 0x95, 0xe4, 0xc1, 0x94, 0x23,
                0xea, 0x5e, 0xa5, 0x4f, 0x7a, 0xbf, 0x4b, 0x7c, 0x30, 0xcc, 0xd5, 0x99, 0xe2, 0x96,
                0x56, 0x20, 0xbd, 0x12, 0x49, 0x20, 0x1c, 0x47, 0x4e, 0xea, 0x18, 0x6c, 0x28, 0x55,
                0xd6, 0x55, 0xfe, 0x18, 0x91, 0xd6, 0x0b, 0x56, 0xb5, 0x68, 0xb4, 0xe3, 0xae, 0xa3,
                0x91, 0x75, 0x5c, 0x8e, 0x6d, 0x67, 0x9d, 0xc5, 0x40, 0xfb, 0x1f, 0x54, 0xbb, 0x29,
                0x81, 0x90, 0x60, 0xa9, 0x7a, 0xbe, 0xf3, 0xd2, 0x8c, 0x21, 0xd5, 0x3b, 0x9f, 0x41,
                0x51, 0x1b, 0xc7, 0x5b, 0x50, 0x69, 0xa5, 0x7b, 0xb7, 0x9b, 0x5b, 0x08, 0xf7, 0x04,
                0xb2, 0x63, 0x5d, 0x2f, 0x10, 0x7e, 0xa8, 0x87, 0x15, 0xda, 0x2d, 0xae, 0x81, 0x4e,
                0xa2, 0x09, 0xa2, 0x46, 0x61, 0x27, 0x3f, 0x65, 0x0b, 0x9e, 0x77, 0x84, 0xfd, 0x6c,
                0x79, 0xf3, 0xa4, 0xf9, 0x9f, 0xf3, 0x3e, 0x9a, 0x62, 0x6a, 0xf4, 0xfb, 0xbc, 0x24,
                0x48, 0x69, 0x1f, 0x4d, 0x20, 0xd8, 0xe0, 0x2b, 0x90, 0x50, 0xb2, 0x55, 0xec, 0x1e,
                0xa0, 0x85, 0x93, 0xf1, 0x8f, 0x27, 0x1e, 0xf0, 0xb9, 0xad, 0x8f, 0x03, 0xd3, 0x23,
                0x4d, 0x76, 0xb6, 0x4a, 0x78, 0xf3, 0x65, 0xc0, 0x43, 0x4f, 0xd4, 0x48, 0xd9, 0x19,
                0xc1, 0x1d, 0xa8, 0x53, 0xf3, 0x54, 0x9d, 0x13, 0x29, 0xc6, 0x8f, 0x9c, 0x2c, 0x7a,
                0xff, 0x46, 0x55, 0x60, 0x7e, 0xdc, 0x81, 0xef, 0xe1, 0xfc, 0xd3, 0x24, 0xdd, 0xfc,
                0x17, 0xde, 0x55, 0xc3, 0xcb, 0x31, 0x79, 0xfc, 0x85, 0x20, 0xd2, 0x55, 0xe2, 0xb2,
                0x2e, 0x11, 0x6b, 0xee, 0x97, 0x8f, 0x93, 0xfe, 0x9d, 0xec, 0xcb, 0x92, 0x93, 0xf8,
                0xa7, 0xd4, 0xb3, 0x7e, 0x42, 0x1c, 0x21, 0xad, 0xbc, 0x10, 0x11, 0xbf, 0x1f, 0x46,
                0xf4, 0x78, 0x16, 0xb9, 0x5c, 0xb9, 0x9b, 0xcb, 0x6e, 0x45, 0x9e, 0xf0, 0x1a, 0x52,
                0xb3, 0x67, 0xa3, 0xfc, 0x47, 0x0f,
            ]),
            crypto_suite: 0x1,
            pce_id: 0,
        };
        let result: Result<tee_qpl_config, quote3_error_t> = tee_qpl_get_quote_config(&cert_id);
        match result {
            Ok(_q) => {
                println!("tee_qpl_get_quote_config Success");
            }
            Err(_e) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn test_tee_qpl_get_quote_verification_collateral() {
        let fmspc: Vec<u8> = vec![0x00, 0x60, 0x6a, 0x00, 0x00, 0x00];
        let custom_param: Vec<u8> = vec![0x61, 0x62, 0x63];
        let result = tee_qpl_get_quote_verification_collateral(
            tee_qpl_type::TEE_QPL_TYPE_SGX,
            &fmspc,
            "platform",
            Some(&custom_param),
        );
        match result {
            Ok(_q) => {
                println!("tee_qpl_get_quote_verification_collateral Success");
            }
            Err(_e) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn test_tee_qpl_get_qve_identity() {
        let result = tee_qpl_get_qve_identity();
        match result {
            Ok(_q) => {
                println!("tee_qpl_get_qve_identity Success");
            }
            Err(_e) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn test_tee_qpl_get_root_ca_crl() {
        let result = tee_qpl_get_root_ca_crl();
        match result {
            Ok(_q) => {
                println!("tee_qpl_get_root_ca_crl Success");
            }
            Err(_e) => {
                assert!(false);
            }
        };
    }

    #[test]
    fn test_others() {
        let result: quote3_error_t = tee_qpl_clear_cache(
            tee_qpl_cache_type::TEE_QPL_CACHE_CERTIFICATE
                | tee_qpl_cache_type::TEE_QPL_CACHE_QV_COLLATERAL,
        );
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                println!("tee_qpl_clear_cache Success");
            }
            _ => {
                assert!(false);
            }
        };
        let result = tee_qpl_global_init();
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                println!("tee_qpl_global_init Success");
            }
            _ => {
                assert!(false);
            }
        };
        let result = tee_qpl_global_cleanup();
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                println!("tee_qpl_global_cleanup Success");
            }
            _ => {
                assert!(false);
            }
        };
    }

    unsafe extern "C" fn my_logging_callback(
        level: tee_qpl_log_level,
        message: *const ::std::os::raw::c_char,
    ) {
        let msg_str = std::ffi::CStr::from_ptr(message).to_str().unwrap();
        println!("level {level}: {:?}", msg_str);
    }

    #[test]
    fn test_tee_qpl_set_logging_callback() {
        let cb: tee_qpl_logging_callback = Some(my_logging_callback);
        let result: quote3_error_t = tee_qpl_set_logging_callback(cb, 1);
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                println!("tee_qpl_set_logging_callback Success");
            }
            _ => {
                assert!(false);
            }
        };
        test_tee_qpl_get_quote_config();
    }
}
