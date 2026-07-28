/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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
//! Intel®️ Software Guard Extensions Data Center Attestation Primitives (Intel®️ SGX DCAP)\
//! Rust wrapper for Quote Verification Library
//! ================================================
//!
//! This is a safe wrapper for **sgx-dcap-quoteverify-sys**.

use std::ffi::CString;
use std::marker::PhantomData;
use std::mem;
use std::ops::Deref;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use intel_tee_quote_verification_sys as qvl_sys;
use qvl_sys::sgx_ql_qve_collateral_t;

pub use qvl_sys::quote3_error_t;
pub use qvl_sys::sgx_ql_qe_report_info_t;
pub use qvl_sys::sgx_ql_qv_result_t;
pub use qvl_sys::sgx_ql_qv_supplemental_t;
pub use qvl_sys::sgx_ql_request_policy_t;
pub use qvl_sys::sgx_qv_path_type_t;
pub use qvl_sys::tee_supp_data_descriptor_t;

/// Quote Certification Collateral Structure
///
#[derive(Debug, Clone)]
pub struct QuoteCollateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: Vec<c_char>,
    pub root_ca_crl: Vec<c_char>,
    pub pck_crl: Vec<c_char>,
    pub tcb_info_issuer_chain: Vec<c_char>,
    pub tcb_info: Vec<c_char>,
    pub qe_identity_issuer_chain: Vec<c_char>,
    pub qe_identity: Vec<c_char>,
}

impl TryFrom<&sgx_ql_qve_collateral_t> for QuoteCollateral {
    type Error = ();

    fn try_from(collateral: &sgx_ql_qve_collateral_t) -> Result<Self, Self::Error> {
        fn raw_ptr_to_vec(data: *mut c_char, len: u32) -> Result<Vec<c_char>, ()> {
            if data.is_null() {
                return Err(());
            }
            Ok(unsafe { slice::from_raw_parts(data, len as _) }.to_vec())
        }

        Ok(QuoteCollateral {
            major_version: unsafe { collateral.__bindgen_anon_1.__bindgen_anon_1.major_version },
            minor_version: unsafe { collateral.__bindgen_anon_1.__bindgen_anon_1.minor_version },
            tee_type: collateral.tee_type,
            pck_crl_issuer_chain: raw_ptr_to_vec(
                collateral.pck_crl_issuer_chain,
                collateral.pck_crl_issuer_chain_size,
            )?,
            root_ca_crl: raw_ptr_to_vec(collateral.root_ca_crl, collateral.root_ca_crl_size)?,
            pck_crl: raw_ptr_to_vec(collateral.pck_crl, collateral.pck_crl_size)?,
            tcb_info_issuer_chain: raw_ptr_to_vec(
                collateral.tcb_info_issuer_chain,
                collateral.tcb_info_issuer_chain_size,
            )?,
            tcb_info: raw_ptr_to_vec(collateral.tcb_info, collateral.tcb_info_size)?,
            qe_identity_issuer_chain: raw_ptr_to_vec(
                collateral.qe_identity_issuer_chain,
                collateral.qe_identity_issuer_chain_size,
            )?,
            qe_identity: raw_ptr_to_vec(collateral.qe_identity, collateral.qe_identity_size)?,
        })
    }
}

struct PhantomCollateral<'a> {
    inner: sgx_ql_qve_collateral_t,
    phantom: PhantomData<&'a ()>,
}

impl<'a> From<&'a QuoteCollateral> for PhantomCollateral<'a> {
    fn from(collateral: &'a QuoteCollateral) -> Self {
        PhantomCollateral {
            inner: sgx_ql_qve_collateral_t {
                __bindgen_anon_1: qvl_sys::_sgx_ql_qve_collateral_t__bindgen_ty_1 {
                    __bindgen_anon_1:
                        qvl_sys::_sgx_ql_qve_collateral_t__bindgen_ty_1__bindgen_ty_1 {
                            major_version: collateral.major_version,
                            minor_version: collateral.minor_version,
                        },
                },
                tee_type: collateral.tee_type,
                pck_crl_issuer_chain: collateral.pck_crl_issuer_chain.as_ptr() as _,
                pck_crl_issuer_chain_size: collateral.pck_crl_issuer_chain.len() as _,
                root_ca_crl: collateral.root_ca_crl.as_ptr() as _,
                root_ca_crl_size: collateral.root_ca_crl.len() as _,
                pck_crl: collateral.pck_crl.as_ptr() as _,
                pck_crl_size: collateral.pck_crl.len() as _,
                tcb_info_issuer_chain: collateral.tcb_info_issuer_chain.as_ptr() as _,
                tcb_info_issuer_chain_size: collateral.tcb_info_issuer_chain.len() as _,
                tcb_info: collateral.tcb_info.as_ptr() as _,
                tcb_info_size: collateral.tcb_info.len() as _,
                qe_identity_issuer_chain: collateral.qe_identity_issuer_chain.as_ptr() as _,
                qe_identity_issuer_chain_size: collateral.qe_identity_issuer_chain.len() as _,
                qe_identity: collateral.qe_identity.as_ptr() as _,
                qe_identity_size: collateral.qe_identity.len() as _,
            },
            phantom: PhantomData,
        }
    }
}

impl<'a> Deref for PhantomCollateral<'a> {
    type Target = sgx_ql_qve_collateral_t;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// When the Quoting Verification Library is linked to a process, it needs to know the proper enclave loading policy.
/// The library may be linked with a long lived process, such as a service, where it can load the enclaves and leave
/// them loaded (persistent). This better ensures that the enclaves will be available upon quote requests and not subject
/// to EPC limitations if loaded on demand. However, if the Quoting library is linked with an application process, there
/// may be many applications with the Quoting library and a better utilization of EPC is to load and unloaded the quoting
/// enclaves on demand (ephemeral).  The library will be shipped with a default policy of loading enclaves and leaving
/// them loaded until the library is unloaded (PERSISTENT). If the policy is set to EPHEMERAL, then the QE and PCE will
/// be loaded and unloaded on-demand.  If either enclave is already loaded when the policy is change to EPHEMERAL, the
/// enclaves will be unloaded before returning.
///
/// # Param
/// - **policy**\
/// Set the requested enclave loading policy to either *SGX_QL_PERSISTENT*, *SGX_QL_EPHEMERAL* or *SGX_QL_DEFAULT*.
///
/// # Return
/// - ***SGX_QL_SUCCESS***\
/// Successfully set the enclave loading policy for the quoting library's enclaves.\
/// - ***SGX_QL_UNSUPPORTED_LOADING_POLICY***\
/// The selected policy is not support by the quoting library.\
/// - ***SGX_QL_ERROR_UNEXPECTED***\
/// Unexpected internal error.
///
/// # Examples
/// ```
/// use intel_tee_quote_verification_rs::*;
///
/// let policy = sgx_ql_request_policy_t::SGX_QL_DEFAULT;
/// let ret = sgx_qv_set_enclave_load_policy(policy);
///
/// assert_eq!(ret, quote3_error_t::SGX_QL_SUCCESS);
/// ```
pub fn sgx_qv_set_enclave_load_policy(policy: sgx_ql_request_policy_t) -> quote3_error_t {
    unsafe { qvl_sys::sgx_qv_set_enclave_load_policy(policy) }
}

/// Get SGX supplemental data required size.
///
/// # Return
/// Size of the supplemental data in bytes.
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_ERROR_QVL_QVE_MISMATCH*
/// - *SGX_QL_ENCLAVE_LOAD_ERROR*
///
/// # Examples
/// ```
/// use intel_tee_quote_verification_rs::*;
///
/// let data_size = sgx_qv_get_quote_supplemental_data_size().unwrap();
///
/// assert_eq!(data_size, std::mem::size_of::<sgx_ql_qv_supplemental_t>() as u32);
/// ```
pub fn sgx_qv_get_quote_supplemental_data_size() -> Result<u32, quote3_error_t> {
    let mut data_size = 0u32;
    match unsafe { qvl_sys::sgx_qv_get_quote_supplemental_data_size(&mut data_size) } {
        quote3_error_t::SGX_QL_SUCCESS => Ok(data_size),
        error_code => Err(error_code),
    }
}

/// Perform SGX ECDSA quote verification.
///
/// # Param
/// - **quote**\
/// SGX Quote, presented as u8 vector.
/// - **quote_collateral**\
/// Quote Certification Collateral provided by the caller.
/// - **expiration_check_date**\
/// This is the date that the QvE will use to determine if any of the inputted collateral have expired.
/// - **qve_report_info**\
/// This parameter can be used in 2 ways.\
///     - If qve_report_info is NOT None, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.\
///     - if qve_report_info is None, the API will use QVL library to perform quote verification, note that the results can not be cryptographically authenticated in this mode.
/// - **supplemental_data_size**\
/// Size of the supplemental data (in bytes).
/// - **supplemental_data**\
/// The parameter is optional. If it is None, supplemental_data_size must be 0.
///
/// # Return
/// Result type of (collateral_expiration_status, verification_result).
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_QUOTE_FORMAT_UNSUPPORTED*
/// - *SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED*
/// - *SGX_QL_UNABLE_TO_GENERATE_REPORT*
/// - *SGX_QL_CRL_UNSUPPORTED_FORMAT*
/// - *SGX_QL_ERROR_UNEXPECTED*
///
pub fn sgx_qv_verify_quote(
    quote: &[u8],
    quote_collateral: Option<&QuoteCollateral>,
    expiration_check_date: i64,
    qve_report_info: Option<&mut sgx_ql_qe_report_info_t>,
    supplemental_data_size: u32,
    supplemental_data: Option<&mut sgx_ql_qv_supplemental_t>,
) -> Result<(u32, sgx_ql_qv_result_t), quote3_error_t> {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let quote_collateral = quote_collateral.map(PhantomCollateral::from);
    let p_quote_collateral = quote_collateral.as_deref().map_or(ptr::null(), |p| p);
    let p_qve_report_info = qve_report_info.map_or(ptr::null_mut(), |p| p);
    let p_supplemental_data = supplemental_data.map_or(ptr::null_mut(), |p| p);

    match unsafe {
        qvl_sys::sgx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            p_quote_collateral,
            expiration_check_date,
            &mut collateral_expiration_status,
            &mut quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data as _,
        )
    } {
        quote3_error_t::SGX_QL_SUCCESS => {
            Ok((collateral_expiration_status, quote_verification_result))
        }
        error_code => Err(error_code),
    }
}

/// Get TDX supplemental data required size.
///
/// # Return
/// Size of the supplemental data in bytes.
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_ERROR_QVL_QVE_MISMATCH*
/// - *SGX_QL_ENCLAVE_LOAD_ERROR*
///
/// # Examples
/// ```
/// use intel_tee_quote_verification_rs::*;
///
/// let data_size = tdx_qv_get_quote_supplemental_data_size().unwrap();
///
/// assert_eq!(data_size, std::mem::size_of::<sgx_ql_qv_supplemental_t>() as u32);
/// ```
pub fn tdx_qv_get_quote_supplemental_data_size() -> Result<u32, quote3_error_t> {
    let mut data_size = 0u32;
    match unsafe { qvl_sys::tdx_qv_get_quote_supplemental_data_size(&mut data_size) } {
        quote3_error_t::SGX_QL_SUCCESS => Ok(data_size),
        error_code => Err(error_code),
    }
}

/// Perform TDX ECDSA quote verification.
///
/// # Param
/// - **quote**\
/// TDX Quote, presented as u8 vector.
/// - **quote_collateral**\
/// Quote Certification Collateral provided by the caller.
/// - **expiration_check_date**\
/// This is the date that the QvE will use to determine if any of the inputted collateral have expired.
/// - **qve_report_info**\
/// This parameter can be used in 2 ways.\
///     - If qve_report_info is NOT None, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.\
///     - if qve_report_info is None, the API will use QVL library to perform quote verification, note that the results can not be cryptographically authenticated in this mode.
/// - **supplemental_data_size**\
/// Size of the supplemental data (in bytes).
/// - **supplemental_data**\
/// The parameter is optional. If it is None, supplemental_data_size must be 0.
///
/// # Return
/// Result type of (collateral_expiration_status, verification_result).
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_QUOTE_FORMAT_UNSUPPORTED*
/// - *SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED*
/// - *SGX_QL_UNABLE_TO_GENERATE_REPORT*
/// - *SGX_QL_CRL_UNSUPPORTED_FORMAT*
/// - *SGX_QL_ERROR_UNEXPECTED*
///
pub fn tdx_qv_verify_quote(
    quote: &[u8],
    quote_collateral: Option<&QuoteCollateral>,
    expiration_check_date: i64,
    qve_report_info: Option<&mut sgx_ql_qe_report_info_t>,
    supplemental_data_size: u32,
    supplemental_data: Option<&mut sgx_ql_qv_supplemental_t>,
) -> Result<(u32, sgx_ql_qv_result_t), quote3_error_t> {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let quote_collateral = quote_collateral.map(PhantomCollateral::from);
    let p_quote_collateral = quote_collateral.as_deref().map_or(ptr::null(), |p| p);
    let p_qve_report_info = qve_report_info.map_or(ptr::null_mut(), |p| p);
    let p_supplemental_data = supplemental_data.map_or(ptr::null_mut(), |p| p);

    match unsafe {
        qvl_sys::tdx_qv_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            p_quote_collateral,
            expiration_check_date,
            &mut collateral_expiration_status,
            &mut quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data as _,
        )
    } {
        quote3_error_t::SGX_QL_SUCCESS => {
            Ok((collateral_expiration_status, quote_verification_result))
        }
        error_code => Err(error_code),
    }
}

/// Set the full path of QVE and QPL library.\
/// The function takes the enum and the corresponding full path.
///
/// # Param
/// - **path_type**\
/// The type of binary being passed in.
/// - **path**\
/// It should be a valid full path.
///
/// # Return
/// - ***SGX_QL_SUCCESS***\
/// Successfully set the full path.
/// - ***SGX_QL_ERROR_INVALID_PARAMETER***\
/// Path is not a valid full path or the path is too long.
///
#[cfg(target_os = "linux")]
pub fn sgx_qv_set_path(path_type: sgx_qv_path_type_t, path: &str) -> quote3_error_t {
    match CString::new(path) {
        Ok(path) => unsafe { qvl_sys::sgx_qv_set_path(path_type, path.as_ptr()) },
        _ => quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER,
    }
}

/// Get quote verification collateral.
///
/// # Param
/// - **quote**\
/// SGX/TDX Quote, presented as u8 vector.
///
/// # Return
/// Result type of quote_collecteral.
///
/// - **quote_collateral**\
/// This is the Quote Certification Collateral retrieved based on Quote.
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_PLATFORM_LIB_UNAVAILABLE*
/// - *SGX_QL_PCK_CERT_CHAIN_ERROR*
/// - *SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT*
/// - *SGX_QL_QUOTE_FORMAT_UNSUPPORTED*
/// - *SGX_QL_OUT_OF_MEMORY*
/// - *SGX_QL_NO_QUOTE_COLLATERAL_DATA*
/// - *SGX_QL_ERROR_UNEXPECTED*
///
pub fn tee_qv_get_collateral(quote: &[u8]) -> Result<QuoteCollateral, quote3_error_t> {
    let mut buf = ptr::null_mut();
    let mut buf_len = 0u32;

    match unsafe {
        qvl_sys::tee_qv_get_collateral(quote.as_ptr(), quote.len() as u32, &mut buf, &mut buf_len)
    } {
        quote3_error_t::SGX_QL_SUCCESS => {
            if buf.is_null()
                || buf_len == 0
                || buf.align_offset(mem::align_of::<sgx_ql_qve_collateral_t>()) != 0
            {
                return Err(quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA);
            }

            // SAFETY: buf is not null, buf_len is not zero, and buf is aligned.
            let orig_collateral = &unsafe { *(buf as *const sgx_ql_qve_collateral_t) };
            let collateral = QuoteCollateral::try_from(orig_collateral)
                .map_err(|_| quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA)?;

            match unsafe { qvl_sys::tee_qv_free_collateral(buf) } {
                quote3_error_t::SGX_QL_SUCCESS => Ok(collateral),
                error_code => Err(error_code),
            }
        }
        error_code => Err(error_code),
    }
}

/// Get supplemental data latest version and required size, support both SGX and TDX.
///
/// # Param
/// - **quote**\
/// SGX/TDX Quote, presented as u8 vector.
///
/// # Return
/// Result type of (version, data_size) tuple.
///
/// - **version**\
/// Latest version of the supplemental data.
/// - **data_size**\
/// The size of the buffer in bytes required to contain all of the supplemental data.
///
pub fn tee_get_supplemental_data_version_and_size(
    quote: &[u8],
) -> Result<(u32, u32), quote3_error_t> {
    let mut version = 0u32;
    let mut data_size = 0u32;

    match unsafe {
        qvl_sys::tee_get_supplemental_data_version_and_size(
            quote.as_ptr(),
            quote.len() as u32,
            &mut version,
            &mut data_size,
        )
    } {
        quote3_error_t::SGX_QL_SUCCESS => Ok((version, data_size)),
        error_code => Err(error_code),
    }
}

/// Perform quote verification for SGX and TDX.\
/// This API works the same as the old one, but takes a new parameter to describe the supplemental data (supp_data_descriptor).
///
/// # Param
/// - **quote**\
/// SGX/TDX Quote, presented as u8 vector.
/// - **quote_collateral**\
/// Quote Certification Collateral provided by the caller.
/// - **expiration_check_date**\
/// This is the date that the QvE will use to determine if any of the inputted collateral have expired.
/// - **qve_report_info**\
/// This parameter can be used in 2 ways.\
///     - If qve_report_info is NOT None, the API will use Intel QvE to perform quote verification, and QvE will generate a report using the target_info in sgx_ql_qe_report_info_t structure.\
///     - if qve_report_info is None, the API will use QVL library to perform quote verification, note that the results can not be cryptographically authenticated in this mode.
/// - **supp_datal_descriptor**\
/// *tee_supp_data_descriptor_t* structure.\
/// You can specify the major version of supplemental data by setting supp_datal_descriptor.major_version.\
/// If supp_datal_descriptor is None, no supplemental data is returned.\
/// If supp_datal_descriptor.major_version == 0, then return the latest version of the *sgx_ql_qv_supplemental_t* structure.\
/// If supp_datal_descriptor.major_version <= latest supported version, return the latest minor version associated with that major version.\
/// If supp_datal_descriptor.major_version > latest supported version, return an error *SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED*.
///
/// # Return
/// Result type of (collateral_expiration_status, verification_result).
///
/// Status code of the operation, one of:
/// - *SGX_QL_ERROR_INVALID_PARAMETER*
/// - *SGX_QL_QUOTE_FORMAT_UNSUPPORTED*
/// - *SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED*
/// - *SGX_QL_UNABLE_TO_GENERATE_REPORT*
/// - *SGX_QL_CRL_UNSUPPORTED_FORMAT*
/// - *SGX_QL_ERROR_UNEXPECTED*
///
pub fn tee_verify_quote(
    quote: &[u8],
    quote_collateral: Option<&QuoteCollateral>,
    expiration_check_date: i64,
    qve_report_info: Option<&mut sgx_ql_qe_report_info_t>,
    supp_data_descriptor: Option<&mut tee_supp_data_descriptor_t>,
) -> Result<(u32, sgx_ql_qv_result_t), quote3_error_t> {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let quote_collateral = quote_collateral.map(PhantomCollateral::from);
    let p_quote_collateral = quote_collateral.as_deref().map_or(ptr::null(), |p| p);
    let p_qve_report_info = qve_report_info.map_or(ptr::null_mut(), |p| p);
    let p_supp_data_descriptor = supp_data_descriptor.map_or(ptr::null_mut(), |p| p);

    match unsafe {
        qvl_sys::tee_verify_quote(
            quote.as_ptr(),
            quote.len() as u32,
            p_quote_collateral as _,
            expiration_check_date,
            &mut collateral_expiration_status,
            &mut quote_verification_result,
            p_qve_report_info,
            p_supp_data_descriptor,
        )
    } {
        quote3_error_t::SGX_QL_SUCCESS => {
            Ok((collateral_expiration_status, quote_verification_result))
        }
        error_code => Err(error_code),
    }
}
