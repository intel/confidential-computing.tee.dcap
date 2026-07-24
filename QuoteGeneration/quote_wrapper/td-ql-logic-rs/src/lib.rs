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

//! This is the Intel TDX Quote Logic Library for Rust.
#![allow(non_camel_case_types)]

use std::mem::MaybeUninit;
use std::option::Option;
pub use td_ql_logic_sys::sgx_quote_nonce_t;
pub use td_ql_logic_sys::sgx_report_t;
pub use td_ql_logic_sys::sgx_target_info_t;
pub use td_ql_logic_sys::tee_att_ae_type_t;
pub use td_ql_logic_sys::tee_att_att_key_id_t;
pub use td_ql_logic_sys::tee_att_config_t;
pub use td_ql_logic_sys::tee_att_error_t;
pub use td_ql_logic_sys::tee_platform_info_t;

pub use qpl_rs::tee_qpl_log_level;
pub use qpl_rs::tee_qpl_logging_callback;

type sgx_ql_set_logging_callback_t = unsafe extern "C" fn(
    logger: qpl_rs::tee_qpl_logging_callback,
    loglevel: qpl_rs::tee_qpl_log_level,
) -> qpl_rs::quote3_error_t;

/// Creates a TEE attestation context.
///
/// # Arguments
///
/// * `att_key_id` - Attestation key ID, can be `None`.
/// * `qe_path` - QE path, can be `None`.
///
/// # Returns
///
/// Returns a pointer to a `tee_att_config_t` type on success, or a
/// `tee_att_error_t` error code on failure.
///
/// # Panics
///
/// Panics if the returned `p_config` is null.
///
/// # Example
///
/// ```
/// use td_ql_logic_rs::*;
///
/// let att_key_id = None;
/// let qe_path = None;
/// let result = tee_att_create_context(att_key_id, qe_path);
/// assert!(result.is_ok());
/// ```
pub fn tee_att_create_context(
    att_key_id: Option<&tee_att_att_key_id_t>,
    qe_path: Option<&str>,
) -> Result<*mut tee_att_config_t, tee_att_error_t> {
    let p_att_key_id = match att_key_id {
        Some(p) => p as *const tee_att_att_key_id_t,
        None => std::ptr::null(),
    };
    let mut c_string = std::ffi::CString::new("").unwrap();
    let p_qe_path = match qe_path {
        Some(path) => match std::ffi::CString::new(path) {
            Ok(c_str) => {
                c_string = c_str;
                c_string.as_ptr() as *const i8
            }
            _ => return Err(tee_att_error_t::TEE_ATT_ERROR_INVALID_PARAMETER),
        },
        None => std::ptr::null(),
    };
    let mut p_config: *mut tee_att_config_t = std::ptr::null_mut();
    unsafe {
        let result =
            td_ql_logic_sys::tee_att_create_context(p_att_key_id, p_qe_path, &mut p_config);
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => {
                assert!(!p_config.is_null());
                Ok(p_config)
            }
            _ => Err(result),
        }
    }
}

/// # Safety
///
/// `context` must be either null or a pointer previously returned by
/// [`tee_att_create_context`] that has not yet been freed. Passing any
/// other value (dangling pointer, double-free, foreign allocation) is
/// undefined behavior.
pub unsafe fn tee_att_free_context(context: *mut tee_att_config_t) -> tee_att_error_t {
    td_ql_logic_sys::tee_att_free_context(context)
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
/// * `refresh_att_key`: A boolean value indicating whether to refresh the attestation key.
///
/// # Panics
///
/// This function could panic if the FFI reports a zero-length
/// `buf_len` for the public-key buffer.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_init_quote(
    context: *mut tee_att_config_t,
    refresh_att_key: bool,
) -> Result<(Vec<u8>, sgx_target_info_t), tee_att_error_t> {
    let mut qe_target: sgx_target_info_t = MaybeUninit::zeroed().assume_init();
    let mut buf_len = 0;
    {
        let result = td_ql_logic_sys::tee_att_init_quote(
            context,
            &mut qe_target,
            refresh_att_key,
            &mut buf_len,
            std::ptr::null_mut(),
        );
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => {
                assert!(buf_len > 0);
                let mut buf: Vec<u8> = vec![0; buf_len];
                let result = td_ql_logic_sys::tee_att_init_quote(
                    context,
                    &mut qe_target,
                    refresh_att_key,
                    &mut buf_len,
                    buf.as_mut_ptr(),
                );
                match result {
                    tee_att_error_t::TEE_ATT_SUCCESS => Ok((buf, qe_target)),
                    _ => Err(result),
                }
            }
            _ => Err(result),
        }
    }
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
/// * `report`: The 1024-byte TDX report to be quoted. The slice length
///   must be exactly 1024; any other length returns
///   `TEE_ATT_ERROR_INVALID_PARAMETER`.
///
/// # Panics
///
/// This function could panic if the FFI reports a zero-length
/// `buf_len` for the quote buffer.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_get_quote(
    context: *mut tee_att_config_t,
    report: &[u8],
) -> Result<Vec<u8>, tee_att_error_t> {
    let mut buf_len = 0;
    if report.len() != 1024 {
        return Err(tee_att_error_t::TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    {
        let result = td_ql_logic_sys::tee_att_get_quote_size(context, &mut buf_len);
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => {
                assert!(buf_len > 0);
                let mut buf: Vec<u8> = vec![0; buf_len as usize];
                let result = td_ql_logic_sys::tee_att_get_quote(
                    context,
                    report.as_ptr(),
                    1024,
                    std::ptr::null_mut(),
                    buf.as_mut_ptr(),
                    buf_len,
                );
                match result {
                    tee_att_error_t::TEE_ATT_SUCCESS => Ok(buf),
                    _ => Err(result),
                }
            }
            _ => Err(result),
        }
    }
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
///
/// # Panics
///
/// This function does not have any scenarios in which it could panic.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_get_keyid(
    context: *mut tee_att_config_t,
) -> Result<tee_att_att_key_id_t, tee_att_error_t> {
    let mut buf: tee_att_att_key_id_t = MaybeUninit::zeroed().assume_init();
    {
        let result = td_ql_logic_sys::tee_att_get_keyid(context, &mut buf);
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => Ok(buf),
            _ => Err(result),
        }
    }
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
///
/// # Panics
///
/// This function does not have any scenarios in which it could panic.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_get_platform_info(
    context: *mut tee_att_config_t,
) -> Result<tee_platform_info_t, tee_att_error_t> {
    let mut buf: tee_platform_info_t = MaybeUninit::zeroed().assume_init();
    {
        let result = td_ql_logic_sys::tee_att_get_platform_info(context, &mut buf);
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => Ok(buf),
            _ => Err(result),
        }
    }
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
/// * `ae_type`: The type of attestation engine to use.
/// * `path`: The path to the attestation engine library.
///
/// # Panics
///
/// This function does not have any scenarios in which it could panic.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_set_path(
    context: *mut tee_att_config_t,
    ae_type: tee_att_ae_type_t,
    path: &str,
) -> tee_att_error_t {
    match std::ffi::CString::new(path) {
        Ok(path) => {
            td_ql_logic_sys::tee_att_set_path(context, ae_type, path.as_ptr() as *const i8)
        }
        _ => tee_att_error_t::TEE_ATT_ERROR_INVALID_PARAMETER,
    }
}

/// # Parameters
///
/// * `context`: A mutable pointer to a `tee_att_config_t` object.
/// * `cb` - The logging callback to set.
/// * `loglevel` - The log level to set for the callback.
///
/// # Panics
///
/// This function does not have any scenarios in which it could panic.
///
/// # Safety
///
/// `context` must be a valid, live pointer previously returned by
/// [`tee_att_create_context`].
pub unsafe fn tee_att_set_logging_callback(
    context: *mut tee_att_config_t,
    cb: qpl_rs::tee_qpl_logging_callback,
    loglevel: qpl_rs::tee_qpl_log_level,
) -> tee_att_error_t {
    let mut qpl_handle: *mut std::ffi::c_void = std::ptr::null_mut();
    {
        let result = td_ql_logic_sys::tee_att_get_qpl_handle(context, &mut qpl_handle);
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => {
                let name = std::ffi::CString::new("sgx_ql_set_logging_callback").unwrap();
                let func = libc::dlsym(qpl_handle, name.as_ptr() as *const i8);
                if func.is_null() {
                    tee_att_error_t::TEE_ATT_PLATFORM_LIB_UNAVAILABLE
                } else {
                    let set_callback_handle: sgx_ql_set_logging_callback_t =
                        std::mem::transmute(func);
                    let ret = set_callback_handle(cb, loglevel);
                    match ret {
                        qpl_rs::quote3_error_t::SGX_QL_SUCCESS => tee_att_error_t::TEE_ATT_SUCCESS,
                        _ => tee_att_error_t::TEE_ATT_PLATFORM_LIB_UNAVAILABLE,
                    }
                }
            }
            _ => result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" fn my_logging_callback(
        level: tee_qpl_log_level,
        message: *const ::std::os::raw::c_char,
    ) {
        let msg_str = std::ffi::CStr::from_ptr(message).to_str().unwrap();
        println!("level {level}: {:?}", msg_str);
    }

    #[test]
    fn it_works() {
        let result = tee_att_create_context(None, None);
        let context = match result {
            Ok(c) => {
                println!("tee_att_create_context Success");
                c
            }
            Err(_e) => panic!("tee_att_create_context failed"),
        };
        let result = unsafe { tee_att_get_keyid(context) };
        let _key_id = match result {
            Ok(k) => {
                println!("tee_att_get_keyid Success");
                k
            }
            Err(_e) => panic!("tee_att_get_keyid failed"),
        };
        let result = unsafe { tee_att_set_path(context, 0, "/lib64/libsgx_tdqe.signed.so.1") };
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => println!("tee_att_set_path Success"),
            _ => println!("tee_att_set_path failed"),
        }
        let cb: tee_qpl_logging_callback = Some(my_logging_callback);
        let result = unsafe { tee_att_set_logging_callback(context, cb, 1) };
        match result {
            tee_att_error_t::TEE_ATT_SUCCESS => println!("tee_att_set_logging_callback Success"),
            _ => println!("tee_att_set_logging_callback failed"),
        };
        let result = unsafe { tee_att_init_quote(context, false) };
        let (_pub_key, _qe_target_info) = match result {
            Ok((p, t)) => {
                println!("tee_att_init_quote Success");
                (p, t)
            }
            Err(_e) => panic!("tee_att_init_quote failed"),
        };
        let result = unsafe { tee_att_get_platform_info(context) };
        let _platform_info = match result {
            Ok(p) => {
                println!("tee_att_get_platform_info Success");
                p
            }
            Err(_e) => panic!("tee_att_get_platform_info failed"),
        };

        use std::fs::File;
        use std::io::Read;

        let mut file = File::open("tdreport_for_test.dat").unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        let result = unsafe { tee_att_get_quote(context, &buffer) };
        match result {
            Ok(_q) => {
                println!("tee_att_get_quote Success");
            }
            Err(_e) => {
                println!("tee_att_get_quote should fail");
            }
        };

        let _result = unsafe { tee_att_free_context(context) };
    }
}
