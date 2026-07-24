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

#![allow(unused)]

use std::mem;
use std::ptr;
use std::time::{Duration, SystemTime};

use clap::Parser;

use intel_tee_quote_verification_rs::*;
use intel_tee_quote_verification_sys as qvl_sys;

#[cfg(debug_assertions)]
const SGX_DEBUG_FLAG: i32 = 1;
#[cfg(not(debug_assertions))]
const SGX_DEBUG_FLAG: i32 = 0;

// C library bindings

#[cfg(not(feature = "TD_ENV"))]
#[link(name = "sgx_urts")]
extern "C" {
    fn sgx_create_enclave(
        file_name: *const u8,
        debug: i32,
        launch_token: *mut [u8; 1024usize],
        launch_token_updated: *mut i32,
        enclave_id: *mut u64,
        misc_attr: *mut qvl_sys::sgx_misc_attribute_t,
    ) -> u32;
    fn sgx_destroy_enclave(enclave_id: u64) -> u32;
}

#[cfg(not(feature = "TD_ENV"))]
#[link(name = "enclave_untrusted")]
extern "C" {
    fn ecall_get_target_info(
        eid: u64,
        retval: *mut u32,
        target_info: *mut qvl_sys::sgx_target_info_t,
    ) -> u32;
    fn sgx_tvl_verify_qve_report_and_identity(
        eid: u64,
        retval: *mut quote3_error_t,
        p_quote: *const u8,
        quote_size: u32,
        p_qve_report_info: *const sgx_ql_qe_report_info_t,
        expiration_check_date: i64,
        collateral_expiration_status: u32,
        quote_verification_result: sgx_ql_qv_result_t,
        p_supplemental_data: *const u8,
        supplemental_data_size: u32,
        qve_isvsvn_threshold: qvl_sys::sgx_isv_svn_t,
    ) -> u32;
}

/// Quote verification with QvE/QVL
///
/// # Param
/// - **quote**\
/// ECDSA quote buffer.
/// - **use_qve**\
/// Set quote verification mode.\
///     - If true, quote verification will be performed by Intel QvE.
///     - If false, quote verification will be performed by untrusted QVL.
///
fn ecdsa_quote_verification(quote: &[u8], use_qve: bool) {
    let mut collateral_expiration_status = 1u32;
    let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;

    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    if use_qve {
#[cfg(not(feature = "TD_ENV"))]
{

        // Trusted quote verification

        let rand_nonce = "59jslk201fgjmm;\0";
        let mut qve_report_info: sgx_ql_qe_report_info_t = Default::default();

        // set nonce
        //
        qve_report_info
            .nonce
            .rand
            .copy_from_slice(rand_nonce.as_bytes());

        // get target info of SampleISVEnclave. QvE will target the generated report to this enclave
        //
        let sample_isv_enclave = "../QuoteVerificationSample/enclave.signed.so\0";
        let mut token = [0u8; 1024usize];
        let mut updated = 0i32;
        let mut eid: u64 = 0;
        let sgx_ret = unsafe {
            sgx_create_enclave(
                sample_isv_enclave.as_ptr(),
                SGX_DEBUG_FLAG,
                &mut token,
                &mut updated,
                &mut eid,
                ptr::null_mut(),
            )
        };
        if sgx_ret != 0 {
            println!("\tError: Can't load SampleISVEnclave: {:#04x}", sgx_ret);
            return;
        }
        let mut get_target_info_ret = 0x0001u32; // SGX_ERROR_UNEXPECTED
        let mut tmp_target_info: qvl_sys::sgx_target_info_t = Default::default();
        let sgx_ret =
            unsafe { ecall_get_target_info(eid, &mut get_target_info_ret, &mut tmp_target_info) };
        if sgx_ret != 0 || get_target_info_ret != 0 {
            println!(
                "\tError in sgx_get_target_info. {:#04x}",
                get_target_info_ret
            );
        } else {
            println!("\tInfo: get target info successfully returned.");
            let unaligned = ptr::addr_of_mut!(qve_report_info.app_enclave_target_info);
            unsafe { ptr::write_unaligned(unaligned, tmp_target_info) };
        }

        // call DCAP quote verify library to set QvE loading policy
        //
        match sgx_qv_set_enclave_load_policy(sgx_ql_request_policy_t::SGX_QL_DEFAULT) {
            quote3_error_t::SGX_QL_SUCCESS => {
                println!("\tInfo: sgx_qv_set_enclave_load_policy successfully returned.")
            }
            err => println!(
                "\tError: sgx_qv_set_enclave_load_policy failed: {:#04x}",
                err.0
            ),
        }

        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        //
        match tee_get_supplemental_data_version_and_size(quote) {
            Ok((supp_ver, supp_size)) => {
                if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                    println!("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.");
                    println!("\tInfo: latest supplemental data major version: {}, minor version: {}, size: {}",
                        u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into().unwrap()),
                        u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into().unwrap()),
                        supp_size,
                    );
                    supp_data_desc.data_size = supp_size;
                } else {
                    println!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
                }
            }
            Err(e) => println!(
                "\tError: tee_get_quote_supplemental_data_size failed: {:#04x}",
                e.0
            ),
        }

        // get collateral
        let collateral = tee_qv_get_collateral(quote);
        match collateral {
            Ok(ref c) => println!("\tInfo: tee_qv_get_collateral successfully returned."),
            Err(e) => println!("\tError: tee_qv_get_collateral failed: {:#04x}", e.0),
        };

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        let p_supplemental_data = match supp_data_desc.data_size {
            0 => None,
            _ => Some(&mut supp_data_desc),
        };

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        // SAFETY: `supp_data_desc.p_data` points at a stack-allocated
        // `sgx_ql_qv_supplemental_t` that outlives the call and is not aliased.
        match unsafe { tee_verify_quote(
            quote,
            collateral.ok().as_ref(),
            current_time,
            Some(&mut qve_report_info),
            p_supplemental_data,
        ) } {
            Ok((colla_exp_stat, qv_result)) => {
                collateral_expiration_status = colla_exp_stat;
                quote_verification_result = qv_result;
                println!("\tInfo: App: tee_verify_quote successfully returned.");
            }
            Err(e) => println!("\tError: App: tee_verify_quote failed: {:#04x}", e.0),
        }

        // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
        // e.g. You can check latest QvE ISVSVN from QvE configuration file on Github
        // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Enclave/linux/config.xml#L4
        // or you can get latest QvE ISVSVN in QvE Identity JSON file from
        // https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity
        // Make sure you are using trusted & latest QvE ISV SVN as threshold
        // Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
        //
        let qve_isvsvn_threshold: qvl_sys::sgx_isv_svn_t = 7;

        let p_supplemental_data = match supp_data_desc.data_size {
            0 => ptr::null(),
            _ => supp_data_desc.p_data,
        };

        // call sgx_dcap_tvl API in SampleISVEnclave to verify QvE's report and identity
        //
        let mut verify_qveid_ret = quote3_error_t::SGX_QL_ERROR_UNEXPECTED;
        let sgx_ret = unsafe {
            sgx_tvl_verify_qve_report_and_identity(
                eid,
                &mut verify_qveid_ret,
                quote.as_ptr(),
                quote.len() as u32,
                &qve_report_info,
                current_time,
                collateral_expiration_status,
                quote_verification_result,
                p_supplemental_data,
                supp_data_desc.data_size,
                qve_isvsvn_threshold,
            )
        };
        if sgx_ret != 0 || verify_qveid_ret != quote3_error_t::SGX_QL_SUCCESS {
            println!(
                "\tError: Ecall: Verify QvE report and identity failed. {:#04x}",
                verify_qveid_ret.0
            );
        } else {
            println!("\tInfo: Ecall: Verify QvE report and identity successfully returned.")
        }

        unsafe { sgx_destroy_enclave(eid) };

}
    } else {
        // Untrusted quote verification

        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        //
        match tee_get_supplemental_data_version_and_size(quote) {
            Ok((supp_ver, supp_size)) => {
                if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                    println!("\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.");
                    println!("\tInfo: latest supplemental data major version: {}, minor version: {}, size: {}",
                        u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into().unwrap()),
                        u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into().unwrap()),
                        supp_size,
                    );
                    supp_data_desc.data_size = supp_size;
                } else {
                    println!("\tWarning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
                }
            }
            Err(e) => println!(
                "\tError: tee_get_quote_supplemental_data_size failed: {:#04x}",
                e.0
            ),
        }

        // get collateral
        let collateral = tee_qv_get_collateral(quote);
        match collateral {
            Ok(ref c) => println!("\tInfo: tee_qv_get_collateral successfully returned."),
            Err(e) => println!("\tError: tee_qv_get_collateral failed: {:#04x}", e.0),
        };

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        let current_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs() as i64;

        let p_supplemental_data = match supp_data_desc.data_size {
            0 => None,
            _ => Some(&mut supp_data_desc),
        };

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        // SAFETY: `supp_data_desc.p_data` points at a stack-allocated
        // `sgx_ql_qv_supplemental_t` that outlives the call and is not aliased.
        match unsafe { tee_verify_quote(
            quote,
            collateral.ok().as_ref(),
            current_time,
            None,
            p_supplemental_data,
        ) } {
            Ok((colla_exp_stat, qv_result)) => {
                collateral_expiration_status = colla_exp_stat;
                quote_verification_result = qv_result;
                println!("\tInfo: App: tee_verify_quote successfully returned.");
            }
            Err(e) => println!("\tError: App: tee_verify_quote failed: {:#04x}", e.0),
        }
    }

    // check verification result
    //
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if collateral_expiration_status == 0 {
                println!("\tInfo: App: Verification completed successfully.");
            } else {
                println!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!(
                "\tWarning: App: Verification completed with Non-terminal result: {:x}",
                quote_verification_result.0
            );
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            println!(
                "\tError: App: Verification completed with Terminal result: {:x}",
                quote_verification_result.0
            );
        }
    }

    // check supplemental data if necessary
    //
    if supp_data_desc.data_size > 0 {
        // you can check supplemental data based on your own attestation/verification policy
        // here we only print supplemental data version for demo usage
        //
        let version_s = unsafe { supp_data.__bindgen_anon_1.__bindgen_anon_1 };
        println!(
            "\tInfo: Supplemental data Major Version: {}",
            version_s.major_version
        );
        println!(
            "\tInfo: Supplemental data Minor Version: {}",
            version_s.minor_version
        );

        // print SA list if exist, SA list is supported from version 3.1
        //
        if unsafe { supp_data.__bindgen_anon_1.version } > 3 {
            let sa_list = unsafe { std::ffi::CStr::from_ptr(supp_data.sa_list.as_ptr()) };
            if sa_list.to_bytes().len() > 0 {
                println!("\tInfo: Advisory ID: {}", sa_list.to_str().unwrap());
            }
        }
    }
}

#[derive(Parser)]
struct Cli {
    /// Specify quote path
    #[arg(long = "quote")]
    quote_path: Option<String>,
}

fn main() {
    // Specify quote path from command line arguments
    //
    let args = Cli::parse();
    let default_quote = "../QuoteGenerationSample/quote.dat";
    let quote_path = args.quote_path.as_deref().unwrap_or(default_quote);

    //read quote from file
    //
    let quote = std::fs::read(quote_path).expect("Error: Unable to open quote file");

    println!("Info: ECDSA quote path: {}", quote_path);

    // We demonstrate two different types of quote verification
    //      a. Trusted quote verification - quote will be verified by Intel QvE
    //      b. Untrusted quote verification - quote will be verified by untrusted QVL (Quote Verification Library)
    //          this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    //

    #[cfg(not(feature = "TD_ENV"))]
    {
        // Trusted quote verification, ignore error checking
        //
        println!("\nTrusted quote verification:");
        ecdsa_quote_verification(&quote, true);

        println!("\n===========================================");

        // Unrusted quote verification, ignore error checking
        //
        println!("\nUntrusted quote verification:");
    }
    #[cfg(feature = "TD_ENV")]
    // Quote verification inside TD
    //
    println!("\nQuote verification inside TD, support both SGX and TDX quote:");
    ecdsa_quote_verification(&quote, false);

    println!();
}
