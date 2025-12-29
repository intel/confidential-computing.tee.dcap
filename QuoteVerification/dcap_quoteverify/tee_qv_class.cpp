/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 /**
  * File: tee_qv_class.cpp
  *
  * Description: Implementation of SGX and TDX QVL/QvE wrapper class
  */

#include "tee_qv_class.h"
#include "sgx_dcap_qv_internal.h"
#include "sgx_dcap_pcs_com.h"
#include "se_trace.h"
#include "sgx_urts_wrapper.h"

#if defined(_MSC_VER)
#include "win/qve_u.h"
#include <tchar.h>
bool get_qve_path(TCHAR *p_file_path, size_t buf_size);
#else
#include <limits.h>
#include "linux/qve_u.h"
#define MAX_PATH PATH_MAX
bool get_qve_path(char *p_file_path, size_t buf_size);

#endif

static constexpr size_t kQvePathBufferSize = MAX_PATH + 1;

extern sgx_create_enclave_func_t p_sgx_urts_create_enclave;
extern sgx_destroy_enclave_func_t p_sgx_urts_destroy_enclave;

sgx_status_t load_qve_once(sgx_enclave_id_t *p_qve_eid)
{
    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;
    int enclave_lost_retry_time = 1;
    sgx_launch_token_t token = {0};
    int updated = 0;

#if defined(_MSC_VER)
    TCHAR qve_enclave_path[kQvePathBufferSize] = _T("");
#else
    char qve_enclave_path[kQvePathBufferSize] = "";
#endif

    // Try to load urts lib first
    //
    if (!sgx_dcap_load_urts()) {
        return SGX_ERROR_FEATURE_NOT_SUPPORTED;
    }

    if (!get_qve_path(qve_enclave_path, kQvePathBufferSize)) {

        return SGX_ERROR_UNEXPECTED; //SGX_QvE_INTERFACE_UNAVAILABLE;
    }

    do
    {
        SE_TRACE(SE_TRACE_DEBUG, "Call sgx_create_enclave for QvE. %s\n", qve_enclave_path);
        if (p_sgx_urts_create_enclave) {
            sgx_status = p_sgx_urts_create_enclave(qve_enclave_path,
                0, // Don't support debug load QvE by default
                &token,
                &updated,
                p_qve_eid,
                NULL);
            if (SGX_SUCCESS != sgx_status) {
                SE_TRACE(SE_TRACE_DEBUG, "Info, call sgx_create_enclave for QvE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
            }
            else {
                break;
            }
        }
        else
            return SGX_ERROR_UNEXPECTED; //urts handle has been closed;

            // Retry in case there was a power transition that resulted is losing the enclave.
        } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
        if(sgx_status == SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info, Load QvE successfully, eid is 0x%llx\n.", *p_qve_eid);
        }

    return sgx_status;
}

sgx_status_t unload_qve_once(sgx_enclave_id_t *p_qve_eid)
{
    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;

    // Try to load urts lib first
    //
    if (!sgx_dcap_load_urts()) {
        SE_TRACE(SE_TRACE_ERROR, "Error, failed to load SGX uRTS library\n");
        return sgx_status;
    }

    if (*p_qve_eid != 0) {
        SE_TRACE(SE_TRACE_DEBUG, "unload qve enclave 0x%llx\n", *p_qve_eid);
        if (p_sgx_urts_destroy_enclave) {
            sgx_status = p_sgx_urts_destroy_enclave(*p_qve_eid);
        }
        *p_qve_eid = 0;
    }

    return sgx_status;
}


//SGX untrusted quote verification
//
quote3_error_t sgx_qv::tee_verify_evidence(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data) {

    return sgx_qvl_verify_quote(
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
}

#ifndef _MSC_VER
quote3_error_t sgx_qv::tee_get_verify_token(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t current_time,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    uint32_t *verification_result_token_buffer_size,
    uint8_t **p_verification_result_token) {

    return tee_qvl_verify_quote_qvt(
        p_quote,
        quote_size,
        current_time,
        p_quote_collateral,
        p_qve_report_info,
        p_user_data,
        user_data_size,
        verification_result_token_buffer_size,
        p_verification_result_token);
}
#endif

quote3_error_t sgx_qv::tee_get_supplemental_data_size(uint32_t *p_data_size)
{
    return sgx_qvl_get_quote_supplemental_data_size(p_data_size);
}

quote3_error_t sgx_qv::tee_get_supplemental_data_version(uint32_t *p_version)
{
    return sgx_qvl_get_quote_supplemental_data_version(p_version);
}

quote3_error_t sgx_qv::tee_get_fmspc_ca_from_quote(
    const uint8_t* p_quote,
    uint32_t quote_size,
    unsigned char* p_fmsp_from_quote,
    uint32_t fmsp_from_quote_size,
    unsigned char* p_ca_from_quote,
    uint32_t ca_from_quote_size) {

    return qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        p_fmsp_from_quote,
        fmsp_from_quote_size,
        p_ca_from_quote,
        ca_from_quote_size);
}

quote3_error_t sgx_qv::tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        sgx_ql_qve_collateral_t **pp_quote_collateral) {

    return sgx_dcap_retrieve_verification_collateral(
        fmspc,
        fmspc_size,
        pck_ca,
        pp_quote_collateral);
}

quote3_error_t sgx_qv::tee_free_verification_endorsement(
    sgx_ql_qve_collateral_t *p_quote_collateral) {

    return sgx_dcap_free_verification_collateral(p_quote_collateral);
}

quote3_error_t sgx_qv::tee_get_qve_identity(
    uint8_t **pp_qveid,
    uint32_t *p_qveid_size,
    uint8_t **pp_qveid_issue_chain,
    uint32_t *p_qveid_issue_chain_size,
    uint8_t **pp_root_ca_crl,
    uint16_t *p_root_ca_crl_size) {

    return sgx_dcap_retrieve_qve_identity(
        pp_qveid,
        p_qveid_size,
        pp_qveid_issue_chain,
        p_qveid_issue_chain_size,
        pp_root_ca_crl,
        p_root_ca_crl_size);
}

quote3_error_t sgx_qv::tee_free_qve_identity(
    uint8_t *p_qveid,
    uint8_t *p_qveid_issue_chain,
    uint8_t *p_root_ca_crl) {

    return sgx_dcap_free_qve_identity(
        p_qveid,
        p_qveid_issue_chain,
        p_root_ca_crl);
}


//SGX trusted quote verification
//
quote3_error_t sgx_qv_trusted::tee_verify_evidence(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t qv_ret = SGX_QL_ERROR_UNEXPECTED;

    if (m_qve_id == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    ret = sgx_qve_verify_quote(
        m_qve_id,
        &qv_ret,
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);

    if (qv_ret == SGX_QL_SUCCESS && ret == SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_qve_verify_quote successfully returned.\n");
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_qve_verify_quote failed. ecall return 0x%04x, \
            function return 0x%04x\n", ret, qv_ret);
    }

    return qv_ret;
}

#ifndef _MSC_VER
quote3_error_t sgx_qv_trusted::tee_get_verify_token(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t current_time,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t user_data_size,
    uint32_t *verification_result_token_buffer_size,
    uint8_t **p_verification_result_token) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t qv_ret = SGX_QL_ERROR_UNEXPECTED;

    if (m_qve_id == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    ret = tee_qve_verify_quote_qvt(
        m_qve_id,
        &qv_ret,
        p_quote,
        quote_size,
        current_time,
        p_quote_collateral,
        p_qve_report_info,
        p_user_data,
        user_data_size,
        verification_result_token_buffer_size,
        p_verification_result_token);

    if (qv_ret == SGX_QL_SUCCESS && ret == SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: tee_qve_verify_quote_qvt successfully returned.\n");
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Error: tee_qve_verify_quote_qvt failed. ecall return 0x%04x, \
            function return 0x%04x\n", ret, qv_ret);
    }

    return qv_ret;
}
#endif

quote3_error_t sgx_qv_trusted::tee_get_supplemental_data_size(uint32_t *p_data_size)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t qv_ret = SGX_QL_ERROR_UNEXPECTED;

    if (m_qve_id == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    ret = sgx_qve_get_quote_supplemental_data_size(
        m_qve_id,
        &qv_ret,
        p_data_size);

    if (qv_ret == SGX_QL_SUCCESS && ret == SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_qve_get_quote_supplemental_data_size successfully returned.\n");
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_qve_get_quote_supplemental_data_size failed. ecall return 0x%04x, \
            function return 0x%04x\n", ret, qv_ret);
    }

    return qv_ret;
}

quote3_error_t sgx_qv_trusted::tee_get_supplemental_data_version(uint32_t *p_version)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t qv_ret = SGX_QL_ERROR_UNEXPECTED;

    if (m_qve_id == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    ret = sgx_qve_get_quote_supplemental_data_version(
        m_qve_id,
        &qv_ret,
        p_version);

    if (qv_ret == SGX_QL_SUCCESS && ret == SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: sgx_qve_get_quote_supplemental_data_version successfully returned.\n");
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Error: sgx_qve_get_quote_supplemental_data_version failed. ecall return 0x%04x, \
            function return 0x%04x\n", ret, qv_ret);
    }

    return qv_ret;
}

quote3_error_t sgx_qv_trusted::tee_get_fmspc_ca_from_quote(
    const uint8_t* p_quote,
    uint32_t quote_size,
    unsigned char* p_fmsp_from_quote,
    uint32_t fmsp_from_quote_size,
    unsigned char* p_ca_from_quote,
    uint32_t ca_from_quote_size) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    quote3_error_t qv_ret = SGX_QL_ERROR_UNEXPECTED;

    if (m_qve_id == 0)
        return SGX_QL_ERROR_UNEXPECTED;

    ret = get_fmspc_ca_from_quote(
        m_qve_id,
        &qv_ret,
        p_quote,
        quote_size,
        p_fmsp_from_quote,
        fmsp_from_quote_size,
        p_ca_from_quote,
        ca_from_quote_size);

    if (qv_ret == SGX_QL_SUCCESS && ret == SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
    }
    else {
        SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed. ecall return 0x%04x, \
            function return 0x%04x\n", ret, qv_ret);
    }

    return qv_ret;
}

sgx_status_t sgx_qv_trusted::load_qve() {

    sgx_status_t ret = SGX_SUCCESS;

    if (m_qve_id == 0) {
      ret = load_qve_once(&m_qve_id);

      if (ret != SGX_SUCCESS) {
        SE_TRACE(SE_TRACE_ERROR, "Error: Load QvE failed with error 0x%08x.\n", ret);
        m_qve_id = 0;
      }
    }

    return ret;
}

sgx_status_t sgx_qv_trusted::unload_qve()
{
    sgx_status_t ret = SGX_SUCCESS;

    if (m_qve_id != 0) {
        ret = unload_qve_once(&m_qve_id);
        m_qve_id = 0;

        if (ret != SGX_SUCCESS) {
            SE_TRACE(SE_TRACE_ERROR, "Error: Unooad QvE failed with error 0x%08x.\n", ret);
        }
    }

    return ret;
}

void sgx_qv_trusted::set_eid(sgx_enclave_id_t eid)
{
    m_qve_id = eid;
}

sgx_qv_trusted::~sgx_qv_trusted()
{
    //Only unload QvE when use multi-thread PERSISTENT here
    //the thread local object will guarantee destructor will only called before thread exit
    //legacy PERSISTENT need to unload QvE manually, we will do it before unloading library
    //
    if (g_qve_policy == SGX_QL_PERSISTENT_QVE_MULTI_THREAD) {
        unload_qve();
    }
}

quote3_error_t tdx_qv::tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral) {

    return tdx_dcap_retrieve_verification_collateral(
        fmspc,
        fmspc_size,
        pck_ca,
        pp_quote_collateral);
}

quote3_error_t tdx_qv::tee_free_verification_endorsement(
    sgx_ql_qve_collateral_t *p_quote_collateral) {

    return tdx_dcap_free_verification_collateral(p_quote_collateral);
}

//TDX trusted quote verification
//
quote3_error_t tdx_qv_trusted::tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral) {

    return tdx_dcap_retrieve_verification_collateral(
        fmspc,
        fmspc_size,
        pck_ca,
        pp_quote_collateral);
}

quote3_error_t tdx_qv_trusted::tee_free_verification_endorsement(
    sgx_ql_qve_collateral_t *p_quote_collateral) {

    return tdx_dcap_free_verification_collateral(p_quote_collateral);
}
