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
 /**
  * File: sgx_dcap_quoteverify.cpp
  *
  * Description: Quote Verification Library
  */

#include "sgx_dcap_quoteverify.h"
#include "sgx_dcap_pcs_com.h"
#include "sgx_dcap_qv_internal.h"
#include "sgx_qve_def.h"
#include "tee_qv_class.h"
#include <stdlib.h>
#include <stdio.h>
#include <new>
#include <memory>
#include <mutex>
#include "se_trace.h"
#include "se_thread.h"
#include "se_memcpy.h"
#include "sgx_urts_wrapper.h"
#include <functional>

thread_local std::shared_ptr<tee_qv_base> p_tee_qv = NULL;
std::shared_ptr<tee_qv_base> global_tee_qv = NULL;
sgx_enclave_id_t g_qve_eid = 0;
std::mutex qve_mutex;

// Default policy is SGX_QL_EPHEMERAL, which is same with legacy DCAP QVL behavior
//
std::atomic<sgx_ql_request_policy_t> g_qve_policy(SGX_QL_EPHEMERAL);
std::atomic<bool> policy_set_once(false);

thread_local tee_class_type_t current_class_type = CLASS_SGX_QVL;

static quote3_error_t sgx_error_to_quote3_error(sgx_status_t err)
{
    switch (err)
    {
    case SGX_SUCCESS:
        return SGX_QL_SUCCESS;
    case SGX_ERROR_OUT_OF_EPC:
        return SGX_QL_OUT_OF_EPC;
    case SGX_ERROR_OUT_OF_MEMORY:
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    case SGX_ERROR_INVALID_PARAMETER:
        return SGX_QL_ERROR_INVALID_PARAMETER;
    default:
        return SGX_QL_ERROR_UNEXPECTED;
    }
}

std::unique_ptr<tee_qv_base> create_instance(tee_class_type_t type)
{
    switch(type) {
        case CLASS_SGX_QVL:
            return std::make_unique<sgx_qv>();

        case CLASS_SGX_QVE:
            return std::make_unique<sgx_qv_trusted>();

        case CLASS_TDX_QVL:
            return std::make_unique<tdx_qv>();

        case CLASS_TDX_QVE:
            return std::make_unique<tdx_qv_trusted>();

        default:
            return nullptr;
    }
}

/**
 * Internal function - get supplemental data size and version.
 **/
static quote3_error_t get_verification_supplemental_data_size_and_version(
    uint32_t *p_data_size,
    uint32_t *p_version) {

    if (NULL_POINTER(p_data_size)) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    supp_ver_t untrusted_version;
    untrusted_version.version = 0;
    uint32_t untrusted_size = 0;
    quote3_error_t qve_ret = SGX_QL_ERROR_INVALID_PARAMETER;

    do {
        //call untrusted API to get supplemental data version
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_version(&untrusted_version.version);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_version failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        //call untrusted API to get supplemental data size
        //
        qve_ret = sgx_qvl_get_quote_supplemental_data_size(&untrusted_size);
        if (qve_ret != SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Error: untrusted API qvl_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
            *p_data_size = 0;
            break;
        }

        if (p_data_size != NULL)
            *p_data_size = untrusted_size;
        if (p_version != NULL)
            *p_version = untrusted_version.version;

    } while (0) ;

    return qve_ret;
}

quote3_error_t sgx_qv_set_enclave_load_policy(
    sgx_ql_request_policy_t policy)
{
    std::lock_guard<std::mutex> lock(qve_mutex);

    if (policy < SGX_QL_PERSISTENT || policy > SGX_QL_PERSISTENT_QVE_MULTI_THREAD)
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;

    if (policy_set_once) {
        SE_TRACE(SE_TRACE_ERROR, "Err: QvE load policy has already been set once in current process.\n");
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;
    }

    g_qve_policy = policy;
    policy_set_once = true;

    return SGX_QL_SUCCESS;
}

/**
 * Get supplemental data latest version and required size.
 **/
quote3_error_t tee_get_supplemental_data_version_and_size(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint32_t *p_version,
    uint32_t *p_data_size) {

    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE ||
        (p_version == NULL && p_data_size == NULL))
        return SGX_QL_ERROR_INVALID_PARAMETER;

    return get_verification_supplemental_data_size_and_version(p_data_size, p_version);
}

void unload_persistent_qve()
{
    //Try to unload QvE only when use legacy PERSISTENT policy
    //All the threads will share single QvE instance in this mode
    //
    if (g_qve_policy == SGX_QL_PERSISTENT) {
        if (g_qve_eid != 0) {
            //ignore the return error
            unload_qve_once(&g_qve_eid);
            g_qve_eid = 0;
        }
    }
}

static quote3_error_t tee_verify_evidence_internal(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data,
    std::shared_ptr<tee_qv_base> p_qv)
{

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;

    if (!p_qv)
        return SGX_QL_ERROR_UNEXPECTED;

    do {
        //try to load QvE if user wants to use trusted quote verification
        //
        if (current_class_type == CLASS_SGX_QVE || current_class_type == CLASS_TDX_QVE) {
            if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

                if (g_qve_eid == 0) {
                    sgx_ret = load_qve_once(&g_qve_eid);

                    if (g_qve_policy == SGX_QL_PERSISTENT) {
                        //register the termination function
                        //only used for QvE persistent mode
                        //Don't treat the atexit error as critical error, because it will not block any functionality
                        if (0 != (atexit(unload_persistent_qve))) {
                            SE_TRACE(SE_TRACE_ERROR, "Err: Register 'unload_persistent_qve' failed.\n");
                        }
                    }
                }

                p_qv->set_eid(g_qve_eid);
            }

            //Only legacy mode share single QvE in multi-threads, other modes load QvE per thread
            //
            else {
                sgx_ret = p_qv->load_qve();
            }

            if (sgx_ret != SGX_SUCCESS) {
                qve_ret = sgx_error_to_quote3_error(sgx_ret);
                break;
            }
        }

        //validate supplemental data size if using QvE
        //
        if (p_supplemental_data && p_qve_report_info) {
            quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
            uint32_t tmp_size = 0;

            //supplemental size from QvE
            tmp_ret = p_qv->tee_get_supplemental_data_size(&tmp_size);

            if (tmp_ret != SGX_QL_SUCCESS) {

                if (p_quote_verification_result) {
                    *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
                }

                qve_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }

            if (tmp_size != supplemental_data_size) {
                if (p_quote_verification_result) {
                    *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
                }

                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                break;
            }
        }

        //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
        //
        if (NULL_POINTER(p_quote_collateral)) {

            //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
            //
            qve_ret = p_qv->tee_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                break;
            }

            //retrieve verification collateral using QPL
            //
            qve_ret = p_qv->tee_get_verification_endorsement(
                (const char *)fmspc_from_quote,
                FMSPC_SIZE,
                (const char *)ca_from_quote,
                &qve_collaterals_from_qp);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: dcap_retrieve_verification_collateral successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                break;
            }
            p_quote_collateral = qve_collaterals_from_qp;
        }

        qve_ret = p_qv->tee_verify_evidence(
            p_quote, quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data);
        if (qve_ret == SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: verify_quote successfully returned.\n");
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: verify_quote failed: 0x%04x\n", qve_ret);
            break;
        }

    } while (0);

    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        p_qv->tee_free_verification_endorsement(qve_collaterals_from_qp);
    }

    //unload QvE if set policy to ephemeral
    //
    if (g_qve_policy == SGX_QL_EPHEMERAL ||
        g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD) {

        sgx_ret = p_qv->unload_qve();
        g_qve_eid = 0;

        if (sgx_ret != SGX_SUCCESS) {
            qve_ret = sgx_error_to_quote3_error(sgx_ret);
        }
    }

    return qve_ret;
}

/**
 * Perform ECDSA quote verification
 **/
quote3_error_t tee_verify_evidence(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data) {

    //validate input parameters
    //
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE ||
        NULL_POINTER(p_collateral_expiration_status) ||
        expiration_check_date == 0 ||
        NULL_POINTER(p_quote_verification_result) ||
        CHECK_OPT_PARAMS(p_supplemental_data, supplemental_data_size)) {
        //one or more invalid parameters
        //
        if (p_quote_verification_result) {
            *p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
        }
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    //check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - SGX quote.\n");
        tee_type = SGX_EVIDENCE;
    }
    else if (*p_type == TDX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - TDX quote.\n");
        tee_type = TDX_EVIDENCE;
    }
    else {
        SE_TRACE(SE_TRACE_ERROR, "Err: Unsupported quote type.\n");
        //quote type is not supported
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    tee_class_type_t class_type = CLASS_SGX_QVL;

    if (p_qve_report_info) {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVE;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVE;
    }

    //untrsuted quote verification
    //
    else {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVL;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVL;
    }

    if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

        std::lock_guard<std::mutex> lock(qve_mutex);

        if (global_tee_qv && class_type != current_class_type) {
            //reset the object if the type change in next thread
            global_tee_qv.reset();
            global_tee_qv = NULL;

            SE_TRACE(SE_TRACE_DEBUG, "Info: Reset global tee qve instance.\n");
        }

        if (!global_tee_qv) {
            global_tee_qv = create_instance(class_type);
            if (global_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_evidence_internal(
            p_quote,
            quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
            global_tee_qv);
    }

    else if (g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD || g_qve_policy == SGX_QL_PERSISTENT_QVE_MULTI_THREAD) {

        if (p_tee_qv && class_type != current_class_type) {
            //reset the object if the type change in next thread
            //
            p_tee_qv.reset();
        }

        if (!p_tee_qv) {
            p_tee_qv = create_instance(class_type);
            if (p_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_evidence_internal(
            p_quote,
            quote_size,
            p_quote_collateral,
            expiration_check_date,
            p_collateral_expiration_status,
            p_quote_verification_result,
            p_qve_report_info,
            supplemental_data_size,
            p_supplemental_data,
            p_tee_qv);
    }

    else {
        //invalid policy
        //
        qve_ret = SGX_QL_UNSUPPORTED_LOADING_POLICY;
        goto end;
    }

end:
    return qve_ret;
}

/**
 * Get SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_get_qve_identity(
         uint8_t **pp_qveid,
         uint32_t *p_qveid_size,
         uint8_t **pp_qveid_issue_chain,
         uint32_t *p_qveid_issue_chain_size,
         uint8_t **pp_root_ca_crl,
         uint16_t *p_root_ca_crl_size) {

    return sgx_dcap_retrieve_qve_identity(pp_qveid,
                                          p_qveid_size,
                                          pp_qveid_issue_chain,
                                          p_qveid_issue_chain_size,
                                          pp_root_ca_crl,
                                          p_root_ca_crl_size);
}


/**
 * Free SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_free_qve_identity(
        uint8_t *p_qveid,
        uint8_t *p_qveid_issue_chain,
        uint8_t *p_root_ca_crl) {

    return sgx_dcap_free_qve_identity(p_qveid,
                                      p_qveid_issue_chain,
                                      p_root_ca_crl);
}

/**
 * Get SGX supplemental data required size.
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL);
}

/**
 * Perform SGX ECDSA quote verification
 **/
quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    quote3_error_t ret = SGX_QL_SUCCESS;

    // set supplemental version if necessary
    if (p_supplemental_data != NULL && supplemental_data_size >= sizeof(sgx_ql_qv_supplemental_t)) {
        try {
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supplemental_data)->version = SUPPLEMENTAL_DATA_VERSION;
        }

        catch(...) {
            // cannot access p_supplemental_data field
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    ret = tee_verify_evidence(
        p_quote,
        quote_size,
        p_quote_collateral,
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);

    // clear version info
    if (ret != SGX_QL_SUCCESS && p_supplemental_data != NULL) {
        memset(p_supplemental_data, 0, supplemental_data_size);
    }

    return ret;
}

/**
 * Get TDX supplemental data required size.
 **/
quote3_error_t tdx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size)
{
    return get_verification_supplemental_data_size_and_version(p_data_size, NULL);
}

/**
 * Perform TDX ECDSA quote verification
 **/
quote3_error_t tdx_qv_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const tdx_ql_qv_collateral_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    uint32_t supplemental_data_size,
    uint8_t *p_supplemental_data)
{
    quote3_error_t ret = SGX_QL_SUCCESS;

    // set supplemental version if necessary
    if (p_supplemental_data != NULL && supplemental_data_size >= sizeof(sgx_ql_qv_supplemental_t)) {
        try {
            reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supplemental_data)->version = SUPPLEMENTAL_DATA_VERSION;
        }

        catch(...) {
            // cannot access p_supplemental_data field
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    ret = tee_verify_evidence(
       p_quote,
       quote_size,
       p_quote_collateral,
       expiration_check_date,
       p_collateral_expiration_status,
       p_quote_verification_result,
       p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);

    // clear version info
    if (ret != SGX_QL_SUCCESS && p_supplemental_data != NULL) {
        memset(p_supplemental_data, 0, supplemental_data_size);
    }

    return ret;
}


/**
 * @brief retrieve verification colloateral
 *
 */
quote3_error_t tee_qv_get_collateral(
    const uint8_t *p_quote,
    uint32_t quote_size,
    uint8_t **pp_quote_collateral,
    uint32_t *p_collateral_size)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = {0};
    unsigned char ca_from_quote[CA_SIZE] = {0};
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
         quote_size < QUOTE_MIN_SIZE ||
         pp_quote_collateral == NULL ||
         *pp_quote_collateral != NULL ||
         p_collateral_size == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;
    // skip version and att_key_type in SGX or TDX quote
    uint32_t quote_type = *((uint32_t *)(p_quote + sizeof(uint16_t) + sizeof(uint16_t)));
    *p_collateral_size = 0;

    ret = qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
    if (ret != SGX_QL_SUCCESS)
    {
        return ret;
    }
    if (quote_type == SGX_QUOTE_TYPE)
    { // little endian 0x0 means SGX
        ret = sgx_dcap_retrieve_verification_collateral((const char *)fmspc_from_quote,
                                                        FMSPC_SIZE,
                                                        (const char *)ca_from_quote,
                                                        (sgx_ql_qve_collateral_t **)pp_quote_collateral);
        if (ret == SGX_QL_SUCCESS)
        {
		 *p_collateral_size =
                (uint32_t)sizeof(sgx_ql_qve_collateral_t) +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->root_ca_crl_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_issuer_chain_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_size +
                ((sgx_ql_qve_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_size;
	    }
    }
    else if (quote_type == TDX_QUOTE_TYPE)
    { // little endian 0x81 means TDX
        ret = tdx_dcap_retrieve_verification_collateral((const char *)fmspc_from_quote,
                                                        FMSPC_SIZE,
                                                        (const char *)ca_from_quote,
                                                        (tdx_ql_qv_collateral_t **)pp_quote_collateral);
        if (ret == SGX_QL_SUCCESS)
        {
		 *p_collateral_size =
                (uint32_t)sizeof(tdx_ql_qv_collateral_t) +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->root_ca_crl_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->pck_crl_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_issuer_chain_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->qe_identity_size +
                ((tdx_ql_qv_collateral_t *)(*pp_quote_collateral))
                    ->tcb_info_size;
	    }
    }
    else
    {
        // quote type is not supported
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
    }

    return ret;
}


/**
 * @brief free verification colloateral
 *
 */
quote3_error_t tee_qv_free_collateral(uint8_t *p_quote_collateral)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    if (p_quote_collateral == NULL)

        return SGX_QL_ERROR_INVALID_PARAMETER;

    const sgx_ql_qve_collateral_t *p_collater =
        reinterpret_cast<const sgx_ql_qve_collateral_t *>(p_quote_collateral);
    if (p_collater->tee_type == SGX_QUOTE_TYPE)
    {
        ret = sgx_dcap_free_verification_collateral((sgx_ql_qve_collateral_t *)p_quote_collateral);
    }
    else if (p_collater->tee_type == TDX_QUOTE_TYPE)
    {
        ret = tdx_dcap_free_verification_collateral((tdx_ql_qv_collateral_t *)p_quote_collateral);
    }
    else
    {
        // quote type is not supported
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
    }
    return ret;
}


/**
 * Perform quote verification for SGX and TDX
 * This API works the same as the old one, but takes a new parameter to describe the supplemental data (p_supp_data_descriptor)
 **/
quote3_error_t tee_verify_quote(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const uint8_t *p_quote_collateral,
    const time_t expiration_check_date,
    uint32_t *p_collateral_expiration_status,
    sgx_ql_qv_result_t *p_quote_verification_result,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    tee_supp_data_descriptor_t *p_supp_data_descriptor)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    supp_ver_t latest_version;
    uint32_t supp_data_size = 0;
    uint32_t tmp_size = 0;
    uint8_t *p_supp_data = NULL;

    // only check quote, other parameters will be checked in internal functions
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
         quote_size < QUOTE_MIN_SIZE)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    ret = tee_get_supplemental_data_version_and_size(p_quote, quote_size, &latest_version.version, &tmp_size);

    if (ret != SGX_QL_SUCCESS)
        return ret;

    try {
        // check supplemental descriptor
        if (p_supp_data_descriptor != NULL) {

            if (p_supp_data_descriptor->p_data == NULL)
                return SGX_QL_ERROR_INVALID_PARAMETER;

            if (p_supp_data_descriptor->major_version > latest_version.major_version)
                return SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED;

            // major version <= latest support version
            else {
                // Only support major version 0 and 3 in current stage
                if ((p_supp_data_descriptor->major_version != 0 && p_supp_data_descriptor->major_version != SUPPLEMENTAL_DATA_VERSION) ||
                        p_supp_data_descriptor->data_size != tmp_size)
                    return SGX_QL_ERROR_INVALID_PARAMETER;

                // only support version 3 by now, may add additional logic to match major version and minor version in future
                memset(p_supp_data_descriptor->p_data, 0, p_supp_data_descriptor->data_size);

                // set version in supplemental data
                reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supp_data_descriptor->p_data)->major_version = SUPPLEMENTAL_DATA_VERSION;
                reinterpret_cast<sgx_ql_qv_supplemental_t*> (p_supp_data_descriptor->p_data)->minor_version = SUPPLEMENTAL_V3_LATEST_MINOR_VERSION;

                // size will be checked in internal logic
                supp_data_size = p_supp_data_descriptor->data_size;
                p_supp_data = p_supp_data_descriptor->p_data;
            }
        }
    }

    catch (...) {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    ret = tee_verify_evidence(
        p_quote,
        quote_size,
        reinterpret_cast<const sgx_ql_qve_collateral_t*> (p_quote_collateral),
        expiration_check_date,
        p_collateral_expiration_status,
        p_quote_verification_result,
        p_qve_report_info,
        supp_data_size,
        p_supp_data);

    if (ret != SGX_QL_SUCCESS && p_supp_data_descriptor != NULL && p_supp_data_descriptor->p_data != NULL) {
        // defense in depth
        memset(p_supp_data_descriptor->p_data, 0, p_supp_data_descriptor->data_size);
    }

    return ret;
}

/**
 * @brief Extrace FMSPC from a given quote with cert type 5
 * @param p_quote[IN] - Pointer to a quote buffer.
 * @param quote_size[IN] - Size of input quote buffer.
 * @param p_fmspc_from_quote[IN/OUT] - Pointer to a buffer to write fmspc to.
 * @param fmspc_from_quote_size[IN] - Size of fmspc buffer.
 *
 * @return Status code of the operation, one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ERROR_UNEXPECTED
 *      - SGX_QL_PCK_CERT_CHAIN_ERROR
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 */
quote3_error_t tee_get_fmspc_from_quote(const uint8_t *p_quote,
                                        uint32_t quote_size,
                                        uint8_t *p_fmspc_from_quote,
                                        uint32_t fmspc_from_quote_size) {
  if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
       quote_size < QUOTE_MIN_SIZE ||
       p_fmspc_from_quote == NULL ||
       fmspc_from_quote_size < FMSPC_SIZE) {
    return SGX_QL_ERROR_INVALID_PARAMETER;
  }

  unsigned char ca_from_quote[CA_SIZE] = {0};
  return qvl_get_fmspc_ca_from_quote(
        p_quote,
        quote_size,
        p_fmspc_from_quote,
        FMSPC_SIZE,
        ca_from_quote,
        CA_SIZE);
}

#ifndef _MSC_VER
#include "qal_common.h"

static quote3_error_t tee_verify_quote_qvt_internal(
    const uint8_t *p_quote,
    uint32_t quote_size,
    time_t current_time,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    tee_supp_data_descriptor_t supp_data,
    supp_ver_t supp_ver,
    const uint8_t *p_user_data,
    uint32_t user_data_len,
    uint32_t *p_verification_result_token_buffer_size,
    uint8_t **p_verification_result_token,
    std::shared_ptr<tee_qv_base> p_qv)
{

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    unsigned char fmspc_from_quote[FMSPC_SIZE] = { 0 };
    unsigned char ca_from_quote[CA_SIZE] = { 0 };
    struct _sgx_ql_qve_collateral_t* qve_collaterals_from_qp = NULL;
    sgx_ql_qe_report_info_t tmp_report_info;
    memset(&tmp_report_info, 0, sizeof(sgx_ql_qe_report_info_t));
    

    if (!p_qv)
        return SGX_QL_ERROR_UNEXPECTED;

    do {
        //try to load QvE if user wants to use trusted quote verification
        //
        if (current_class_type == CLASS_SGX_QVE || current_class_type == CLASS_TDX_QVE) {
            if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

                if (g_qve_eid == 0) {
                    sgx_ret = load_qve_once(&g_qve_eid);

                    if (g_qve_policy == SGX_QL_PERSISTENT) {
                        //register the termination function
                        //only used for QvE persistent mode
                        //Don't treat the atexit error as critical error, because it will not block any functionality
                        if (0 != (atexit(unload_persistent_qve))) {
                            SE_TRACE(SE_TRACE_ERROR, "Err: Register 'unload_persistent_qve' failed.\n");
                        }
                    }
                }

                p_qv->set_eid(g_qve_eid);
            }

            //Only legacy mode share single QvE in multi-threads, other modes load QvE per thread
            //
            else {
                sgx_ret = p_qv->load_qve();
            }

            if (sgx_ret != SGX_SUCCESS) {
                qve_ret = sgx_error_to_quote3_error(sgx_ret);
                break;
            }
        }

        //validate supplemental data size if using QvE
        //
        if (p_qve_report_info) {
            quote3_error_t tmp_ret = SGX_QL_ERROR_UNEXPECTED;
            uint32_t tmp_size = 0;

            //supplemental size from QvE
            tmp_ret = p_qv->tee_get_supplemental_data_size(&tmp_size);

            if (tmp_ret != SGX_QL_SUCCESS) {
                qve_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }

            if (tmp_size != supp_data.data_size) {
                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Quote supplemental data size is different between QVL and QVE, please make sure you installed DCAP QVL and QvE from same release.\n");
                break;
            }

            supp_ver_t tmp_ver;
            tmp_ret = p_qv->tee_get_supplemental_data_version(&tmp_ver.version);
            if (tmp_ret != SGX_QL_SUCCESS) {
                qve_ret = SGX_QL_ERROR_UNEXPECTED;
                break;
            }

            if (tmp_ver.version != supp_ver.version) {
                qve_ret = SGX_QL_ERROR_QVL_QVE_MISMATCH;
                SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Quote supplemental data version is different between QVL and QVE, please make sure you installed DCAP QVL and QvE from same release.\n");
                break;
            }

            qve_ret = tee_qae_get_target_info(&tmp_report_info.app_enclave_target_info);
            if(qve_ret != SGX_QL_SUCCESS)
            {
                SE_TRACE(SE_TRACE_DEBUG,"\Error: tee_qae_get_target_info failed: 0x%04x\n", qve_ret);
                break;
            }
        }

        //in case input collateral is NULL, dynamically load and call QPL to retrieve verification collateral
        //
        if (NULL_POINTER(p_quote_collateral)) {

            //extract fmspc and CA from the quote, these values are required inorder to query collateral from QPL
            //
            qve_ret = p_qv->tee_get_fmspc_ca_from_quote(p_quote, quote_size, fmspc_from_quote, FMSPC_SIZE, ca_from_quote, CA_SIZE);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: get_fmspc_ca_from_quote successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: get_fmspc_ca_from_quote failed: 0x%04x\n", qve_ret);
                break;
            }

            //retrieve verification collateral using QPL
            //
            qve_ret = p_qv->tee_get_verification_endorsement(
                (const char *)fmspc_from_quote,
                FMSPC_SIZE,
                (const char *)ca_from_quote,
                &qve_collaterals_from_qp);
            if (qve_ret == SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_DEBUG, "Info: dcap_retrieve_verification_collateral successfully returned.\n");
            }
            else {
                SE_TRACE(SE_TRACE_DEBUG, "Error: dcap_retrieve_verification_collateral failed: 0x%04x\n", qve_ret);
                break;
            }
            p_quote_collateral = qve_collaterals_from_qp;
        }

        qve_ret = p_qv->tee_get_verify_token(
            p_quote, quote_size,
            current_time,
            p_quote_collateral,
            &tmp_report_info,
            p_user_data,
            user_data_len,
            p_verification_result_token_buffer_size,
            p_verification_result_token);

        if (qve_ret == SGX_QL_SUCCESS) {
            SE_TRACE(SE_TRACE_DEBUG, "Info: verify_quote_qvt successfully returned.\n");
            if (p_qve_report_info)
            {
                memcpy(&p_qve_report_info->qe_report, &tmp_report_info.qe_report, sizeof(tmp_report_info.qe_report));
            }
        }
        else {
            SE_TRACE(SE_TRACE_DEBUG, "Error: verify_quote_qvt failed: 0x%04x\n", qve_ret);
            break;
        }
    } while (0);

    //free verification collateral using QPL
    //
    if (qve_collaterals_from_qp) {
        p_qv->tee_free_verification_endorsement(qve_collaterals_from_qp);
    }

    //unload QvE if set policy to ephemeral
    //
    if (g_qve_policy == SGX_QL_EPHEMERAL ||
        g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD) {

        sgx_ret = p_qv->unload_qve();
        g_qve_eid = 0;

        if (sgx_ret != SGX_SUCCESS) {
            qve_ret = sgx_error_to_quote3_error(sgx_ret);
        }
    }
    return qve_ret;
}



quote3_error_t tee_verify_quote_qvt(
    const uint8_t *p_quote,
    uint32_t quote_size,
    const sgx_ql_qve_collateral_t *p_quote_collateral,
    sgx_ql_qe_report_info_t *p_qve_report_info,
    const uint8_t *p_user_data,
    uint32_t *p_verification_result_token_buffer_size,
    uint8_t **p_verification_result_token
)
{
    if (CHECK_MANDATORY_PARAMS(p_quote, quote_size) ||
        quote_size < QUOTE_MIN_SIZE) {
        //one or more invalid parameters
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //check the length of user_data, max to 128
    uint32_t user_data_len = 0;
    if(p_user_data != NULL){
        user_data_len = (uint32_t)strnlen(reinterpret_cast<const char *>(p_user_data), USER_DATA_MAX_LEN+1);
        if(user_data_len > USER_DATA_MAX_LEN){
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    //parse quote header to get tee type, only support SGX and TDX by now
    tee_evidence_type_t tee_type = UNKNOWN_QUOTE_TYPE;

    //check quote type
    uint32_t *p_type = (uint32_t *) (p_quote + sizeof(uint16_t) * 2);

    if (*p_type == SGX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - SGX quote.\n");
        tee_type = SGX_EVIDENCE;
    }
    else if (*p_type == TDX_QUOTE_TYPE) {
        SE_TRACE(SE_TRACE_DEBUG, "Info: Quote type - TDX quote.\n");
        tee_type = TDX_EVIDENCE;
    }
    else {
        SE_TRACE(SE_TRACE_ERROR, "Err: Unsupported quote type.\n");
        //quote type is not supported
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    //get untrusred supplemental data size
    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));
    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    supp_ver_t latest_ver;

    dcap_ret = tee_get_supplemental_data_version_and_size(p_quote,
                                            quote_size,
                                            &latest_ver.version,
                                            &supp_data.data_size);
    if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: tee_get_quote_supplemental_data_version_and_size successfully returned.\n");
        SE_TRACE(SE_TRACE_DEBUG,"\tInfo: latest supplemental data major version: %d, minor version: %d, size: %d\n", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
    }
    else {
        if (dcap_ret != TEE_SUCCESS)
            SE_TRACE(SE_TRACE_DEBUG,"\tError: tee_get_supplemental_data_version_and_size failed: 0x%04x\n", dcap_ret);

        if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
            SE_TRACE(SE_TRACE_DEBUG,"\tWarning: Quote supplemental data size is different, please make sure you installed DCAP QVL and QvE from same release.\n");

        supp_data.data_size = 0;
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    tee_class_type_t class_type = CLASS_SGX_QVL;

    if (p_qve_report_info) {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVE;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVE;
    }

    //untrsuted quote verification
    //
    else {
        if (tee_type == SGX_EVIDENCE)
            class_type = CLASS_SGX_QVL;
        if (tee_type == TDX_EVIDENCE)
            class_type = CLASS_TDX_QVL;
    }

    time_t current_time = time(NULL);
    if (g_qve_policy == SGX_QL_PERSISTENT || g_qve_policy == SGX_QL_EPHEMERAL) {

        std::lock_guard<std::mutex> lock(qve_mutex);

        if (global_tee_qv && class_type != current_class_type) {
            //reset the object if the type change in next thread
            global_tee_qv.reset();
            global_tee_qv = NULL;

            SE_TRACE(SE_TRACE_DEBUG, "Info: Reset global tee qve instance.\n");
        }

        if (!global_tee_qv) {
            global_tee_qv = create_instance(class_type);
            if (global_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_quote_qvt_internal(
            p_quote,
            quote_size,
            current_time,
            p_quote_collateral,
            p_qve_report_info,
            supp_data,
            latest_ver,
            p_user_data,
            user_data_len,
            p_verification_result_token_buffer_size,
            p_verification_result_token,
            global_tee_qv);
    }

    else if (g_qve_policy == SGX_QL_EPHEMERAL_QVE_MULTI_THREAD || g_qve_policy == SGX_QL_PERSISTENT_QVE_MULTI_THREAD) {

        if (p_tee_qv && class_type != current_class_type) {
            //reset the object if the type change in next thread
            //
            p_tee_qv.reset();
        }

        if (!p_tee_qv) {
            p_tee_qv = create_instance(class_type);
            if (p_tee_qv == nullptr) {
                SE_TRACE(SE_TRACE_ERROR, "Error: cannot create tee qv instance.\n");
                goto end;
            }
        }

        current_class_type = class_type;

        qve_ret = tee_verify_quote_qvt_internal(
            p_quote,
            quote_size,
            current_time,
            p_quote_collateral,
            p_qve_report_info,
            supp_data,
            latest_ver,
            p_user_data,
            user_data_len,
            p_verification_result_token_buffer_size,
            p_verification_result_token,
            p_tee_qv);
    }

    else {
        //invalid policy
        //
        qve_ret = SGX_QL_UNSUPPORTED_LOADING_POLICY;
        goto end;
    }

end:
    return qve_ret;
}

void ocall_qvt_token_malloc(uint64_t verification_result_token_buffer_size, uint8_t **p_verification_result_token)
{
    if(verification_result_token_buffer_size != 0 && p_verification_result_token != NULL)
    {
        *p_verification_result_token = (uint8_t*)malloc(verification_result_token_buffer_size);
        if(*p_verification_result_token != NULL)
        {
            memset(*p_verification_result_token, 0, verification_result_token_buffer_size);
        }
        else
        {
            SE_TRACE(SE_TRACE_ERROR, "Error: failed to malloc memory for JWT.\n");
        }
    }
    return;
}

quote3_error_t tee_free_verify_quote_qvt(uint8_t *p_verification_result_token, uint32_t *p_verification_result_token_buffer_size)
{
    if(p_verification_result_token == NULL || p_verification_result_token_buffer_size == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    free(p_verification_result_token);
    p_verification_result_token = NULL;
    *p_verification_result_token_buffer_size = 0;
    return SGX_QL_SUCCESS;
}



#include <sys/types.h>
#include <sys/stat.h>

/**
 * This API can be used to set the full path of QVE and QPL library.
 *
 * The function takes the enum and the corresponding full path.
 *
 * @param path_type The type of binary being passed in.
 * @param p_path It should be a valid full path.
 *
 * @return SGX_QL_SUCCESS  Successfully set the full path.
 * @return SGX_QL_ERROR_INVALID_PARAMETER p_path is not a valid full path or the path is too long.
 */

quote3_error_t sgx_qv_set_path(
        sgx_qv_path_type_t path_type,
        const char *p_path)
{
    quote3_error_t ret = SGX_QL_SUCCESS;
    bool temp_ret = false;

    struct stat info;

    if (!p_path){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }

    if(stat(p_path, &info) != 0){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }
    else if((info.st_mode & S_IFMT) != S_IFREG){
        return(SGX_QL_ERROR_INVALID_PARAMETER);
    }

    switch(path_type)
    {
        case SGX_QV_QVE_PATH:
            temp_ret = sgx_qv_set_qve_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
        case SGX_QV_QPL_PATH:
            temp_ret = sgx_qv_set_qpl_path(p_path);
            ret = temp_ret ? SGX_QL_SUCCESS : SGX_QL_ERROR_INVALID_PARAMETER;
            break;
    default:
        ret = SGX_QL_ERROR_INVALID_PARAMETER;
        break;
    }
    return(ret);
}
#endif
