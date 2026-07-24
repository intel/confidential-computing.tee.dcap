/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
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
 * File: td_ql_wrapper.cpp
 */
#include <string.h>
#include <limits.h>

#include "sgx_urts.h"
#include "util.h"
#include "td_ql_wrapper.h"
#include "td_ql_logic.h"
#include "quoting_enclave_tdqe.h"

#ifndef _MSC_VER
    extern errno_t memcpy_s(void *dest, size_t numberOfElements, const void *src, size_t count);
#endif
#define MAX_PATH 260

uint8_t g_tdqe_mrsigner[32] = { 0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a,
                              0x00, 0x56, 0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff };
uint8_t g_tdqe_ext_prod_id[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t g_tdqe_config_id[64] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // QE's Config ID
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t g_tdqe_family_id[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };   // QE's family_id

/* Set the default Attestation Key Identity for the TDX Quoting Library.  This is the ECDSA TDQE's identity and
   ECDSA-256 */
extern const sgx_ql_att_key_id_t g_default_ecdsa_p256_att_key_id =
{
    0,                                                                                                   // ID
    0,                                                                                                   // Version
    32,                                                                                                  // Number of bytes in MRSIGNER
    { 0x8c, 0x4f, 0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13, 0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a,
      0x00, 0x56, 0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b, 0x08, 0x1b, 0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   // Production TDQE's MRSIGNER
    2,                                                                                                   // TDQE's Legacy Prod ID
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   // QE's extended_prod_id
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // QE's Config ID
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   // QE's family_id
    SGX_QL_ALG_ECDSA_P256                                                                                // Supported QE3's algorithm_id
};


tee_att_error_t tee_att_create_context(const tee_att_att_key_id_t* p_att_key_id,
    const char* p_qe_path,
    tee_att_config_t** pp_context)
{
    // Verify inputs
    if (NULL == pp_context)
    {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (NULL != p_att_key_id)
    {
        // Verify the Attestation key identity is supported.
        if (0 != p_att_key_id->base.id)
        {
            return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
        }
        if (0 != p_att_key_id->base.version)
        {
            return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
        }
        if (32 != p_att_key_id->base.mrsigner_length)
        {
            return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
        }
        if (0 != memcmp(p_att_key_id->base.mrsigner, g_tdqe_mrsigner, 32))
        {
            return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
        }
        else
        {
            if (2 != p_att_key_id->base.prod_id)
            {
                return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
            }
            if (SGX_QL_ALG_ECDSA_P256 != p_att_key_id->base.algorithm_id)
            {
                return(TEE_ATT_UNSUPPORTED_ATT_KEY_ID);
            }
        }
    }
    tee_att_config_t* p_context = new tee_att_config_t();

    if (NULL != p_qe_path)
    {
        size_t len = strnlen(p_qe_path, MAX_PATH);
        // Make sure there is enough space for the '\0',
        // after this line len <= sizeof(this->qe3_path) - 1
        if (len > MAX_PATH - 1)
        {
            delete p_context;
            return TEE_ATT_ERROR_INVALID_PARAMETER;

        }
#ifndef _MSC_VER
        strncpy(p_context->tdqe_path, p_qe_path, MAX_PATH - 1);
#else
        MultiByteToWideChar(CP_ACP, 0, p_qe_path, (int)len, p_context->tdqe_path, MAX_PATH);
#endif
        p_context->tdqe_path[len] = '\0';
    }
    *pp_context = p_context;
    return TEE_ATT_SUCCESS;

}

tee_att_error_t tee_att_free_context(tee_att_config_t* p_context)
{
    if (NULL == p_context)
    {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    delete p_context;

    return(TEE_ATT_SUCCESS);
}

tee_att_error_t tee_att_init_quote(const tee_att_config_t* p_context,
    sgx_target_info_t* p_qe_target_info,
    bool refresh_att_key,
    size_t* p_pub_key_id_size,
    uint8_t* p_pub_key_id)
{

    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_SUCCESS;
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;

    if (NULL == p_context)
    {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (NULL == p_pub_key_id_size) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid pub key id size pointer.\n");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    if (NULL == p_pub_key_id) {
        // Caller is requesting the required size of buffer to hold the key id.
        *p_pub_key_id_size = sizeof(ref_sha256_hash_t);
        return(TEE_ATT_SUCCESS);
    }
    if (*p_pub_key_id_size != sizeof(ref_sha256_hash_t)) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid pub key id size. %d\n", (int)*p_pub_key_id_size);
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    // Choose the default certification key type supported by the reference.
    sgx_ql_cert_key_type_t certification_key_type = PPID_RSA3072_ENCRYPTED;

    ret_val = const_cast<tee_att_config_t*>(p_context)->ecdsa_init_quote(certification_key_type, p_qe_target_info, refresh_att_key, (ref_sha256_hash_t *)p_pub_key_id);
    if (TEE_ATT_SUCCESS != ret_val) {
        if ((ret_val < TEE_ATT_ERROR_MIN) ||
            (ret_val > TEE_ATT_ERROR_MAX))
        {
            sgx_status = (sgx_status_t)ret_val;
            tdqe_error = (tdqe_error_t)ret_val;

            // Translate TDQE errors
            switch (tdqe_error)
            {
            case TDQE_ERROR_INVALID_PARAMETER:
                ret_val = TEE_ATT_ERROR_INVALID_PARAMETER;
                break;

            case TDQE_ERROR_OUT_OF_MEMORY:
                ret_val = TEE_ATT_ERROR_OUT_OF_MEMORY;
                break;

            case TDQE_ERROR_UNEXPECTED:
            case TDQE_ERROR_CRYPTO:       // Error generating the QE_ID (or decypting PPID not supported in release).  Unexpected error.
            case TDQE_ERROR_ATT_KEY_GEN:  // Error generating the ECDSA Attestation key.
            case TDQE_ECDSABLOB_ERROR:    // Should be unexpected since the blob was either generated or regenerated during this call
                ret_val = TEE_ATT_ERROR_UNEXPECTED;
                break;

            default:
                // Translate SDK errors
                switch (sgx_status)
                {
                case SGX_ERROR_INVALID_PARAMETER:
                    ret_val = TEE_ATT_ERROR_INVALID_PARAMETER;
                    break;

                case SGX_ERROR_OUT_OF_MEMORY:
                    ret_val = TEE_ATT_ERROR_OUT_OF_MEMORY;
                    break;

                case SGX_ERROR_ENCLAVE_FILE_ACCESS:
                    ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                    break;

                case SGX_ERROR_ENCLAVE_LOST:
                    ret_val = TEE_ATT_ENCLAVE_LOST;
                    break;

                    // Unexpected enclave loading errorsReturn codes from load_qe
                case SGX_ERROR_INVALID_ENCLAVE:
                case SGX_ERROR_UNDEFINED_SYMBOL:
                case SGX_ERROR_MODE_INCOMPATIBLE:
                case SGX_ERROR_INVALID_METADATA:
                case SGX_ERROR_MEMORY_MAP_CONFLICT:
                case SGX_ERROR_INVALID_VERSION:
                case SGX_ERROR_INVALID_ATTRIBUTE:
                case SGX_ERROR_NDEBUG_ENCLAVE:
                case SGX_ERROR_INVALID_MISC:
                    //case SE_ERROR_INVALID_LAUNCH_TOKEN:     ///todo: Internal error should be scrubbed before here.
                case SGX_ERROR_DEVICE_BUSY:
                case SGX_ERROR_NO_DEVICE:
                case SGX_ERROR_INVALID_SIGNATURE:
                    //case SE_ERROR_INVALID_MEASUREMENT:      ///todo: Internal error should be scrubbed before here.
                    //case SE_ERROR_INVALID_ISVSVNLE:         ///todo: Internal error should be scrubbed before here.
                case SGX_ERROR_INVALID_ENCLAVE_ID:
                    ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                    break;
                case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
                    ret_val = TEE_ATT_ERROR_INVALID_PRIVILEGE;
                    break;

                case SGX_ERROR_UNEXPECTED:
                    ret_val = TEE_ATT_ERROR_UNEXPECTED;
                    break;

                default:
                    ret_val = TEE_ATT_ERROR_UNEXPECTED;
                    break;
                }
                break;
            }
        }
    }

    return(ret_val);
}

tee_att_error_t tee_att_get_quote_size(const tee_att_config_t* p_context,
    uint32_t* p_quote_size)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;
    sgx_ql_cert_key_type_t certification_key_type = PPID_RSA3072_ENCRYPTED;

    if (NULL == p_context)
    {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    if (NULL == p_quote_size) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid quote size pointer.\n");
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    ret_val = const_cast<tee_att_config_t*>(p_context)->ecdsa_get_quote_size(certification_key_type, p_quote_size);
    if (TEE_ATT_SUCCESS != ret_val) {
        if ((ret_val < TEE_ATT_ERROR_MIN) ||
            (ret_val > TEE_ATT_ERROR_MAX))
        {
            sgx_status = (sgx_status_t)ret_val;

            // Translate SDK errors
            switch (sgx_status)
            {
            case SGX_ERROR_OUT_OF_MEMORY:
                ret_val = TEE_ATT_ERROR_OUT_OF_MEMORY;
                break;

            case SGX_ERROR_ENCLAVE_FILE_ACCESS:
                ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                break;

                // Unexpected enclave loading errorsReturn codes from load_qe
            case SGX_ERROR_INVALID_ENCLAVE:
            case SGX_ERROR_UNDEFINED_SYMBOL:
            case SGX_ERROR_MODE_INCOMPATIBLE:
            case SGX_ERROR_INVALID_METADATA:
            case SGX_ERROR_MEMORY_MAP_CONFLICT:
            case SGX_ERROR_INVALID_VERSION:
            case SGX_ERROR_INVALID_ATTRIBUTE:
            case SGX_ERROR_NDEBUG_ENCLAVE:
            case SGX_ERROR_INVALID_MISC:
                //case SE_ERROR_INVALID_LAUNCH_TOKEN:     ///todo: Internal error should be scrubbed before here.
            case SGX_ERROR_DEVICE_BUSY:
            case SGX_ERROR_NO_DEVICE:
            case SGX_ERROR_INVALID_SIGNATURE:
                //case SE_ERROR_INVALID_MEASUREMENT:      ///todo: Internal error should be scrubbed before here.
                //case SE_ERROR_INVALID_ISVSVNLE:         ///todo: Internal error should be scrubbed before here.
            case SGX_ERROR_INVALID_ENCLAVE_ID:
                ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                break;
            case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
                ret_val = TEE_ATT_ERROR_INVALID_PRIVILEGE;
                break;

            case SGX_ERROR_ENCLAVE_LOST:
                ret_val = TEE_ATT_ENCLAVE_LOST;
                break;

            case SGX_ERROR_UNEXPECTED:
                ret_val = TEE_ATT_ERROR_UNEXPECTED;
                break;

            default:
                ret_val = TEE_ATT_ERROR_UNEXPECTED;
                break;
            }
        }
    }

    return(ret_val);
}

static tee_att_error_t tee_att_get_quote_internal(const tee_att_config_t* p_context,
    const uint8_t* p_report,
    uint32_t report_size,
    sgx_qe_report_info_t* p_qe_report_info,
    uint8_t* p_quote,
    uint32_t quote_size,
    const tdx_servtd_ext_t* p_servtd_ext)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    tdqe_error_t tdqe_error = TDQE_SUCCESS;
    tee_att_error_t ret_val = TEE_ATT_SUCCESS;
    sgx_report2_t report_copy = {};

    UNUSED(p_qe_report_info);

    if (NULL == p_context)
    {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    if (NULL == p_report) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }
    if (report_size != sizeof(sgx_report2_t)) {
        SE_TRACE(SE_TRACE_ERROR, "Invalid report size. %u\n", report_size);
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    if (0 != memcpy_s(&report_copy, sizeof(report_copy), p_report, sizeof(report_copy))) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    ret_val = const_cast<tee_att_config_t*>(p_context)->ecdsa_get_quote(
        &report_copy, p_quote, quote_size, p_servtd_ext);
    if (TEE_ATT_SUCCESS != ret_val) {
        if ((ret_val < TEE_ATT_ERROR_MIN) ||
            (ret_val > TEE_ATT_ERROR_MAX))
        {
            sgx_status = (sgx_status_t)ret_val;
            tdqe_error = (tdqe_error_t)ret_val;

            // Translate TDQE errors
            switch (tdqe_error)
            {
            case TDQE_ERROR_INVALID_PARAMETER:
                ret_val = TEE_ATT_ERROR_INVALID_PARAMETER;
                break;

            case TDQE_ERROR_INVALID_REPORT:
                ret_val = TEE_ATT_INVALID_REPORT;
                break;

            case TDQE_ERROR_CRYPTO:
                // Error generating QE_ID.  Shouldn't happen
                ret_val = TEE_ATT_ERROR_UNEXPECTED;
                break;

            case TDQE_ERROR_OUT_OF_MEMORY:
                ret_val = TEE_ATT_ERROR_OUT_OF_MEMORY;
                break;

            case TDQE_UNABLE_TO_GENERATE_QE_REPORT:
                ret_val = TEE_ATT_UNABLE_TO_GENERATE_QE_REPORT;
                break;

            case TDQE_REPORT_FORMAT_NOT_SUPPORTED:
                ret_val = TEE_ATT_QE_REPORT_UNSUPPORTED_FORMAT;
                break;

            default:
                // Translate SDK errors
                switch (sgx_status)
                {
                case SGX_ERROR_INVALID_PARAMETER:
                    ret_val = TEE_ATT_ERROR_INVALID_PARAMETER;
                    break;

                case SGX_ERROR_ENCLAVE_FILE_ACCESS:
                    ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                    break;

                case SGX_ERROR_OUT_OF_MEMORY:
                    ret_val = TEE_ATT_ERROR_OUT_OF_MEMORY;
                    break;

                case SGX_ERROR_ENCLAVE_LOST:
                    ret_val = TEE_ATT_ENCLAVE_LOST;
                    break;

                    // Unexpected enclave loading errorsReturn codes from load_qe
                case SGX_ERROR_INVALID_ENCLAVE:
                case SGX_ERROR_UNDEFINED_SYMBOL:
                case SGX_ERROR_MODE_INCOMPATIBLE:
                case SGX_ERROR_INVALID_METADATA:
                case SGX_ERROR_MEMORY_MAP_CONFLICT:
                case SGX_ERROR_INVALID_VERSION:
                case SGX_ERROR_INVALID_ATTRIBUTE:
                case SGX_ERROR_NDEBUG_ENCLAVE:
                case SGX_ERROR_INVALID_MISC:
                    //case SE_ERROR_INVALID_LAUNCH_TOKEN:     ///todo: Internal error should be scrubbed before here.
                case SGX_ERROR_DEVICE_BUSY:
                case SGX_ERROR_NO_DEVICE:
                case SGX_ERROR_INVALID_SIGNATURE:
                    //case SE_ERROR_INVALID_MEASUREMENT:      ///todo: Internal error should be scrubbed before here.
                    //case SE_ERROR_INVALID_ISVSVNLE:         ///todo: Internal error should be scrubbed before here.
                case SGX_ERROR_INVALID_ENCLAVE_ID:
                    ret_val = TEE_ATT_ENCLAVE_LOAD_ERROR;
                    break;
                case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
                    ret_val = TEE_ATT_ERROR_INVALID_PRIVILEGE;
                    break;

                case SGX_ERROR_UNEXPECTED:
                    ret_val = TEE_ATT_ERROR_UNEXPECTED;
                    break;

                default:
                    ret_val = TEE_ATT_ERROR_UNEXPECTED;
                    break;
                }
                break;
            }
        }
    }

    return(ret_val);
}

tee_att_error_t tee_att_get_quote(const tee_att_config_t* p_context,
    const uint8_t* p_report,
    uint32_t report_size,
    sgx_qe_report_info_t* p_qe_report_info,
    uint8_t* p_quote,
    uint32_t quote_size)
{
    return tee_att_get_quote_internal(p_context, p_report, report_size, p_qe_report_info,
        p_quote, quote_size, NULL);
}

tee_att_error_t tee_att_get_quote_mig_history(const tee_att_config_t* p_context,
    const uint8_t* p_report,
    uint32_t report_size,
    sgx_qe_report_info_t* p_qe_report_info,
    uint8_t* p_quote,
    uint32_t quote_size,
    const tdx_servtd_ext_t* p_servtd_ext)
{
    if (NULL == p_servtd_ext) {
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    }

    return tee_att_get_quote_internal(p_context, p_report, report_size, p_qe_report_info,
        p_quote, quote_size, p_servtd_ext);
}

tee_att_error_t tee_att_get_keyid(const tee_att_config_t* p_context,
    tee_att_att_key_id_t* p_att_key_id)
{
    if (NULL == p_context || NULL == p_att_key_id)
        return TEE_ATT_ERROR_INVALID_PARAMETER;

    memset(p_att_key_id, 0, sizeof(tee_att_att_key_id_t));
    if (0  !=  memcpy_s(&p_att_key_id->base, sizeof(p_att_key_id->base),
        &g_default_ecdsa_p256_att_key_id, sizeof(g_default_ecdsa_p256_att_key_id))) {
        return TEE_ATT_ERROR_UNEXPECTED;
    }
    return TEE_ATT_SUCCESS;
}

tee_att_error_t tee_att_get_platform_info(const tee_att_config_t* p_context,
    tee_platform_info_t* p_platform_info)
{
    if (NULL == p_context || NULL == p_platform_info)
        return TEE_ATT_ERROR_INVALID_PARAMETER;
    return const_cast<tee_att_config_t*>(p_context)->get_platform_info(
        &p_platform_info->platform_id, &p_platform_info->cpu_svn,
        &p_platform_info->tdqe_isv_svn, &p_platform_info->pce_isv_svn);
}


#ifndef _MSC_VER
extern "C"
tee_att_error_t tee_att_get_qpl_handle(const tee_att_config_t *p_context,
    void **pp_qpl_handle) {
    void *p_local_qpl_handle = NULL;
    if (NULL == p_context || NULL == pp_qpl_handle)
        return TEE_ATT_ERROR_INVALID_PARAMETER;

    p_local_qpl_handle = const_cast<tee_att_config_t*>(p_context)->get_qpl_handle();
    if ( NULL == p_local_qpl_handle) {
        return TEE_ATT_PLATFORM_LIB_UNAVAILABLE;
    }

    *pp_qpl_handle = p_local_qpl_handle;
    return TEE_ATT_SUCCESS;
}

static tee_att_error_t sgx_set_context_path(const tee_att_config_t* p_context,
    tee_att_ae_type_t type,
    const char* p_path)
{
    char* context_path;
    if (NULL == p_context)
        return TEE_ATT_ERROR_INVALID_PARAMETER;

    switch (type)
    {
    case TEE_ATT_TDQE:
        context_path = const_cast<char*> (p_context->tdqe_path);
        break;
    case TEE_ATT_QPL:
        context_path = const_cast<char*> (p_context->qpl_path);
        break;
    case TEE_ATT_IDE:
        context_path = const_cast<char*> (p_context->ide_path);
        break;
    default:
        return TEE_ATT_ERROR_INVALID_PARAMETER;
    }
    // p_path isn't NULL, caller has checked it.
    // len <= sizeof(g_pce_status.pce_path)
    size_t len = strnlen(p_path, MAX_PATH);
    // Make sure there is enough space for the '\0',
    // after this line len <= sizeof(this->qe3_path) - 1
    if (len > MAX_PATH - 1)
        return TEE_ATT_ERROR_INVALID_PARAMETER;
#ifndef _MSC_VER
    strncpy(context_path, p_path, MAX_PATH - 1);
#else
    strncpy_s(context_path, MAX_PATH, p_path, MAX_PATH);
#endif
    context_path[len] = '\0';
    return TEE_ATT_SUCCESS;
}

#include <sys/types.h>
#include <sys/stat.h>
tee_att_error_t tee_att_set_path(const tee_att_config_t* p_context,
    tee_att_ae_type_t type,
    const char* p_path)
{
    tee_att_error_t ret = TEE_ATT_SUCCESS;
    sgx_pce_error_t pce_ret = SGX_PCE_SUCCESS;
    struct stat info;

    if (!p_path)
        return(TEE_ATT_ERROR_INVALID_PARAMETER);

    if (stat(p_path, &info) != 0)
        return(TEE_ATT_ERROR_INVALID_PARAMETER);
    else if ((info.st_mode & S_IFREG) == 0)
        return(TEE_ATT_ERROR_INVALID_PARAMETER);

    switch (type)
    {
    case TEE_ATT_PCE:
        pce_ret = sgx_set_pce_path(p_path);
        switch (pce_ret)
        {
        case SGX_PCE_SUCCESS:
            (void)sgx_set_pce_enclave_load_policy(SGX_QL_EPHEMERAL);
            ret = TEE_ATT_SUCCESS;
            break;
        case SGX_PCE_INVALID_PARAMETER:
            ret = TEE_ATT_ERROR_INVALID_PARAMETER;
            break;
        default:
            ret = TEE_ATT_ERROR_UNEXPECTED;
            break;
        }
        break;
    default:
        ret = sgx_set_context_path(p_context, type, p_path);
        break;
    }
    return(ret);
}
#endif
