/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sgx_dcap_qal.h"
#include <stdlib.h>
#include <string>
#include <sstream>
#include "opa_wasm.h"
#include "se_thread.h"
#include "se_trace.h"
#include "qal_json.h"
#include "qae_wrapper.h"
#include "file_util.h"
#include "sgx_dcap_pcs_com.h"
#include "qal_auth.h"

#define INVALID_AUTH_STATUS -2

static bool s_wasm_buf_flag = false;
static uint8_t *s_wasm_buf = NULL;
static size_t s_wasm_size = 0;
static pthread_once_t s_wasm_buf_initialized = PTHREAD_ONCE_INIT;

#ifdef USE_LOCAL_WASM
#define WASM_FILE "./policy.wasm"
#else
#define WASM_FILE "/usr/share/sgx/tee_appraisal_policy.wasm"
#endif

void __attribute__((destructor)) qal_destructor()
{
    if (s_wasm_buf)
    {
        free(s_wasm_buf);
        s_wasm_buf = NULL;
    }
}

static void prepare_wasm_buf()
{
    s_wasm_buf = read_file_to_buffer(WASM_FILE, &s_wasm_size);
    if (s_wasm_buf == NULL)
    {
        se_trace(SE_TRACE_ERROR, "Read WASM file failed.\n");
    }
    else
    {
        s_wasm_buf_flag = true;
    }
}

quote3_error_t tee_appraise_verification_token(
    const uint8_t *p_verification_result_token,
    uint8_t **p_qaps,
    uint8_t qaps_count,
    const time_t appraisal_check_date,
    sgx_ql_qe_report_info_t *p_qae_report_info,
    uint32_t *p_appraisal_result_token_buffer_size,
    uint8_t **p_appraisal_result_token)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_enclave_id_t qae_id = 0;

    if (p_verification_result_token == NULL ||
        appraisal_check_date == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if (p_appraisal_result_token_buffer_size == NULL || p_appraisal_result_token == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_qaps == NULL || qaps_count == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    for (uint8_t i = 0; i < qaps_count; i++)
    {
        if (p_qaps[i] == NULL)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    if (pthread_once(&s_wasm_buf_initialized, prepare_wasm_buf) != 0 || s_wasm_buf_flag == false)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }

    if (p_qae_report_info)
    {
        // trusted qae
        ret = load_enclave(&qae_id);
        if (ret != SGX_QL_SUCCESS)
        {
            se_trace(SE_TRACE_ERROR, "Failed to load QAE: %#x\n", ret);
            return ret;
        }

        ret = ecall_appraise_quote_result(qae_id, s_wasm_buf, s_wasm_size, p_verification_result_token, p_qaps, qaps_count, appraisal_check_date,
                                          p_qae_report_info, p_appraisal_result_token_buffer_size, p_appraisal_result_token);
        unload_enclave(qae_id);
        return ret;
    }
    else
    {
        std::string json_str = "";
        try
        {
            ret = construct_complete_json(p_verification_result_token, p_qaps, qaps_count, json_str);
            if (ret != SGX_QL_SUCCESS)
            {
                return ret;
            }
        }
        catch (...)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        OPAEvaluateEngine instance;
        if ((ret = instance.prepare_wasm(s_wasm_buf, s_wasm_size)) != SGX_QL_SUCCESS)
        {
            return ret;
        }
        ret = instance.start_eval(reinterpret_cast<const uint8_t *>(json_str.c_str()), (uint32_t)(json_str.length() + 1), appraisal_check_date,
                                  p_appraisal_result_token_buffer_size, p_appraisal_result_token);
        return ret;
    }
}

quote3_error_t tee_free_appraisal_token(uint8_t *p_appraisal_result_token)
{
    if (p_appraisal_result_token == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;
    free(p_appraisal_result_token);
    return SGX_QL_SUCCESS;
}

quote3_error_t tee_authenticate_appraisal_result(const uint8_t *p_appraisal_result_token, const tee_policy_bundle_t *p_policies, tee_policy_auth_result_t *result)
{
    return tee_authenticate_appraisal_result_ex(NULL, 0, p_appraisal_result_token, p_policies, NULL, NULL, result, NULL);
}

quote3_error_t tee_authenticate_appraisal_result_ex(const uint8_t *p_quote,
                                                    uint32_t quote_size,
                                                    const uint8_t *p_appraisal_result_token,
                                                    const tee_policy_bundle_t *p_policies,
                                                    const uint8_t *p_td_identity,
                                                    const uint8_t *p_td_tcb_mapping_table,
                                                    tee_policy_auth_result_t *result,
                                                    sgx_ql_qe_report_info_t *p_qae_report_info)
{
    if (p_appraisal_result_token == NULL || p_policies == NULL || result == NULL || p_td_identity != NULL || p_td_tcb_mapping_table != NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if ((p_policies->platform_policy.pt == CUSTOMIZED && p_policies->platform_policy.p_policy == NULL) ||
        (p_policies->platform_policy.pt == DEFAULT_STRICT && p_policies->platform_policy.p_policy != NULL) ||
        (p_policies->tdqe_policy.pt == CUSTOMIZED && p_policies->tdqe_policy.p_policy == NULL) ||
        (p_policies->tdqe_policy.pt == DEFAULT_STRICT && p_policies->tdqe_policy.p_policy != NULL))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    for (size_t i = 0; i < sizeof(p_policies->reserved) / sizeof(p_policies->reserved[0]); i++)
    {
        if (p_policies->reserved[i].pt != 0 || p_policies->reserved[i].p_policy != NULL)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    if ((p_quote != NULL && quote_size == 0) || (p_quote == NULL && quote_size != 0))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    int tmp_result = INVALID_AUTH_STATUS;

    if (p_qae_report_info != NULL)
    {
        sgx_enclave_id_t qae_id;
        // trusted qae
        ret = load_enclave(&qae_id);
        if (ret != SGX_QL_SUCCESS)
        {
            se_trace(SE_TRACE_ERROR, "Failed to load QAE: %#x\n", ret);
            return ret;
        }

        ret = ecall_authenticate_appraisal_result(qae_id, p_quote, quote_size, p_appraisal_result_token, p_policies, reinterpret_cast<tee_policy_auth_result_t *>(&tmp_result), p_qae_report_info);
        if (tmp_result != INVALID_AUTH_STATUS)
        {
            *result = (tee_policy_auth_result_t)tmp_result;
        }
        if (ret != SGX_QL_SUCCESS)
        {
            se_trace(SE_TRACE_ERROR, "ecall_authenticat_appraisal_result() return failure: %#x\n", ret);
            unload_enclave(qae_id);
            return ret;
        }
        unload_enclave(qae_id);
    }
    else
    {
        ret = authenticate_appraisal_result_internal(p_quote, quote_size, reinterpret_cast<const char *>(p_appraisal_result_token), p_policies, reinterpret_cast<tee_policy_auth_result_t *>(&tmp_result));
        if (tmp_result != INVALID_AUTH_STATUS)
        {
            *result = (tee_policy_auth_result_t)tmp_result;
        }
        if (ret != SGX_QL_SUCCESS)
        {
            return ret;
        }
    }

    return ret;
}

quote3_error_t tee_authenticate_policy_owner(const uint8_t *p_quote,
                                             uint32_t quote_size,
                                             const uint8_t *p_appraisal_result_token,
                                             const uint8_t **policy_key_list,
                                             uint32_t list_size,
                                             const uint8_t *p_td_identity,
                                             const uint8_t *p_td_tcb_mapping_table,
                                             tee_policy_auth_result_t *result,
                                             sgx_ql_qe_report_info_t *p_qae_report_info)
{
    if (p_appraisal_result_token == NULL || result == NULL)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if (policy_key_list == NULL || list_size == 0)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < list_size; i++)
    {
        if (policy_key_list[i] == NULL)
        {
            return TEE_ERROR_INVALID_PARAMETER;
        }
    }
    if ((p_quote != NULL && quote_size == 0) || (p_quote == NULL && quote_size != 0))
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if (p_td_identity != NULL || p_td_tcb_mapping_table != NULL)
    {
        // For future usage
        return TEE_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    int tmp_result = INVALID_AUTH_STATUS;
    if (p_qae_report_info != NULL)
    {
        sgx_enclave_id_t qae_id;
        // trusted qae
        ret = load_enclave(&qae_id);
        if (ret != SGX_QL_SUCCESS)
        {
            se_trace(SE_TRACE_ERROR, "Failed to load QAE: %#x\n", ret);
            return ret;
        }

        ret = ecall_authenticate_policy_owner(qae_id,
                                              p_quote,
                                              quote_size,
                                              p_appraisal_result_token,
                                              policy_key_list, list_size,
                                              reinterpret_cast<tee_policy_auth_result_t *>(&tmp_result),
                                              p_qae_report_info);
        if (tmp_result != INVALID_AUTH_STATUS)
        {
            *result = (tee_policy_auth_result_t)tmp_result;
        }
        if (ret != SGX_QL_SUCCESS)
        {
            se_trace(SE_TRACE_ERROR, "ecall_authenticate_policy_owner() return failure: %#x\n", ret);
            unload_enclave(qae_id);
            return ret;
        }
        unload_enclave(qae_id);
    }
    else
    {
        ret = authenticate_policy_owner_internal(p_quote,
                                                 quote_size,
                                                 reinterpret_cast<const char *>(p_appraisal_result_token),
                                                 reinterpret_cast<const char **>(policy_key_list),
                                                 list_size,
                                                 reinterpret_cast<tee_policy_auth_result_t *>(&tmp_result));
        if (tmp_result != INVALID_AUTH_STATUS)
        {
            *result = (tee_policy_auth_result_t)tmp_result;
        }
    }
    return ret;
}

// This API will allow the calling code to retrieve the target info of the QAE
quote3_error_t tee_qae_get_target_info(sgx_target_info_t *p_target_info)
{
    if (p_target_info == NULL)
        return SGX_QL_ERROR_INVALID_PARAMETER;

    sgx_enclave_id_t qae_id = 0;
    quote3_error_t ret = load_enclave(&qae_id, p_target_info);
    if (ret != SGX_QL_SUCCESS)
    {
        se_trace(SE_TRACE_ERROR, "Failed to load QAE: %#x\n", ret);
        return ret;
    }
    unload_enclave(qae_id);
    return ret;
}
