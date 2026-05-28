/*
 * Copyright(c) 2011-2026 Intel Corporation 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pthread.h"
#include "qae_t.h"
#include "opa_wasm.h"
#include "qal_common.h"
#include "qal_auth.h"
#include "qal_json.h"
#include "sgx_trts.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include <sgx_dcap_constant_val.h>  // Provided by SGX SDK (version >= 2.29)
#include "encode_helper.h"
#include "sgx_tcrypto.h"
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static quote3_error_t verify_qve_report_and_identity(const char *p_verification_result_token, sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = {0};
    sgx_report_t *p_qve_report = &(p_qae_report_info->qe_report);

    // Verify QvE report and report_data
    sgx_status_t sgx_ret = sgx_verify_report(p_qve_report);
    if (sgx_ret != SGX_SUCCESS)
    {
        return SGX_QL_ERROR_REPORT;
    }
    sgx_ret = sgx_sha384_init(&sha_handle);
    if (sgx_ret != SGX_SUCCESS)
    {
        return ret;
    }
    sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(p_verification_result_token), (uint32_t)strlen(p_verification_result_token), sha_handle);
    if (SGX_SUCCESS != sgx_ret)
    {
        sgx_sha384_close(sha_handle);
        return ret;
    }

    sgx_ret = sgx_sha384_get_hash(sha_handle, reinterpret_cast<sgx_sha384_hash_t *>(&report_data));
    if (sgx_ret != SGX_SUCCESS)
    {
        sgx_sha384_close(sha_handle);
        return ret;
    }
    sgx_sha384_close(sha_handle);
    if (memcmp(&(p_qve_report->body.report_data), &report_data, sizeof(report_data)) != 0)
    {
        return SGX_QL_ERROR_REPORT;
    }

    // Check QvE Identity
    try
    {
        const auto miscselectMask = BytesToUint32(hexStringToBytes(QAE_QVE_MISC_SELECT_MASK));
        const auto miscselect = BytesToUint32(hexStringToBytes(QAE_QVE_MISC_SELECT));

        if ((p_qve_report->body.misc_select & miscselectMask) != miscselect)
        {
            return SGX_QL_QVEIDENTITY_MISMATCH;
        }

        const auto attribute_mask = hexStringToBytes(QAE_QVE_ATTRIBUTE_MASK);
        const auto attribute = hexStringToBytes(QAE_QVE_ATTRIBUTE);

        Bytes attributeReport;

        std::copy((uint8_t *)const_cast<sgx_attributes_t *>(&p_qve_report->body.attributes),
                  (uint8_t *)const_cast<sgx_attributes_t *>(&p_qve_report->body.attributes) + sizeof(sgx_attributes_t),
                  std::back_inserter(attributeReport));

        if (applyMask(attributeReport, attribute_mask) != attribute)
        {
            return SGX_QL_QVEIDENTITY_MISMATCH;
        }

        const auto mrsigner = hexStringToBytes(QAE_QVE_MRSIGNER);

        Bytes mrsignerReport;
        std::copy(std::begin(p_qve_report->body.mr_signer.m),
                  std::end(p_qve_report->body.mr_signer.m),
                  std::back_inserter(mrsignerReport));

        if (mrsigner.empty() || mrsignerReport.empty())
        {
            return ret;
        }

        if (mrsigner != mrsignerReport)
        {
            return SGX_QL_QVEIDENTITY_MISMATCH;
        }

        if (p_qve_report->body.isv_prod_id != QVE_PRODID)
        {
            return SGX_QL_QVEIDENTITY_MISMATCH;
        }

        if (p_qve_report->body.isv_svn < LEAST_QVE_ISVSVN)
        {
            return SGX_QL_QVE_OUT_OF_DATE;
        }

        ret = SGX_QL_SUCCESS;
    }
    catch (...)
    {
    }

    return ret;
}

static quote3_error_t generate_qae_report_for_appraisal(const char *p_verification_result_token,
                                                        uint8_t **p_qaps,
                                                        uint8_t qaps_count,
                                                        time_t appraisal_check_date,
                                                        const char *p_appraisal_result_token,
                                                        sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = {0};
    sgx_report_t qae_report;
    memset(&qae_report, 0, sizeof(qae_report));
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    // Report data = SHA384(nonce || qvl_result || policy array || appraisal result || appraisal check date) || 0-padding
    do
    {
        sgx_ret = sgx_sha384_init(&sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&p_qae_report_info->nonce), sizeof(p_qae_report_info->nonce), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(p_verification_result_token), (uint32_t)strlen(p_verification_result_token), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        for (uint8_t i = 0; i < qaps_count; i++)
        {
            sgx_ret = sgx_sha384_update(p_qaps[i], (uint32_t)strlen(reinterpret_cast<const char *>(p_qaps[i])), sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(p_appraisal_result_token), (uint32_t)strlen(p_appraisal_result_token), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&appraisal_check_date), sizeof(appraisal_check_date), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        sgx_ret = sgx_sha384_get_hash(sha_handle, reinterpret_cast<sgx_sha384_hash_t *>(&report_data));
        CHECK_SGX_ERROR_BREAK(sgx_ret);
    } while (0);

    if (sha_handle)
    {
        sgx_sha384_close(sha_handle);
    }
    if (sgx_ret != SGX_SUCCESS)
    {
        ret = (sgx_ret == SGX_ERROR_OUT_OF_MEMORY) ? SGX_QL_ERROR_OUT_OF_MEMORY : SGX_QL_ERROR_UNEXPECTED;
        return ret;
    }
    sgx_ret = sgx_create_report(&p_qae_report_info->app_enclave_target_info, &report_data, &qae_report);
    if (sgx_ret != SGX_SUCCESS)
    {
        return ret;
    }
    memcpy(&p_qae_report_info->qe_report, &qae_report, sizeof(qae_report));
    return SGX_QL_SUCCESS;
}

quote3_error_t qae_appraise_quote_result(const char *p_verification_result_token,
                                         uint8_t **p_qaps,
                                         uint8_t qaps_count,
                                         time_t appraisal_check_date,
                                         sgx_ql_qe_report_info_t *p_qae_report_info,
                                         uint32_t *p_appraisal_result_token_buffer_size,
                                         uint8_t **p_appraisal_result_token)
{
    if (p_verification_result_token == NULL || !sgx_is_within_enclave(p_verification_result_token, strlen(p_verification_result_token)))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_qaps == NULL || !sgx_is_within_enclave(p_qaps, qaps_count * sizeof(uint8_t *)) || qaps_count == 0)
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
    if (p_qae_report_info == NULL || !sgx_is_within_enclave(p_qae_report_info, sizeof(sgx_ql_qe_report_info_t)))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_appraisal_result_token_buffer_size == NULL ||
       !sgx_is_within_enclave(p_appraisal_result_token_buffer_size, sizeof(p_appraisal_result_token_buffer_size)) ||
       p_appraisal_result_token == NULL || !sgx_is_within_enclave(p_appraisal_result_token, sizeof(p_appraisal_result_token)))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint32_t tmp_appraisal_result_buf_size = 0;
    uint8_t *tmp_appraisal_result_token = NULL;
    std::string json_str = "";
    uint8_t **tmp_qaps = NULL;
    int res = 0;
    uint8_t *buf = NULL;
    uint8_t i = 0;

    // Verify QvE report and identity
    ret = verify_qve_report_and_identity(p_verification_result_token, p_qae_report_info);
    if (ret != SGX_QL_SUCCESS)
    {
        return ret;
    }
    do
    {
        // Copy the policies to QAE before appraise
        tmp_qaps = (uint8_t **)malloc(qaps_count * sizeof(uint8_t *));
        if (tmp_qaps == NULL)
        {
            ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }
        memset(tmp_qaps, 0, qaps_count * sizeof(uint8_t *));

        for (; i < qaps_count; i++)
        {
            const char *policy = (char *)p_qaps[i];
            uint8_t *p = (uint8_t *)malloc(strlen(policy)+1);
            if (p == NULL)
            {
                ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }
            memcpy(p, policy, strlen(policy));
            p[strlen(policy)] = '\0';
            tmp_qaps[i] = p;
        }
        if (i < qaps_count)
        {
            break;
        }
        // Start appraise
        try
        {
            ret = construct_complete_json(reinterpret_cast<const uint8_t *>(p_verification_result_token), tmp_qaps, qaps_count, json_str);

            if (ret != SGX_QL_SUCCESS)
            {
                break;
            }
        }
        catch (...)
        {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        OPAEvaluateEngine instance;
        ret = instance.prepare_wasm();
        if (ret != SGX_QL_SUCCESS)
        {
            break;
        }

        ret = instance.start_eval(reinterpret_cast<const uint8_t *>(json_str.c_str()), (uint32_t)(json_str.length() + 1),
                                  appraisal_check_date, &tmp_appraisal_result_buf_size, &tmp_appraisal_result_token);
        if (ret != SGX_QL_SUCCESS)
        {
            break;
        }

        // Generate QAE report based on the target info of application enclave
        ret = generate_qae_report_for_appraisal(p_verification_result_token, tmp_qaps, qaps_count, appraisal_check_date,
                                  reinterpret_cast<const char *>(tmp_appraisal_result_token), p_qae_report_info);
        if (ret != SGX_QL_SUCCESS)
        {
            break;
        }

        // Allocate buf outside and copy the appraisal result outside
        sgx_status_t sgx_ret = ocall_malloc(&res, &buf, tmp_appraisal_result_buf_size);
        if (sgx_ret != SGX_SUCCESS)
        {
            ret = (sgx_ret == SGX_ERROR_OUT_OF_MEMORY) ? SGX_QL_ERROR_OUT_OF_MEMORY : SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        if (res != 1)
        {
            ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }
        // reject any pointer that falls inside the EPC
        if (buf == NULL || !sgx_is_outside_enclave(buf, tmp_appraisal_result_buf_size))
        {
            ret = SGX_QL_ERROR_UNEXPECTED;
            break;
        }
        memcpy(buf, tmp_appraisal_result_token, tmp_appraisal_result_buf_size);
        *p_appraisal_result_token_buffer_size = tmp_appraisal_result_buf_size;
        *p_appraisal_result_token = buf;
        ret = SGX_QL_SUCCESS;

    } while (0);

    if (tmp_qaps)
    {
        for (i = 0; i < qaps_count; i++)
        {
            if (tmp_qaps[i])
            {
                free(tmp_qaps[i]);
            }
        }
        free(tmp_qaps);
    }
    if (tmp_appraisal_result_token)
    {
        free(tmp_appraisal_result_token);
    }
    return ret;
}

static quote3_error_t generate_qae_report_for_authentication(const uint8_t *p_quote,
                                                             uint32_t quote_size,
                                                             const char *p_appraisal_result_token,
                                                             const tee_policy_bundle_t *p_policies,
                                                             tee_policy_auth_result_t result,
                                                             sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = {0};
    sgx_report_t qae_report;
    memset(&qae_report, 0, sizeof(qae_report));
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    // Report data = SHA384(nonce || p_appraisal_result_token || p_policies || result || (optional quote)) || 0-padding
    do
    {
        sgx_ret = sgx_sha384_init(&sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&p_qae_report_info->nonce), sizeof(p_qae_report_info->nonce), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(p_appraisal_result_token), (uint32_t)strlen(p_appraisal_result_token), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        if (p_policies->p_tenant_identity_policy)
        {
            sgx_ret = sgx_sha384_update(p_policies->p_tenant_identity_policy, (uint32_t)strlen((const char *)p_policies->p_tenant_identity_policy), sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }

        if (p_policies->platform_policy.p_policy)
        {
            sgx_ret = sgx_sha384_update(p_policies->platform_policy.p_policy, (uint32_t)strlen((const char *)(p_policies->platform_policy.p_policy)), sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&p_policies->platform_policy.pt), sizeof(p_policies->platform_policy.pt), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        if (p_policies->tdqe_policy.p_policy)
        {
            sgx_ret = sgx_sha384_update(p_policies->tdqe_policy.p_policy, (uint32_t)strlen((const char *)(p_policies->tdqe_policy.p_policy)), sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&p_policies->tdqe_policy.pt), sizeof(p_policies->tdqe_policy.pt), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&result), sizeof(result), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        if(p_quote && quote_size != 0)
        {
            sgx_ret = sgx_sha384_update(p_quote, quote_size, sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }

        sgx_ret = sgx_sha384_get_hash(sha_handle, reinterpret_cast<sgx_sha384_hash_t *>(&report_data));
        CHECK_SGX_ERROR_BREAK(sgx_ret);
    } while (0);

    if (sha_handle)
    {
        sgx_sha384_close(sha_handle);
    }
    if (sgx_ret != SGX_SUCCESS)
    {
        ret = (sgx_ret == SGX_ERROR_OUT_OF_MEMORY) ? SGX_QL_ERROR_OUT_OF_MEMORY : SGX_QL_ERROR_UNEXPECTED;
        return ret;
    }
    sgx_ret = sgx_create_report(&p_qae_report_info->app_enclave_target_info, &report_data, &qae_report);
    if (sgx_ret != SGX_SUCCESS)
    {
        return ret;
    }
    memcpy(&p_qae_report_info->qe_report, &qae_report, sizeof(qae_report));
    return SGX_QL_SUCCESS;
}

quote3_error_t qae_authenticate_appraisal_result(const uint8_t *p_quote,
                                                 uint32_t quote_size,
                                                 const char *p_appraisal_result_token,
                                                 const tee_policy_bundle_t *p_policies,
                                                 tee_policy_auth_result_t *result,
                                                 sgx_ql_qe_report_info_t *p_qae_report_info)
{
    if ((p_quote != NULL && quote_size == 0) || (p_quote == NULL && quote_size != 0) ||
        (p_quote != NULL && quote_size != 0 && sgx_is_within_enclave(p_quote, quote_size) == 0))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_appraisal_result_token == NULL || 
        sgx_is_within_enclave(p_appraisal_result_token, strlen(p_appraisal_result_token)) == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_policies == NULL || sgx_is_within_enclave(p_policies, sizeof(*p_policies)) == 0)
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
    if (result == NULL || p_qae_report_info == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    tee_policy_bundle_t tmp_policies;
    memset(&tmp_policies, 0, sizeof(tmp_policies));
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint8_t *ptr = NULL;
    size_t str_size = 0;

    do
    {
        // Copy policies to enclave before operation
        if (p_policies->p_tenant_identity_policy)
        {
            str_size = strlen((const char *)(p_policies->p_tenant_identity_policy));
            ptr = (uint8_t *)malloc(str_size + 1);
            CHECK_NULL_BREAK(ptr);
            memcpy(ptr, p_policies->p_tenant_identity_policy, str_size + 1);
            tmp_policies.p_tenant_identity_policy = ptr;
        }
        if (p_policies->platform_policy.p_policy)
        {
            str_size = strlen((const char *)(p_policies->platform_policy.p_policy));
            ptr = (uint8_t *)malloc(str_size + 1);
            CHECK_NULL_BREAK(ptr);
            memcpy(ptr, p_policies->platform_policy.p_policy, str_size + 1);
            tmp_policies.platform_policy.p_policy = ptr;
        }
        tmp_policies.platform_policy.pt = p_policies->platform_policy.pt;
        if (p_policies->tdqe_policy.p_policy)
        {
            str_size = strlen((const char *)(p_policies->tdqe_policy.p_policy));
            ptr = (uint8_t *)malloc(str_size + 1);
            CHECK_NULL_BREAK(ptr);
            memcpy(ptr, p_policies->tdqe_policy.p_policy, str_size + 1);
            tmp_policies.tdqe_policy.p_policy = ptr;
        }
        tmp_policies.tdqe_policy.pt = p_policies->tdqe_policy.pt;

        try
        {
            ret = authenticate_appraisal_result_internal(p_quote, quote_size, p_appraisal_result_token, p_policies, result);
            if (ret != SGX_QL_SUCCESS)
                break;
        }
        catch (...)
        {
            ret = SGX_QL_ERROR_UNEXPECTED;
            if (tmp_policies.p_tenant_identity_policy)
            {
                free((void *)tmp_policies.p_tenant_identity_policy);
            }
            if (tmp_policies.platform_policy.p_policy)
            {
                free((void *)tmp_policies.platform_policy.p_policy);
            }
            if (tmp_policies.tdqe_policy.p_policy)
            {
                free((void *)tmp_policies.tdqe_policy.p_policy);
            }

            return ret;
        }
        // Generate QAE report
        ret = generate_qae_report_for_authentication(p_quote, quote_size, p_appraisal_result_token, &tmp_policies, *result, p_qae_report_info);

    } while (0);

    if (tmp_policies.p_tenant_identity_policy)
    {
        free((void *)tmp_policies.p_tenant_identity_policy);
    }
    if (tmp_policies.platform_policy.p_policy)
    {
        free((void *)tmp_policies.platform_policy.p_policy);
    }
    if (tmp_policies.tdqe_policy.p_policy)
    {
        free((void *)tmp_policies.tdqe_policy.p_policy);
    }

    return ret;
}

static quote3_error_t generate_qae_report_for_auth_policy_owner(const uint8_t *p_quote,
                                                                uint32_t quote_size,
                                                                const char *p_appraisal_result_token,
                                                                const uint8_t **policy_key_list,
                                                                uint32_t list_size,
                                                                tee_policy_auth_result_t result,
                                                                sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = {0};
    sgx_report_t qae_report;
    memset(&qae_report, 0, sizeof(qae_report));
    sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;

    // Report data = SHA384(nonce || p_appraisal_result_token || policy_key_list || result || (optional quote)) || 0-padding
    do
    {
        sgx_ret = sgx_sha384_init(&sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&p_qae_report_info->nonce), sizeof(p_qae_report_info->nonce), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(p_appraisal_result_token), (uint32_t)strlen(p_appraisal_result_token), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        for (uint8_t i = 0; i < list_size; i++)
        {
            sgx_ret = sgx_sha384_update(policy_key_list[i], (uint32_t)strlen(reinterpret_cast<const char *>(policy_key_list[i])), sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }
        CHECK_SGX_ERROR_BREAK(sgx_ret);
        sgx_ret = sgx_sha384_update(reinterpret_cast<const uint8_t *>(&result), sizeof(result), sha_handle);
        CHECK_SGX_ERROR_BREAK(sgx_ret);

        if (p_quote && quote_size != 0)
        {
            sgx_ret = sgx_sha384_update(p_quote, quote_size, sha_handle);
            CHECK_SGX_ERROR_BREAK(sgx_ret);
        }

        sgx_ret = sgx_sha384_get_hash(sha_handle, reinterpret_cast<sgx_sha384_hash_t *>(&report_data));
        CHECK_SGX_ERROR_BREAK(sgx_ret);
    } while (0);

    if (sha_handle)
    {
        sgx_sha384_close(sha_handle);
    }
    if (sgx_ret != SGX_SUCCESS)
    {
        ret = (sgx_ret == SGX_ERROR_OUT_OF_MEMORY) ? SGX_QL_ERROR_OUT_OF_MEMORY : SGX_QL_ERROR_UNEXPECTED;
        return ret;
    }
    sgx_ret = sgx_create_report(&p_qae_report_info->app_enclave_target_info, &report_data, &qae_report);
    if (sgx_ret != SGX_SUCCESS)
    {
        return ret;
    }
    memcpy(&p_qae_report_info->qe_report, &qae_report, sizeof(qae_report));
    return SGX_QL_SUCCESS;
}

quote3_error_t qae_authenticate_policy_owner(const uint8_t *p_quote,
                                             uint32_t quote_size,
                                             const char *p_appraisal_result_token,
                                             const uint8_t **policy_key_list,
                                             uint32_t list_size,
                                             tee_policy_auth_result_t *result,
                                             sgx_ql_qe_report_info_t *p_qae_report_info)
{
    if ((p_quote != NULL && quote_size == 0) || (p_quote == NULL && quote_size != 0) ||
        (p_quote != NULL && quote_size != 0 && sgx_is_within_enclave(p_quote, quote_size) == 0))
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (p_appraisal_result_token == NULL || 
        sgx_is_within_enclave(p_appraisal_result_token, strlen(p_appraisal_result_token)) == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (policy_key_list == NULL || sgx_is_within_enclave(policy_key_list, list_size * sizeof(uint8_t *)) == 0 || list_size == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    for (uint8_t i = 0; i < list_size; i++)
    {
        if (policy_key_list[i] == NULL)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }

    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint8_t **tmp_key_policy_list = NULL;
    uint8_t i = 0;
    do
    {
        // Copy the policies to QAE before appraise
        tmp_key_policy_list = (uint8_t **)malloc(list_size * sizeof(uint8_t *));
        if (tmp_key_policy_list == NULL)
        {
            ret = SGX_QL_ERROR_OUT_OF_MEMORY;
            break;
        }
        memset(tmp_key_policy_list, 0, list_size * sizeof(uint8_t *));
        for (; i < list_size; i++)
        {
            const char *key = (const char *)policy_key_list[i];
            uint8_t *p = (uint8_t *)malloc(strlen(key) + 1);
            if (p == NULL)
            {
                ret = SGX_QL_ERROR_OUT_OF_MEMORY;
                break;
            }
            memcpy(p, key, strlen(key));
            p[strlen(key)] = '\0';
            tmp_key_policy_list[i] = p;
        }
        if (i < list_size)
        {
            break;
        }
        try
        {
            ret = authenticate_policy_owner_internal(p_quote, quote_size, p_appraisal_result_token, reinterpret_cast<const char **>(policy_key_list), list_size, result);
            if (ret != SGX_QL_SUCCESS)
                break;
        }
        catch (...)
        {
            if (tmp_key_policy_list)
            {
                for (i = 0; i < list_size; i++)
                {
                    if (tmp_key_policy_list[i])
                    {
                        free(tmp_key_policy_list[i]);
                    }
                }
                free(tmp_key_policy_list);
            }
            return SGX_QL_ERROR_UNEXPECTED;
        }
        // Generate QAE report
        ret = generate_qae_report_for_auth_policy_owner(p_quote, quote_size, p_appraisal_result_token, policy_key_list, list_size, *result, p_qae_report_info);
    } while (0);

    if (tmp_key_policy_list)
    {
        for (i = 0; i < list_size; i++)
        {
            if (tmp_key_policy_list[i])
            {
                free(tmp_key_policy_list[i]);
            }
        }
        free(tmp_key_policy_list);
    }

    return ret;
}