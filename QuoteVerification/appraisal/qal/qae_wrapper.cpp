/**
 * Copyright (c) 2011-2025, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of Intel Corporation nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <mutex>
#include "sgx_urts.h"
#include "qae_u.h"
#include "sgx_error.h"
#include "qae_wrapper.h"
#include "sgx_dcap_qal.h"
#include "se_trace.h"
#include "metadata.h"
#include "sgx_urts_wrapper.h"
#include "qal_common.h"
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

#define QAE_NAME "libsgx_qae.signed.so"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

static constexpr size_t kQaePathBufferSize = MAX_PATH + 1;

struct qae_info_t
{
    sgx_enclave_id_t m_qae_eid;
    sgx_ql_request_policy_t m_qae_policy;
    bool m_qae_policy_flag;
    sgx_target_info_t m_qae_target_info;
    char m_qae_path[kQaePathBufferSize];
    std::mutex m_qae_mutex;
    qae_info_t():
    m_qae_eid(0),
    m_qae_policy(SGX_QL_PERSISTENT),
    m_qae_policy_flag(false)
    {
        memset(&m_qae_target_info, 0, sizeof(m_qae_target_info));
        memset(m_qae_path, 0, kQaePathBufferSize);
    }
    qae_info_t(const qae_info_t&);
    qae_info_t& operator=(const qae_info_t&);
};

static qae_info_t s_qae_info;

// Set QAE loading policy. This API should be only called once per process.
quote3_error_t sgx_qae_set_enclave_load_policy(sgx_ql_request_policy_t policy)
{
    if (policy < SGX_QL_PERSISTENT || policy > SGX_QL_EPHEMERAL)
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;

    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    if(s_qae_info.m_qae_policy_flag == true)
    {
        se_trace(SE_TRACE_ERROR, "QAE loading policy has been set in current process\n");
        return SGX_QL_UNSUPPORTED_LOADING_POLICY;
    }
    s_qae_info.m_qae_policy = policy;
    s_qae_info.m_qae_policy_flag = true;
    return SGX_QL_SUCCESS;
}

static bool get_qae_path(
    char *p_file_path,
    size_t buf_size)
{
    if (!p_file_path)
        return false;

    Dl_info dl_info;
    if (s_qae_info.m_qae_path[0])
    {
        strncpy(p_file_path, s_qae_info.m_qae_path, buf_size - 1);
        p_file_path[buf_size - 1] = '\0'; // null terminate the string
        return true;
    }
    else if (0 != dladdr(__builtin_return_address(0), &dl_info) &&
             NULL != dl_info.dli_fname)
    {
        if (strnlen(dl_info.dli_fname, buf_size) >= buf_size)
            return false;
        (void)strncpy(p_file_path, dl_info.dli_fname, buf_size);
    }
    else // not a dynamic executable
    {
        ssize_t i = readlink("/proc/self/exe", p_file_path, buf_size - 1);
        if (i == -1)
            return false;
        p_file_path[i] = '\0';
    }

    char *p_last_slash = strrchr(p_file_path, '/');
    if (p_last_slash != NULL)
    {
        p_last_slash++;       // increment beyond the last slash
        *p_last_slash = '\0'; // null terminate the string
    }
    else
    {
        p_file_path[0] = '\0';
    }
    if (strnlen(p_file_path, buf_size) + strnlen(QAE_NAME, buf_size) + sizeof(char) > buf_size)
    {
        return false;
    }
    (void)strncat(p_file_path, QAE_NAME, strnlen(QAE_NAME, buf_size));
    struct stat info;
    if (stat(p_file_path, &info) != 0 ||
        ((info.st_mode & S_IFREG) == 0 && (info.st_mode & S_IFLNK) == 0))
    {
        if (p_last_slash != NULL)
        {
            *p_last_slash = '\0'; // null terminate the string
        }
        else
        {
            p_file_path[0] = '\0';
        }
        (void)strncat(p_file_path, QAE_NAME, strnlen(QAE_NAME, buf_size));
    }
    return true;
}

void unload_qae_atexit()
{
    if (s_qae_info.m_qae_eid != 0)
    {
        unload_enclave(s_qae_info.m_qae_eid, true);
    }
}

quote3_error_t load_enclave(sgx_enclave_id_t *eid, sgx_target_info_t *p_qae_target_info)
{
    if(eid == NULL)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    quote3_error_t retval = SGX_QL_ERROR_UNEXPECTED;
    char qae_path[kQaePathBufferSize] = "";
    metadata_t metadata;
    sgx_misc_attribute_t misc_attr;
    memset(&metadata, 0, sizeof(metadata_t));
    memset(&misc_attr, 0, sizeof(misc_attr));

    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    if (s_qae_info.m_qae_eid == 0)
    {
        if (get_qae_path(qae_path, kQaePathBufferSize) != true)
        {
            return retval;
        }
        if (!sgx_dcap_load_urts())
        {
            return SGX_QL_ERROR_UNEXPECTED;
        }
        if (!p_sgx_urts_create_enclave || !p_sgx_urts_get_metadata)
        {
            return SGX_QL_ERROR_UNEXPECTED;
        }
        sgx_status_t ret = p_sgx_urts_get_metadata(qae_path, &metadata);
        if (ret != SGX_SUCCESS)
        {
            return SGX_QL_ERROR_UNEXPECTED;
        }
        ret = p_sgx_urts_create_enclave(qae_path, 0, NULL, NULL, &s_qae_info.m_qae_eid, &misc_attr);
        if (ret != SGX_SUCCESS)
        {
            if (ret == SGX_ERROR_OUT_OF_MEMORY)
                retval = SGX_QL_ERROR_OUT_OF_MEMORY;
            else if (ret == SGX_ERROR_OUT_OF_EPC)
                retval = SGX_QL_OUT_OF_EPC;
            else
                retval = SGX_QL_ERROR_UNEXPECTED;

            return retval;
        }
        if(s_qae_info.m_qae_policy == SGX_QL_PERSISTENT)
        {
            // register an atexit() callback function to unload the QAE for persistent mode
            atexit(unload_qae_atexit);
        }

        memcpy(&s_qae_info.m_qae_target_info.attributes, &misc_attr.secs_attr, sizeof(sgx_attributes_t));
        memcpy(&s_qae_info.m_qae_target_info.mr_enclave, &metadata.enclave_css.body.enclave_hash, sizeof(sgx_measurement_t));
        s_qae_info.m_qae_target_info.misc_select = misc_attr.misc_select;

        *eid = s_qae_info.m_qae_eid;
        retval = SGX_QL_SUCCESS;
    }
    else
    {
        *eid = s_qae_info.m_qae_eid;
        retval = SGX_QL_SUCCESS;
    }

    if (p_qae_target_info)
    {
        memcpy(p_qae_target_info, &s_qae_info.m_qae_target_info, sizeof(sgx_target_info_t));
    }
    return retval;
}

void unload_enclave(sgx_enclave_id_t eid, bool force)
{
    assert(eid == s_qae_info.m_qae_eid);
    UNUSED(eid);
    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    if (s_qae_info.m_qae_eid && (force || s_qae_info.m_qae_policy == SGX_QL_EPHEMERAL))
    {
        if (!sgx_dcap_load_urts() || !p_sgx_urts_destroy_enclave)
        {
            abort();
        }
        SE_TRACE_NOTICE("Unload SGX QAE %#x\n", s_qae_info.m_qae_eid);
        p_sgx_urts_destroy_enclave(s_qae_info.m_qae_eid);
        s_qae_info.m_qae_eid = 0;
    }
    return;
}

quote3_error_t ecall_appraise_quote_result(sgx_enclave_id_t eid,
                                           uint8_t *wasm_buf,
                                           size_t wasm_size,
                                           const uint8_t *p_verification_result_token,
                                           uint8_t **p_qaps,
                                           uint8_t qaps_count,
                                           const time_t appraisal_check_date,
                                           sgx_ql_qe_report_info_t *p_qae_report_info,
                                           uint32_t *p_appraisal_result_token_buffer_size,
                                           uint8_t **p_appraisal_result_token)
{
    quote3_error_t retval = SGX_QL_ERROR_UNEXPECTED;
    assert(eid == s_qae_info.m_qae_eid);
    UNUSED(eid);
    if (p_verification_result_token == NULL || p_qaps == NULL || qaps_count == 0 || p_qae_report_info == NULL ||
        p_appraisal_result_token_buffer_size == NULL || p_appraisal_result_token == NULL)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    sgx_status_t ret = qae_appraise_quote_result(s_qae_info.m_qae_eid,
                                                 &retval,
                                                 wasm_buf,
                                                 wasm_size,
                                                 reinterpret_cast<const char *>(p_verification_result_token),
                                                 p_qaps,
                                                 qaps_count,
                                                 appraisal_check_date,
                                                 p_qae_report_info,
                                                 p_appraisal_result_token_buffer_size,
                                                 p_appraisal_result_token);
    if (SGX_SUCCESS != ret)
    {
        if (ret == SGX_ERROR_OUT_OF_MEMORY)
            retval = SGX_QL_ERROR_OUT_OF_MEMORY;
        else if (ret == SGX_ERROR_OUT_OF_EPC)
            retval = SGX_QL_OUT_OF_EPC;
        else if (ret == SGX_ERROR_INVALID_ENCLAVE_ID)
            retval = SGX_QL_ENCLAVE_LOST;
        else
            retval = SGX_QL_ERROR_UNEXPECTED;
    }
    return retval;
}

quote3_error_t ecall_authenticate_appraisal_result(sgx_enclave_id_t eid,
                                                   const uint8_t *p_quote,
                                                   uint32_t quote_size,
                                                   const uint8_t *p_appraisal_result_token,
                                                   const tee_policy_bundle_t *p_policies,
                                                   tee_policy_auth_result_t *result,
                                                   sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t retval = SGX_QL_ERROR_UNEXPECTED;
    assert(s_qae_info.m_qae_eid == eid);
    UNUSED(eid);

    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    sgx_status_t ret = qae_authenticate_appraisal_result(s_qae_info.m_qae_eid,
                                                         &retval,
                                                         p_quote,
                                                         quote_size,
                                                         reinterpret_cast<const char *>(p_appraisal_result_token),
                                                         p_policies,
                                                         result,
                                                         p_qae_report_info);
    if (SGX_SUCCESS != ret)
    {
        if (ret == SGX_ERROR_OUT_OF_MEMORY)
            retval = SGX_QL_ERROR_OUT_OF_MEMORY;
        else if (ret == SGX_ERROR_OUT_OF_EPC)
            retval = SGX_QL_OUT_OF_EPC;
        else if (ret == SGX_ERROR_INVALID_ENCLAVE_ID)
            retval = SGX_QL_ENCLAVE_LOST;
        else
            retval = SGX_QL_ERROR_UNEXPECTED;
    }
    return retval;
}

quote3_error_t ecall_authenticate_policy_owner(sgx_enclave_id_t eid,
                                               const uint8_t *p_quote,
                                               uint32_t quote_size,
                                               const uint8_t *p_appraisal_result_token,
                                               const uint8_t **policy_key_list,
                                               uint32_t list_size,
                                               tee_policy_auth_result_t *result,
                                               sgx_ql_qe_report_info_t *p_qae_report_info)
{
    quote3_error_t retval = SGX_QL_ERROR_UNEXPECTED;
    assert(s_qae_info.m_qae_eid == eid);
    UNUSED(eid);

    std::lock_guard<std::mutex> lock(s_qae_info.m_qae_mutex);
    sgx_status_t ret = qae_authenticate_policy_owner(s_qae_info.m_qae_eid,
                                                    &retval,
                                                    p_quote,
                                                    quote_size,
                                                    reinterpret_cast<const char *>(p_appraisal_result_token),
                                                    policy_key_list,
                                                    list_size,
                                                    result,
                                                    p_qae_report_info);
    if (SGX_SUCCESS != ret)
    {
        if (ret == SGX_ERROR_OUT_OF_MEMORY)
            retval = SGX_QL_ERROR_OUT_OF_MEMORY;
        else if (ret == SGX_ERROR_OUT_OF_EPC)
            retval = SGX_QL_OUT_OF_EPC;
        else if (ret == SGX_ERROR_INVALID_ENCLAVE_ID)
            retval = SGX_QL_ENCLAVE_LOST;
        else
            retval = SGX_QL_ERROR_UNEXPECTED;
    }
    return retval;
}