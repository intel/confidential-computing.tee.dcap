/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause 
 */
/**
 * File: pce_wrapper.cpp
 *
 * Description: Wrapper functions for the
 * reference implementing the PCE
 * function defined in sgx_pce.h. This
 * would be replaced or used to wrap the
 * PSW defined interfaces to the PCE.
 *
 */

#include <stdio.h>
#include <limits.h>
#include "se_trace.h"
#include "se_memcpy.h"
#include "se_thread.h"
#include "sgx_urts.h"
#include "metadata.h"
#include "aeerror.h"
#include "sgx_pce.h"

#include "pce_u.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

static constexpr size_t kPcePathBufferSize = MAX_PATH + 1;

struct PCE_status {
    se_mutex_t m_pce_mutex;
    sgx_ql_request_policy_t m_pce_enclave_load_policy;
    sgx_enclave_id_t m_pce_eid;
    sgx_misc_attribute_t m_pce_attributes;
    metadata_t m_pce_metadata;
    char pce_path[kPcePathBufferSize];

    PCE_status() :
        m_pce_enclave_load_policy(SGX_QL_DEFAULT),
        m_pce_eid(0)
    {
        se_mutex_init(&m_pce_mutex);
        memset(&m_pce_attributes, 0, sizeof(m_pce_attributes));
        memset(&m_pce_metadata, 0, sizeof(m_pce_metadata));
        memset(pce_path, 0, sizeof(pce_path));
    }
    ~PCE_status() {
        if (m_pce_eid != 0) sgx_destroy_enclave(m_pce_eid);
        se_mutex_destroy(&m_pce_mutex);
    }
};

static PCE_status g_pce_status;

#if defined(_MSC_VER)
#include <tchar.h>
#define PATH_SEPARATOR '\\'
bool get_pce_path(TCHAR *p_file_path, size_t buf_size);
extern "C" sgx_status_t sgx_get_metadata(const TCHAR* enclave_file, metadata_t *metadata);
#define PCE_ENCLAVE_NAME _T("pce.signed.dll")
#else
#include <limits.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#define PATH_SEPARATOR '/'
extern "C" sgx_status_t sgx_get_metadata(const char* enclave_file, metadata_t *metadata);
#define PCE_ENCLAVE_NAME "libsgx_pce.signed.so.1"
#define PCE_ENCLAVE_NAME_LEGACY "libsgx_pce.signed.so"
bool get_pce_path(
    char *p_file_path,
    size_t buf_size)
{
    if(NULL == p_file_path || 0 == buf_size)
    {
        return false;
    }

    Dl_info dl_info;
    if(g_pce_status.pce_path[0])
    {
        strncpy(p_file_path, g_pce_status.pce_path, buf_size -1);
        p_file_path[buf_size - 1] = '\0';  //null terminate the string
        return true;
    }
    else if (*SGX_ENCLAVE_PATH)
    {
        if ((strlen(SGX_ENCLAVE_PATH) + 1 + strlen(PCE_ENCLAVE_NAME) + 1) > buf_size) {
            return false;
        }
        strcpy(p_file_path, SGX_ENCLAVE_PATH);
        strcat(p_file_path, "/");
        strcat(p_file_path, PCE_ENCLAVE_NAME);
    }
    else if(0 != dladdr(__builtin_return_address(0), &dl_info) &&
        NULL != dl_info.dli_fname)
    {
        if(strnlen(dl_info.dli_fname,buf_size)>=buf_size)
            return false;
        (void)strncpy(p_file_path,dl_info.dli_fname,buf_size);
    }
    else //not a dynamic executable
    {
        ssize_t i = readlink( "/proc/self/exe", p_file_path, buf_size - 1);
        if (i == -1
            || buf_size > PATH_MAX // make sure it is safe to do the type conversion, PATH_MAX is defined in limits.h and it is big enough
            || i == (ssize_t)buf_size) // in this case truncation may have occured, and p_file_path[i] is out of buffer.
            return false;
        p_file_path[i] = '\0';
    }

    char* p_last_slash = strrchr(p_file_path, '/' );
    if ( p_last_slash != NULL )
    {
        p_last_slash++;   //increment beyond the last slash
        *p_last_slash = '\0';  //null terminate the string
    }
    else p_file_path[0] = '\0';
    if(strnlen(p_file_path,buf_size)+strnlen(PCE_ENCLAVE_NAME,buf_size)+sizeof(char)>buf_size)
        return false;
    (void)strncat(p_file_path,PCE_ENCLAVE_NAME, strnlen(PCE_ENCLAVE_NAME,buf_size));
    struct stat info;
    if(stat(p_file_path, &info) != 0 ||
        ((info.st_mode & S_IFREG) == 0 && (info.st_mode & S_IFLNK) == 0)) {
        if ( p_last_slash != NULL )
        {
            *p_last_slash = '\0';  //null terminate the string
        }
        else p_file_path[0] = '\0';
        (void)strncat(p_file_path,PCE_ENCLAVE_NAME_LEGACY, strnlen(PCE_ENCLAVE_NAME_LEGACY,buf_size));
    }
    return true;
}
#endif

static sgx_pce_error_t load_pce(sgx_enclave_id_t *p_pce_eid,
    sgx_misc_attribute_t *p_pce_attributes,
    metadata_t *p_metadata)
{
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_pce_error_t ret = SGX_PCE_INTERFACE_UNAVAILABLE;
    int enclave_lost_retry_time = 1;
#if defined(_MSC_VER)
    TCHAR pce_enclave_path[kPcePathBufferSize] = _T("");
#else
    char pce_enclave_path[kPcePathBufferSize] = "";
#endif

    int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return SGX_PCE_INTERFACE_UNAVAILABLE;
    }

    do {
        // Load the PCE
        if (g_pce_status.m_pce_eid == 0)
        {
            if (!get_pce_path(pce_enclave_path, kPcePathBufferSize))
                break;
            if (SGX_SUCCESS != sgx_get_metadata(pce_enclave_path, &g_pce_status.m_pce_metadata))
                break;

            do
            {
                sgx_launch_token_t launch_token = { 0 };
                int launch_token_updated;
                SE_TRACE(SE_TRACE_NOTICE, "Call sgx_create_enclave for PCE. %s\n", pce_enclave_path);
                sgx_status = sgx_create_enclave(pce_enclave_path,
                    0,
                    &launch_token,
                    &launch_token_updated,
                    p_pce_eid,
                    p_pce_attributes);
                if (SGX_SUCCESS != sgx_status)
                {
                    SE_PROD_LOG("Error, call sgx_create_enclave for PCE fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
                }

                // Retry in case there was a power transition that resulted is losing the enclave.
            } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
            if (sgx_status != SGX_SUCCESS)
            {
                if (sgx_status == SGX_ERROR_OUT_OF_EPC)
                    ret = SGX_PCE_OUT_OF_EPC;
                else
                    ret = SGX_PCE_INTERFACE_UNAVAILABLE;
                break;
            }
            g_pce_status.m_pce_eid = *p_pce_eid;
            memcpy_s(&g_pce_status.m_pce_attributes, sizeof(sgx_misc_attribute_t), p_pce_attributes, sizeof(sgx_misc_attribute_t));
        }
        else {
            *p_pce_eid = g_pce_status.m_pce_eid;
            memcpy_s(p_pce_attributes, sizeof(sgx_misc_attribute_t), &g_pce_status.m_pce_attributes, sizeof(sgx_misc_attribute_t));
        }
        if (p_metadata)
                memcpy_s(p_metadata, sizeof(metadata_t), &g_pce_status.m_pce_metadata, sizeof(metadata_t));

        ret = SGX_PCE_SUCCESS;
    } while(0);

    rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return SGX_PCE_INTERFACE_UNAVAILABLE;
    }
    return ret;
}

static void unload_pce(bool force = false)
{
    int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
        return;
    }

    // Unload the PCE enclave
    if (g_pce_status.m_pce_eid &&
        (force || g_pce_status.m_pce_enclave_load_policy != SGX_QL_PERSISTENT)
        )
    {
        SE_TRACE(SE_TRACE_NOTICE, "unload pce enclave 0X%llX\n", g_pce_status.m_pce_eid);
        sgx_destroy_enclave(g_pce_status.m_pce_eid);
        g_pce_status.m_pce_eid = 0;
    }
    rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
    if (rc != 1)
    {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
        return;
    }
}

sgx_pce_error_t sgx_set_pce_enclave_load_policy(
    sgx_ql_request_policy_t policy)
{
    if (policy > SGX_QL_EPHEMERAL)
        return SGX_PCE_INVALID_PARAMETER;
    g_pce_status.m_pce_enclave_load_policy = policy;
    if (policy == SGX_QL_EPHEMERAL)
        unload_pce(true);
    return SGX_PCE_SUCCESS;
}
sgx_pce_error_t sgx_pce_get_target(sgx_target_info_t *p_target,
    sgx_isv_svn_t *p_isvsvn)
{
    sgx_misc_attribute_t pce_attributes;
    sgx_enclave_id_t pce_eid = 0;
    metadata_t metadata;
    if ((NULL == p_target) ||
        (NULL == p_isvsvn))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    // Load the PCE enclave
    sgx_pce_error_t pce_status = load_pce(&pce_eid,
        &pce_attributes,
        &metadata);
    if (SGX_PCE_SUCCESS != pce_status)
    {
        return pce_status;
    }
    unload_pce();

    memset(p_target, 0, sizeof(*p_target));
    memcpy_s(&p_target->attributes, sizeof(p_target->attributes),
        &pce_attributes.secs_attr, sizeof(pce_attributes.secs_attr));
    memcpy_s(&p_target->misc_select, sizeof(p_target->misc_select),
        &pce_attributes.misc_select, sizeof(pce_attributes.misc_select));
    memcpy_s(&p_target->mr_enclave, sizeof(p_target->mr_enclave),
        &metadata.enclave_css.body.enclave_hash, sizeof(metadata.enclave_css.body.enclave_hash));

    *p_isvsvn = metadata.enclave_css.body.isv_svn;

    return SGX_PCE_SUCCESS;
}

sgx_pce_error_t sgx_get_pce_info(const sgx_report_t *p_report,
    const uint8_t *p_pek,
    uint32_t pek_size,
    uint8_t crypto_suite,
    uint8_t *p_encrypted_ppid,
    uint32_t encrypted_ppid_size,
    uint32_t *p_encrypted_ppid_out_size,
    sgx_isv_svn_t* p_pce_isvsvn,
    uint16_t* p_pce_id,
    uint8_t *p_signature_scheme)
{
    sgx_pce_error_t pce_status = SGX_PCE_SUCCESS;
    sgx_enclave_id_t pce_eid = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_misc_attribute_t pce_attributes;
    uint32_t ae_error;
    uint32_t enclave_lost_retry_time = 1;
    pce_info_t pce_info;

    if ((NULL == p_report) ||
        (NULL == p_pek) ||
        (NULL == p_encrypted_ppid) ||
        (NULL == p_encrypted_ppid_out_size) ||
        (NULL == p_pce_isvsvn) ||
        (NULL == p_pce_id) ||
        (NULL == p_signature_scheme))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    do {
        // Load the PCE enclave
        pce_status = load_pce(&pce_eid,
            &pce_attributes,
            NULL);
        if (SGX_PCE_SUCCESS != pce_status)
        {
            return pce_status;
        }
        int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        // Call get_pc_info ecall
        sgx_status = get_pc_info(pce_eid,
            &ae_error,
            p_report,
            p_pek,
            pek_size,
            crypto_suite,
            p_encrypted_ppid,
            encrypted_ppid_size,
            p_encrypted_ppid_out_size,
            &pce_info,
            p_signature_scheme);
        rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        if (SGX_ERROR_ENCLAVE_LOST != sgx_status)
            break;
        unload_pce(true);
    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);

    if (SGX_SUCCESS != sgx_status)
    {
        SE_TRACE(SE_TRACE_ERROR, "call to get_pc_info() failed. sgx_status = %04x.\n", sgx_status);
        // /todo:  May want to retry on SGX_PCE_ENCLAVE_LOST caused by power transition
        if (SGX_ERROR_OUT_OF_EPC == sgx_status)
            pce_status = SGX_PCE_OUT_OF_EPC;
        else
            pce_status = SGX_PCE_INTERFACE_UNAVAILABLE;
    }
    else {
        switch (ae_error)
        {
        case AE_SUCCESS:
            *p_pce_isvsvn = pce_info.pce_isvn;
            *p_pce_id = pce_info.pce_id;
            pce_status = SGX_PCE_SUCCESS;
            break;
        case AE_INVALID_PARAMETER:
            pce_status = SGX_PCE_INVALID_PARAMETER;
            break;
        case PCE_INVALID_REPORT:
            pce_status = SGX_PCE_INVALID_REPORT;
            break;
        case PCE_CRYPTO_ERROR:
            pce_status = SGX_PCE_CRYPTO_ERROR;
            break;
        case PCE_INVALID_PRIVILEGE:
            pce_status = SGX_PCE_INVALID_PRIVILEGE;
            break;
        case AE_OUT_OF_MEMORY_ERROR:
            pce_status = SGX_PCE_OUT_OF_EPC;
            break;
        default:
            pce_status = SGX_PCE_UNEXPECTED;
        }
    }
    unload_pce();

    return pce_status;
}

sgx_pce_error_t sgx_get_pce_info_without_ppid(sgx_isv_svn_t* p_pce_isvsvn, uint16_t* p_pce_id)
{
    sgx_pce_error_t pce_status = SGX_PCE_SUCCESS;
    sgx_enclave_id_t pce_eid = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_misc_attribute_t pce_attributes;
    uint32_t ae_error;
    uint32_t enclave_lost_retry_time = 1;
    pce_info_t pce_info;

    if ((NULL == p_pce_isvsvn) ||
        (NULL == p_pce_id))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    do {
        // Load the PCE enclave
        pce_status = load_pce(&pce_eid,
            &pce_attributes,
            NULL);
        if (SGX_PCE_SUCCESS != pce_status)
        {
            return pce_status;
        }
        int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        // Call get_pc_info_without_ppid ecall
        sgx_status = get_pc_info_without_ppid(pce_eid, &ae_error, &pce_info);
        rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        if (SGX_ERROR_ENCLAVE_LOST != sgx_status)
            break;
        unload_pce(true);
    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);

    if (SGX_SUCCESS != sgx_status)
    {
        SE_TRACE(SE_TRACE_ERROR, "call to get_pc_info_without_ppid() failed. sgx_status = %04x.\n", sgx_status);
        // /todo:  May want to retry on SGX_PCE_ENCLAVE_LOST caused by power transition
        if (SGX_ERROR_OUT_OF_EPC == sgx_status)
            pce_status = SGX_PCE_OUT_OF_EPC;
        else
            pce_status = SGX_PCE_INTERFACE_UNAVAILABLE;
    }
    else {
        switch (ae_error)
        {
        case AE_SUCCESS:
            *p_pce_isvsvn = pce_info.pce_isvn;
            *p_pce_id = pce_info.pce_id;
            pce_status = SGX_PCE_SUCCESS;
            break;
        case AE_INVALID_PARAMETER:
            pce_status = SGX_PCE_INVALID_PARAMETER;
            break;
        default:
            pce_status = SGX_PCE_UNEXPECTED;
        }
    }
    unload_pce();

    return pce_status;
}

sgx_pce_error_t sgx_pce_sign_report(const sgx_isv_svn_t *p_isv_svn,
    const sgx_cpu_svn_t *p_cpu_svn,
    const sgx_report_t *p_report,
    uint8_t *p_sig,
    uint32_t sig_size,
    uint32_t *p_sig_out_size)
{
    sgx_pce_error_t pce_status = SGX_PCE_SUCCESS;
    sgx_enclave_id_t pce_eid = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_misc_attribute_t pce_attributes;
    uint32_t ae_error;
    uint32_t enclave_lost_retry_time = 1;
    psvn_t psvn;

    if ((NULL == p_cpu_svn) ||
        (NULL == p_isv_svn) ||
        (NULL == p_report) ||
        (NULL == p_sig) ||
        (NULL == p_sig_out_size))
    {
        return(SGX_PCE_INVALID_PARAMETER);
    }

    psvn.cpu_svn = *p_cpu_svn;
    psvn.isv_svn = *p_isv_svn;

    do {
        // Load the PCE enclave
        pce_status = load_pce(&pce_eid,
            &pce_attributes,
            NULL);
        if (SGX_PCE_SUCCESS != pce_status)
        {
            return pce_status;
        }
        int rc = se_mutex_lock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to lock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        // Call certify_enclave ecall
        sgx_status = certify_enclave(pce_eid,
            (uint32_t*)&ae_error,
            &psvn,
            p_report,
            (uint8_t*)p_sig,
            sig_size,
            p_sig_out_size);
        rc = se_mutex_unlock(&g_pce_status.m_pce_mutex);
        if (rc != 1)
        {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock mutex");
            return SGX_PCE_INTERFACE_UNAVAILABLE;
        }
        if (SGX_ERROR_ENCLAVE_LOST != sgx_status)
            break;
        unload_pce(true);
    } while (SGX_ERROR_ENCLAVE_LOST == sgx_status && enclave_lost_retry_time--);
    if (SGX_SUCCESS != sgx_status)
    {
        SE_TRACE(SE_TRACE_ERROR, "call to certify_enclave() failed. sgx_status = %04x.\n", sgx_status);
        if (SGX_ERROR_OUT_OF_EPC == sgx_status)
            pce_status = SGX_PCE_OUT_OF_EPC;
        else
            pce_status = SGX_PCE_INTERFACE_UNAVAILABLE;
    }
    else {
        switch (ae_error)
        {
        case AE_SUCCESS:
            pce_status = SGX_PCE_SUCCESS;
            break;
        case AE_INVALID_PARAMETER:
        case AE_INSUFFICIENT_DATA_IN_BUFFER:
            pce_status = SGX_PCE_INVALID_PARAMETER;
            break;
        case PCE_INVALID_REPORT:
            pce_status = SGX_PCE_INVALID_REPORT;
            break;
        case PCE_INVALID_PRIVILEGE:
            pce_status = SGX_PCE_INVALID_PRIVILEGE;
            break;
        case AE_OUT_OF_MEMORY_ERROR:
            pce_status = SGX_PCE_OUT_OF_EPC;
            break;
        ///@todo:  When the PCE is fixed to return PCE_INVALID_TCB, change this case to PCE_INVALID_TCB and
        // allow AE_FAILURE to defalut to SGX_PCE_UNEXPECTED.
        case AE_FAILURE:
            pce_status = SGX_PCE_INVALID_TCB;
            break;
        default:
            pce_status = SGX_PCE_UNEXPECTED;
        }
    }
    unload_pce();

    return pce_status;
}

sgx_pce_error_t sgx_set_pce_path(const char* p_path)
{
    // p_path isn't NULL, caller has checked it.
    // len <= sizeof(g_pce_status.pce_path)
    size_t len = strnlen(p_path, sizeof(g_pce_status.pce_path));
    // Make sure there is enough space for the '\0',
    // after this line len <= sizeof(g_pce_status.pce_path) - 1
    if(len > sizeof(g_pce_status.pce_path) - 1)
        return SGX_PCE_INVALID_PARAMETER;
#ifndef _MSC_VER
    strncpy(g_pce_status.pce_path, p_path, sizeof(g_pce_status.pce_path) - 1);
#else
    strncpy_s(g_pce_status.pce_path, sizeof(g_pce_status.pce_path), p_path, sizeof(g_pce_status.pce_path));
#endif
    g_pce_status.pce_path[len] = '\0';
    return SGX_PCE_SUCCESS;
}
