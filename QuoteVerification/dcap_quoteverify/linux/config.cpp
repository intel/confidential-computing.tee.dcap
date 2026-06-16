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
 * File: config.cpp
 *
 * Description: Load SGX uRTS & QPL on demand, then unload it in destructor
 *
 */

#include <dlfcn.h>
#include "sgx_dcap_pcs_com.h"
#include "sgx_urts_wrapper.h"
#include "se_trace.h"
#include "se_thread.h"
#include <sgx_pce.h>
#include "sgx_dcap_qv_internal.h"

#define MAX(x, y) (((x)>(y))?(x):(y))
#define PATH_SEPARATOR '/'

#define SGX_URTS_LIB_FILE_NAME "libsgx_urts.so.1"
#define SGX_URTS_LIB_FILE_NAME_V2 "libsgx_urts.so.2"
void *g_urts_handle = NULL;
se_mutex_t g_urts_mutex;

#ifndef GEN_STATIC
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME "libdcap_quoteprov.so.1"
#define SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY "libdcap_quoteprov.so"

void *g_qpl_handle = NULL;
se_mutex_t g_qpl_mutex;

sgx_get_quote_verification_collateral_func_t p_sgx_ql_get_quote_verification_collateral = NULL;
sgx_free_quote_verification_collateral_func_t p_sgx_ql_free_quote_verification_collateral = NULL;

sgx_ql_get_qve_identity_func_t p_sgx_ql_get_qve_identity = NULL;
sgx_ql_free_qve_identity_func_t p_sgx_ql_free_qve_identity = NULL;

sgx_ql_get_root_ca_crl_func_t p_sgx_ql_get_root_ca_crl = NULL;
sgx_ql_free_root_ca_crl_func_t p_sgx_ql_free_root_ca_crl = NULL;

tdx_get_quote_verification_collateral_func_t p_tdx_ql_get_quote_verification_collateral = NULL;
tdx_free_quote_verification_collateral_func_t p_tdx_ql_free_quote_verification_collateral = NULL;

sgx_qpl_global_init_func_t p_sgx_qpl_global_init = NULL;

tee_get_default_platform_policy_func_t p_tee_get_default_platform_policy = NULL;
tee_free_platform_policy_func_t p_tee_free_platform_policy = NULL;

#endif

sgx_create_enclave_func_t p_sgx_urts_create_enclave = NULL;
sgx_destroy_enclave_func_t p_sgx_urts_destroy_enclave = NULL;
sgx_ecall_func_t p_sgx_urts_ecall = NULL;
sgx_oc_cpuidex_func_t p_sgx_oc_cpuidex = NULL;
sgx_thread_wait_untrusted_event_ocall_func_t p_sgx_thread_wait_untrusted_event_ocall = NULL;
sgx_thread_set_untrusted_event_ocall_func_t p_sgx_thread_set_untrusted_event_ocall = NULL;
sgx_thread_setwait_untrusted_events_ocall_func_t p_sgx_thread_setwait_untrusted_events_ocall = NULL;
sgx_thread_set_multiple_untrusted_events_ocall_func_t p_sgx_thread_set_multiple_untrusted_events_ocall = NULL;
pthread_create_ocall_func_t p_pthread_create_ocall = NULL;
pthread_wait_timeout_ocall_func_t p_pthread_wait_timeout_ocall = NULL;
pthread_wakeup_ocall_func_t p_pthread_wakeup_ocall_func = NULL;
sgx_get_metadata_func_t p_sgx_urts_get_metadata = NULL;


#ifndef MAX_PATH
#define MAX_PATH 260
#endif
static char g_qpl_path[MAX_PATH];


extern "C" bool sgx_qv_set_qpl_path(const char* p_path)
{
    // p_path isn't NULL, caller has checked it.
    // len <= sizeof(g_qpl_path)
    size_t len = strnlen(p_path, sizeof(g_qpl_path));
    // Make sure there is enough space for the '\0'
    // after this line len <= sizeof(g_qpl_path) - 1
    if(len > sizeof(g_qpl_path) - 1)
        return false;
    strncpy(g_qpl_path, p_path, sizeof(g_qpl_path) - 1);
    // Make sure the full path is ended with "\0"
    g_qpl_path[len] = '\0';
    return true;
}

#ifndef GEN_STATIC
bool sgx_dcap_load_qpl()
{
    char *err = NULL;
    bool ret = false;

    int rc = se_mutex_lock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex\n");
        return false;
    }

    // don't include TDX related check due to user may use old version QPL
    //
    if (g_qpl_handle &&
            p_sgx_ql_get_quote_verification_collateral && p_sgx_ql_free_quote_verification_collateral &&
            p_sgx_ql_get_qve_identity && p_sgx_ql_free_qve_identity &&
            p_sgx_ql_get_root_ca_crl && p_sgx_ql_free_root_ca_crl) {

        rc = se_mutex_unlock(&g_qpl_mutex);
        if (rc != 1) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex\n");
            return false;
        }

        return true;
    }

    do {
        if (g_qpl_path[0]) {
            g_qpl_handle = dlopen(g_qpl_path, RTLD_LAZY);
            if (NULL == g_qpl_handle) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't find the Quote Provider library %s\n", g_qpl_path);
                 ret = false;
                 break;
             }
        }
        else {
            //try to dynamically load libdcap_quoteprov.so
            g_qpl_handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME, RTLD_LAZY);

            if (NULL == g_qpl_handle)
            {
                ///TODO:
                // This is a temporary solution to make sure the legacy library without a version suffix can be loaded.
                // We shall remove this when we have a major version change later and drop the backward compatible
                // support for old lib name.
                g_qpl_handle = dlopen(SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY, RTLD_LAZY);
            }
            if (g_qpl_handle == NULL) {
                fputs(dlerror(), stderr);
                SE_TRACE(SE_TRACE_ERROR, "Couldn't find the Quote Provider library %s or %s\n",
                    SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME,
                    SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME_LEGACY);
                break;
            }
        }

        // search for sgx_qpl_global_init in dcap_quoteprov library and call it if found
        p_sgx_qpl_global_init = (sgx_qpl_global_init_func_t)dlsym(g_qpl_handle, "sgx_qpl_global_init");
        if (dlerror() == NULL && p_sgx_qpl_global_init) {
            quote3_error_t ql_ret = p_sgx_qpl_global_init();
            if (ql_ret == SGX_QL_CONFIG_INVALID_JSON)
                SE_TRACE(SE_TRACE_WARNING, "QCNL has invalid json config file, fallback to legacy config file");
            else if (ql_ret != SGX_QL_SUCCESS) {
                SE_TRACE(SE_TRACE_ERROR, "Error returned from the sgx_qpl_global_init API. 0x%04x\n", ql_ret);
                break;
            }
        }

        //search for sgx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_quote_verification_collateral = (sgx_get_quote_verification_collateral_func_t)dlsym(g_qpl_handle, QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_sgx_ql_get_quote_verification_collateral == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_quote_verification_collateral = (sgx_free_quote_verification_collateral_func_t)dlsym(g_qpl_handle, QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_sgx_ql_free_quote_verification_collateral == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_qve_identity = (sgx_ql_get_qve_identity_func_t)dlsym(g_qpl_handle, QL_API_GET_QVE_IDENTITY);
        err = dlerror();
        if (p_sgx_ql_get_qve_identity == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_GET_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_qve_identity symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_qve_identity = (sgx_ql_free_qve_identity_func_t)dlsym(g_qpl_handle, QL_API_FREE_QVE_IDENTITY);
        err = dlerror();
        if (p_sgx_ql_free_qve_identity == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_FREE_QVE_IDENTITY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_get_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_get_root_ca_crl = (sgx_ql_get_root_ca_crl_func_t)dlsym(g_qpl_handle, QL_API_GET_ROOT_CA_CRL);
        err = dlerror();
        if (p_sgx_ql_get_root_ca_crl == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_GET_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for sgx_ql_free_root_ca_crl symbol in dcap_quoteprov library
        //
        p_sgx_ql_free_root_ca_crl = (sgx_ql_free_root_ca_crl_func_t)dlsym(g_qpl_handle, QL_API_FREE_ROOT_CA_CRL);
        err = dlerror();
        if (p_sgx_ql_free_root_ca_crl == NULL || err != NULL) {
            SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_FREE_ROOT_CA_CRL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
            break;
        }

        //search for tdx_ql_get_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_tdx_ql_get_quote_verification_collateral = (tdx_get_quote_verification_collateral_func_t)dlsym(g_qpl_handle, TDX_QL_API_GET_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_tdx_ql_get_quote_verification_collateral == NULL || err != NULL) {
            // don't return error due to user may use old version QPL
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote Provider library %s.\n", TDX_QL_API_GET_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
        }

        //search for sgx_ql_free_quote_verification_collateral symbol in dcap_quoteprov library
        //
        p_tdx_ql_free_quote_verification_collateral = (tdx_free_quote_verification_collateral_func_t)dlsym(g_qpl_handle, TDX_QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL);
        err = dlerror();
        if (p_tdx_ql_free_quote_verification_collateral == NULL || err != NULL) {
            // don't return error due to user may use old version QPL
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote Provider library %s.\n", TDX_QL_API_FREE_QUOTE_VERIFICATION_COLLATERAL, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
        }

        //search for tee_get_default_platform_policy symbol in dcap_quoteprov library
        //
        p_tee_get_default_platform_policy = (tee_get_default_platform_policy_func_t)dlsym(g_qpl_handle, QL_API_GET_DEFAULT_PLATFORM_POLICY);
        err = dlerror();
        if (p_tee_get_default_platform_policy == NULL || err != NULL) {
            // don't return error due to user may use old version QPL
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_GET_DEFAULT_PLATFORM_POLICY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
        }
        //search for tee_free_platform_policy symbol in dcap_quoteprov library
        //
        p_tee_free_platform_policy = (tee_free_platform_policy_func_t)dlsym(g_qpl_handle, QL_API_FREE_PLATFORM_POLICY);
        err = dlerror();
        if (p_tee_free_platform_policy == NULL || err != NULL) {
            // don't return error due to user may use old version QPL
            SE_TRACE(SE_TRACE_DEBUG, "Couldn't locate %s in Quote Provider library %s.\n", QL_API_FREE_PLATFORM_POLICY, SGX_QL_QUOTE_CONFIG_LIB_FILE_NAME);
        }

        ret = true;

    } while (0);


    rc = se_mutex_unlock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex\n");
        ret = false;
    }

    return ret;
}
#endif


bool sgx_dcap_load_urts()
{
    char *err = NULL;
    bool ret = false;

    int rc = se_mutex_lock(&g_urts_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock urts mutex\n");
        return false;
    }

    if (g_urts_handle &&
            p_sgx_urts_create_enclave &&
            p_sgx_urts_destroy_enclave &&
            p_sgx_urts_ecall ) {

        rc = se_mutex_unlock(&g_urts_mutex);
        if (rc != 1) {
            SE_TRACE(SE_TRACE_ERROR, "Failed to unlock urts mutex\n");
            return false;
        }

        return true;
    }

    do {
            //try to dynamically load libsgx_urts.so
            g_urts_handle = dlopen(SGX_URTS_LIB_FILE_NAME, RTLD_LAZY);

            if (g_urts_handle == NULL) {
                //try to load urts v2
                g_urts_handle = dlopen(SGX_URTS_LIB_FILE_NAME_V2, RTLD_LAZY);
                if (g_urts_handle == NULL) {
                    char *cerror = dlerror();
                    if(cerror != NULL){
                        fputs(cerror, stderr);
                    }
                    SE_TRACE(SE_TRACE_DEBUG, "Couldn't find urts library: %s, %s\n", SGX_URTS_LIB_FILE_NAME, SGX_URTS_LIB_FILE_NAME_V2);
                    break;
                }
            }

            //search for sgx_create_enclave symbol in urts library
            //
            p_sgx_urts_create_enclave = (sgx_create_enclave_func_t)dlsym(g_urts_handle, SGX_URTS_API_CREATE_ENCLAVE);
            err = dlerror();
            if (p_sgx_urts_create_enclave == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_CREATE_ENCLAVE, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_destroy_enclave symbol in urts library
            //
            p_sgx_urts_destroy_enclave = (sgx_destroy_enclave_func_t)dlsym(g_urts_handle, SGX_URTS_API_DESTROY_ENCLAVE);
            err = dlerror();
            if (p_sgx_urts_destroy_enclave == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_DESTROY_ENCLAVE, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_ecall symbol in urts library
            //
            p_sgx_urts_ecall = (sgx_ecall_func_t)dlsym(g_urts_handle, SGX_URTS_API_ECALL);
            err = dlerror();
            if (p_sgx_urts_ecall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_ECALL, SGX_URTS_LIB_FILE_NAME);
                break;
            }


            //search for sgx_oc_cpuidex symbol in urts library
            //
            p_sgx_oc_cpuidex = (sgx_oc_cpuidex_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_CPUID);
            err = dlerror();
            if (p_sgx_oc_cpuidex == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_CPUID, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_thread_wait_untrusted_event_ocall symbol in urts library
            //
            p_sgx_thread_wait_untrusted_event_ocall = (sgx_thread_wait_untrusted_event_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_WAIT_EVENT);
            err = dlerror();
            if (p_sgx_thread_wait_untrusted_event_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_WAIT_EVENT, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_thread_set_untrusted_event_ocall symbol in urts library
            //
            p_sgx_thread_set_untrusted_event_ocall = (sgx_thread_set_untrusted_event_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_SET_EVENT);
            err = dlerror();
            if (p_sgx_thread_set_untrusted_event_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_SET_EVENT, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_thread_setwait_untrusted_events_ocall symbol in urts library
            //
            p_sgx_thread_setwait_untrusted_events_ocall = (sgx_thread_setwait_untrusted_events_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_WAITSET_EVENT);
            err = dlerror();
            if (p_sgx_thread_setwait_untrusted_events_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_WAITSET_EVENT, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for sgx_thread_set_multiple_untrusted_events_ocall symbol in urts library
            //
            p_sgx_thread_set_multiple_untrusted_events_ocall = (sgx_thread_set_multiple_untrusted_events_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_SET_MULTIPLE_EVENT);
            err = dlerror();
            if (p_sgx_thread_set_multiple_untrusted_events_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_SET_MULTIPLE_EVENT, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for pthread_create_ocall symbol in urts library
            //
            p_pthread_create_ocall = (pthread_create_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_PTHREAD_CREATE);
            err = dlerror();
            if (p_pthread_create_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_PTHREAD_CREATE, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for pthread_wait_timeout_ocall symbol in urts library
            //
            p_pthread_wait_timeout_ocall = (pthread_wait_timeout_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_PTHREAD_TIMEOUT);
            err = dlerror();
            if (p_pthread_wait_timeout_ocall == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_PTHREAD_TIMEOUT, SGX_URTS_LIB_FILE_NAME);
                break;
            }

            //search for pthread_wakeup_ocall symbol in urts library
            //
            p_pthread_wakeup_ocall_func = (pthread_wakeup_ocall_func_t)dlsym(g_urts_handle, SGX_URTS_API_OCALL_PTHREAD_WAKEUP);
            err = dlerror();
            if (p_pthread_wakeup_ocall_func == NULL || err != NULL) {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_OCALL_PTHREAD_WAKEUP, SGX_URTS_LIB_FILE_NAME);
                break;
            }
            // search for sgx_get_metadata symbol in urts library
            p_sgx_urts_get_metadata = (sgx_get_metadata_func_t)dlsym(g_urts_handle, SGX_URTS_API_GET_METADATA);
            err = dlerror();
            if (p_sgx_urts_get_metadata == NULL || err != NULL)
            {
                SE_TRACE(SE_TRACE_ERROR, "Couldn't locate %s in urts library %s.\n", SGX_URTS_API_GET_METADATA, SGX_URTS_LIB_FILE_NAME);
                break;
            }
            ret = true;

    } while (0);


    rc = se_mutex_unlock(&g_urts_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock urts mutex\n");
        ret = false;
    }

    return ret;
}


/**
* Global constructor function of the sgx_dcap_quoteverify library. Will be called when .so is loaded
*/
__attribute__((constructor)) void _qv_global_constructor()
{
    se_mutex_init(&g_urts_mutex);

#ifndef GEN_STATIC
    se_mutex_init(&g_qpl_mutex);
#endif

    return;
}


/**
* Global destructor function of the sgx_dcap_quoteverify library. Will be called when .so is unloaded
*/
__attribute__((destructor)) void _qv_global_destructor()
{
    //Try to unload Quote Provider library
    //
    int rc = 0;

#ifndef GEN_STATIC
    rc = se_mutex_lock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock qpl mutex\n");
        //destroy the mutex before lib is unloaded, even there are some errs here
        se_mutex_destroy(&g_qpl_mutex);
        return;
    }

    if (p_sgx_ql_get_quote_verification_collateral)
        p_sgx_ql_get_quote_verification_collateral = NULL;
    if (p_sgx_ql_free_quote_verification_collateral)
        p_sgx_ql_free_quote_verification_collateral = NULL;

    if (p_sgx_ql_get_qve_identity)
        p_sgx_ql_get_qve_identity = NULL;
    if (p_sgx_ql_free_qve_identity)
        p_sgx_ql_free_qve_identity = NULL;

    if (p_sgx_ql_get_root_ca_crl)
        p_sgx_ql_get_root_ca_crl = NULL;
    if (p_sgx_ql_free_root_ca_crl)
        p_sgx_ql_free_root_ca_crl = NULL;

    if (p_tdx_ql_get_quote_verification_collateral)
        p_tdx_ql_get_quote_verification_collateral = NULL;
    if (p_tdx_ql_free_quote_verification_collateral)
        p_tdx_ql_free_quote_verification_collateral = NULL;

    if (p_tee_get_default_platform_policy)
        p_tee_get_default_platform_policy = NULL;
    if (p_tee_free_platform_policy)
        p_tee_free_platform_policy = NULL;

    if (g_qpl_handle)
    {
        dlclose(g_qpl_handle);
        g_qpl_handle = NULL;
    }

    rc = se_mutex_unlock(&g_qpl_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock qpl mutex\n");
    }

    se_mutex_destroy(&g_qpl_mutex);
#endif

    // Try to unload sgx urts library
    //
    rc = se_mutex_lock(&g_urts_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to lock urts mutex\n");
        //destroy the mutex before lib is unloaded, even there are some errs here
        se_mutex_destroy(&g_urts_mutex);
        return;
    }

    if (p_sgx_urts_create_enclave)
        p_sgx_urts_create_enclave = NULL;

    if (p_sgx_urts_destroy_enclave)
        p_sgx_urts_destroy_enclave = NULL;

    if (p_sgx_urts_ecall)
        p_sgx_urts_ecall = NULL;

    if (p_sgx_oc_cpuidex)
        p_sgx_oc_cpuidex = NULL;

    if (p_sgx_thread_wait_untrusted_event_ocall)
        p_sgx_thread_wait_untrusted_event_ocall = NULL;

    if (p_sgx_thread_set_untrusted_event_ocall)
        p_sgx_thread_set_untrusted_event_ocall = NULL;

    if (p_sgx_thread_setwait_untrusted_events_ocall)
        p_sgx_thread_setwait_untrusted_events_ocall = NULL;

    if (p_sgx_thread_set_multiple_untrusted_events_ocall)
        p_sgx_thread_set_multiple_untrusted_events_ocall = NULL;

    if (p_pthread_create_ocall)
        p_pthread_create_ocall = NULL;

    if (p_pthread_wait_timeout_ocall)
        p_pthread_wait_timeout_ocall = NULL;

    if (p_pthread_wakeup_ocall_func)
        p_pthread_wakeup_ocall_func = NULL;

    if (g_urts_handle) {
        dlclose(g_urts_handle);
        g_urts_handle = NULL;
    }

    rc = se_mutex_unlock(&g_urts_mutex);
    if (rc != 1) {
        SE_TRACE(SE_TRACE_ERROR, "Failed to unlock urts mutex\n");
    }

    se_mutex_destroy(&g_urts_mutex);
}
