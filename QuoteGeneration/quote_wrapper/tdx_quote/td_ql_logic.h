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
 * File: td_ql_logic.h
 *
 * Description: internal API definitions for TD quote library
 *
 */
#ifndef _TD_QL_LOGIC_H_
#define _TD_QL_LOGIC_H_
#include "se_thread.h"
#include <sgx_ql_lib_common.h>
#include "sgx_quote.h"
#include <sgx_quote_5.h>
#include "td_ql_wrapper.h"
#include "quoting_enclave_tdqe.h"

#ifndef _MSC_VER
    #include <pthread.h>
    #include <dlfcn.h>
    #define TCHAR char
    #define _T(x) (x)
#else
#include <tchar.h>
#include <windows.h>
#endif

#define MAX_PATH 260

 /**
  * Used to keep track of the TDQE's load status.  Allows for
  * thread safe updating of the load policy and the storage of
  * target information of the QE  when the policy is
  * persistent mode.  Also contains the global ecdsa_blob and
  * provides thread safe access to he blob.
  */
struct tee_att_config_t {
private:
    se_mutex_t m_enclave_load_mutex;
    se_mutex_t m_ecdsa_blob_mutex;
    sgx_enclave_id_t m_eid;
    sgx_misc_attribute_t m_attributes;
    sgx_launch_token_t m_launch_token;
    uint8_t m_ecdsa_blob[SGX_QL_TRUSTED_ECDSA_BLOB_SIZE_SDK];
    uint8_t* m_pencryptedppid;
    sgx_pce_info_t m_pce_info;
    sgx_key_128bit_t* m_qe_id;
    sgx_isv_svn_t m_raw_pce_isvsvn;
#ifndef _MSC_VER
        void *
#else
        HMODULE
#endif
            m_qpl_handle;
    sgx_report_body_t* m_tdqe_report_body;
public:
    TCHAR tdqe_path[MAX_PATH];
    TCHAR qpl_path[MAX_PATH];
    TCHAR ide_path[MAX_PATH];

    tee_att_config_t() :
        m_eid(0),
        m_pencryptedppid(NULL),
        m_qe_id(NULL),
        m_raw_pce_isvsvn(0xFFFF),
        m_qpl_handle(NULL),
        m_tdqe_report_body(NULL)
    {
        se_mutex_init(&m_enclave_load_mutex);
        se_mutex_init(&m_ecdsa_blob_mutex);
        memset(&m_attributes, 0, sizeof(m_attributes));
        memset(&m_launch_token, 0, sizeof(m_launch_token));
        memset(m_ecdsa_blob, 0, sizeof(m_ecdsa_blob));
        memset(&m_pce_info, 0, sizeof(m_pce_info));
        memset(tdqe_path, 0, sizeof(tdqe_path));
        memset(qpl_path, 0, sizeof(qpl_path));
        memset(ide_path, 0, sizeof(ide_path));
    }
    tee_att_config_t(const tee_att_config_t&);
    void unload_qe();
    tee_att_config_t& operator=(const tee_att_config_t&);
    ~tee_att_config_t() {
        unload_qe();
        se_mutex_destroy(&m_enclave_load_mutex);
        se_mutex_destroy(&m_ecdsa_blob_mutex);
        if (m_pencryptedppid)
        {
            free(m_pencryptedppid);
            m_pencryptedppid = NULL;
        }
        if (m_qe_id)
        {
            free(m_qe_id);
            m_qe_id = NULL;
        }
        if (m_qpl_handle)
        {
#ifndef _MSC_VER
            dlclose(m_qpl_handle);
#else
            FreeLibrary(m_qpl_handle);
#endif
            m_qpl_handle = NULL;
        }
        if (m_tdqe_report_body)
        {
            free(m_tdqe_report_body);
            m_tdqe_report_body = NULL;
        }
    }
    tee_att_error_t ecdsa_init_quote(sgx_ql_cert_key_type_t certification_key_type,
        sgx_target_info_t* p_qe_target_info,
        bool refresh_att_key,
        ref_sha256_hash_t* p_pub_key_id);

    tee_att_error_t ecdsa_get_quote_size(sgx_ql_cert_key_type_t certification_key_type,
        uint32_t* p_quote_size);
    tee_att_error_t ecdsa_get_quote(const sgx_report2_t* p_app_report,
        uint8_t* p_quote,
        uint32_t quote_size,
        const tdx_servtd_ext_t* p_servtd_ext = NULL);

    tee_att_error_t get_platform_info(sgx_key_128bit_t* p_platform_id,
        sgx_cpu_svn_t* p_cpu_svn,
        sgx_isv_svn_t* p_tdqe_isv_svn,
        sgx_isv_svn_t* p_pce_isv_svn);
#ifndef _MSC_VER
    void *
#else
    HMODULE
#endif
    get_qpl_handle();

  private:
    bool get_qe_path(tee_att_ae_type_t type,
        TCHAR* p_file_path,
        size_t buf_size);
    tee_att_error_t load_qe(bool *is_fresh_loaded = nullptr);
    tee_att_error_t load_id_enclave(sgx_enclave_id_t* p_id_enclave_eid);
    tee_att_error_t load_id_enclave_get_id(sgx_key_128bit_t* p_id);
    tee_att_error_t getencryptedppid(sgx_target_info_t& pce_target_info, uint8_t* p_buf, uint32_t buf_size);

    tee_att_error_t write_persistent_data(const uint8_t* p_buf,
        uint32_t buf_size,
        const char* p_label);
    tee_att_error_t read_persistent_data(uint8_t* p_buf,
        uint32_t* p_buf_size,
        const char* p_label);
    tee_att_error_t certify_key(uint8_t* p_ecdsa_blob,
        ref_plaintext_ecdsa_data_sdk_t* p_plaintext_data,
        uint8_t* p_encrypted_ppid,
        uint32_t encrypted_ppid_size,
        sgx_ql_cert_key_type_t certification_key_type);
    tee_att_error_t get_platform_quote_cert_data(sgx_ql_pck_cert_id_t* p_pck_cert_id,
        sgx_cpu_svn_t* p_cert_cpu_svn,
        sgx_isv_svn_t* p_cert_pce_isv_svn,
        uint32_t* p_cert_data_size,
        uint8_t* p_cert_data);
};
#endif
