/*
 * Copyright(c) 2011-2025 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _TEE_CLASS_H_
#define _TEE_CLASS_H_

#include "sgx_qve_header.h"
#include "sgx_qve_def.h"
#include "sgx_urts.h"

#if defined(__cplusplus)
extern "C" {
#endif

class tee_qv_base {
public:
    virtual quote3_error_t tee_verify_evidence(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
        const time_t expiration_check_date,
        uint32_t *p_collateral_expiration_status,
        sgx_ql_qv_result_t *p_quote_verification_result,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        uint32_t supplemental_data_size,
        uint8_t *p_supplemental_data) = 0;

#ifndef _MSC_VER
        virtual quote3_error_t tee_get_verify_token(
        const uint8_t *p_quote,
        uint32_t quote_size,
        time_t current_time,
        const sgx_ql_qve_collateral_t *p_quote_collateral,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        const uint8_t *p_user_data,
        uint32_t user_data_size,
        uint32_t *verification_result_token_buffer_size,
        uint8_t **p_verification_result_token) = 0;
#endif

    virtual quote3_error_t tee_get_supplemental_data_size(uint32_t *p_data_size) = 0;

    virtual quote3_error_t tee_get_supplemental_data_version(uint32_t *p_version) = 0;

    virtual quote3_error_t tee_get_fmspc_ca_from_quote(
        const uint8_t* p_quote,
        uint32_t quote_size,
        unsigned char* p_fmsp_from_quote,
        uint32_t fmsp_from_quote_size,
        unsigned char* p_ca_from_quote,
        uint32_t ca_from_quote_size) = 0;

    virtual quote3_error_t tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral) = 0;

    virtual quote3_error_t tee_free_verification_endorsement(
        struct _sgx_ql_qve_collateral_t *pp_quote_collateral) = 0;

    virtual quote3_error_t tee_get_qve_identity(
        uint8_t **pp_qveid,
        uint32_t *p_qveid_size,
        uint8_t **pp_qveid_issue_chain,
        uint32_t *p_qveid_issue_chain_size,
        uint8_t **pp_root_ca_crl,
        uint16_t *p_root_ca_crl_size) = 0;

    virtual quote3_error_t tee_free_qve_identity(
        uint8_t *p_qveid,
        uint8_t *p_qveid_issue_chain,
        uint8_t *p_root_ca_crl) = 0;

    virtual sgx_status_t load_qve() = 0;

    virtual sgx_status_t unload_qve() = 0;

    virtual void set_eid(sgx_enclave_id_t eid) = 0;

    virtual ~tee_qv_base() {};
};

class sgx_qv : public tee_qv_base {
public:
    virtual quote3_error_t tee_verify_evidence(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
        const time_t expiration_check_date,
        uint32_t *p_collateral_expiration_status,
        sgx_ql_qv_result_t *p_quote_verification_result,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        uint32_t supplemental_data_size,
        uint8_t *p_supplemental_data);

#ifndef _MSC_VER
    virtual quote3_error_t tee_get_verify_token(
        const uint8_t *p_quote,
        uint32_t quote_size,
        time_t current_time,
        const sgx_ql_qve_collateral_t *p_quote_collateral,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        const uint8_t *p_user_data,
        uint32_t user_data_size,
        uint32_t *verification_result_token_buffer_size,
        uint8_t **p_verification_result_token);
#endif

    virtual quote3_error_t tee_get_supplemental_data_size(uint32_t *p_data_size);

    virtual quote3_error_t tee_get_supplemental_data_version(uint32_t *p_version);

    virtual quote3_error_t tee_get_fmspc_ca_from_quote(
        const uint8_t* p_quote,
        uint32_t quote_size,
        unsigned char* p_fmsp_from_quote,
        uint32_t fmsp_from_quote_size,
        unsigned char* p_ca_from_quote,
        uint32_t ca_from_quote_size);

    virtual quote3_error_t tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        sgx_ql_qve_collateral_t **pp_quote_collateral);

    virtual quote3_error_t tee_free_verification_endorsement(
        sgx_ql_qve_collateral_t *pp_quote_collateral);

    virtual quote3_error_t tee_get_qve_identity(
        uint8_t **pp_qveid,
        uint32_t *p_qveid_size,
        uint8_t **pp_qveid_issue_chain,
        uint32_t *p_qveid_issue_chain_size,
        uint8_t **pp_root_ca_crl,
        uint16_t *p_root_ca_crl_size);

    virtual quote3_error_t tee_free_qve_identity(
        uint8_t *p_qveid,
        uint8_t *p_qveid_issue_chain,
        uint8_t *p_root_ca_crl);

    virtual sgx_status_t load_qve() { return SGX_SUCCESS; };

    virtual sgx_status_t unload_qve() { return SGX_SUCCESS; };

    virtual void set_eid(sgx_enclave_id_t eid) { (void)eid; };
};

class sgx_qv_trusted : public sgx_qv {
public:

    virtual ~sgx_qv_trusted();

    virtual quote3_error_t tee_verify_evidence(
        const uint8_t *p_quote,
        uint32_t quote_size,
        const struct _sgx_ql_qve_collateral_t *p_quote_collateral,
        const time_t expiration_check_date,
        uint32_t *p_collateral_expiration_status,
        sgx_ql_qv_result_t *p_quote_verification_result,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        uint32_t supplemental_data_size,
        uint8_t *p_supplemental_data);

#ifndef _MSC_VER
    virtual quote3_error_t tee_get_verify_token(
        const uint8_t *p_quote,
        uint32_t quote_size,
        time_t current_time,
        const sgx_ql_qve_collateral_t *p_quote_collateral,
        sgx_ql_qe_report_info_t *p_qve_report_info,
        const uint8_t *p_user_data,
        uint32_t user_data_size,
        uint32_t *verification_result_token_buffer_size,
        uint8_t **p_verification_result_token);
#endif

    virtual quote3_error_t tee_get_supplemental_data_size(uint32_t *p_data_size);

    virtual quote3_error_t tee_get_supplemental_data_version(uint32_t *p_version);

    virtual quote3_error_t tee_get_fmspc_ca_from_quote(
        const uint8_t* p_quote,
        uint32_t quote_size,
        unsigned char* p_fmsp_from_quote,
        uint32_t fmsp_from_quote_size,
        unsigned char* p_ca_from_quote,
        uint32_t ca_from_quote_size);

    virtual sgx_status_t load_qve();

    virtual sgx_status_t unload_qve();

    virtual void set_eid(sgx_enclave_id_t eid);

private:
    sgx_enclave_id_t m_qve_id = 0;
};

class tdx_qv : public sgx_qv {
public:

    virtual quote3_error_t tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral);

    virtual quote3_error_t tee_free_verification_endorsement(
        struct _sgx_ql_qve_collateral_t *pp_quote_collateral);

};

class tdx_qv_trusted : public sgx_qv_trusted {
public:

    virtual quote3_error_t tee_get_verification_endorsement(
        const char *fmspc,
        uint16_t fmspc_size,
        const char *pck_ca,
        struct _sgx_ql_qve_collateral_t **pp_quote_collateral);

    virtual quote3_error_t tee_free_verification_endorsement(
        struct _sgx_ql_qve_collateral_t *pp_quote_collateral);
};


#if defined(__cplusplus)
}
#endif

#endif /* !_TEE_CLASS_H_*/
