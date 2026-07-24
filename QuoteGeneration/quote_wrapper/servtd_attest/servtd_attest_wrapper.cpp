/*
* Copyright(c) 2011-2026 Intel Corporation
*
* SPDX-License-Identifier: BSD-3-Clause
*/

#include "../../../ae/QvE/Include/tdx_qve_verify.h"
#include <stddef.h>
#include <sgx_quote_4.h>
#include <unordered_map>
#include "../tdx_attest/tdx_attest.h"
#include "inc/servtd_attest.h"

static servtd_attest_error_t map_quote3_error_to_servtd_attest_error(quote3_error_t quote3_err)
{
    static const std::unordered_map<quote3_error_t, servtd_attest_error_t> error_map = {
        {SGX_QL_SUCCESS, SERVTD_ATTEST_SUCCESS},
        {SGX_QL_ERROR_INVALID_PARAMETER, SERVTD_ATTEST_ERROR_INVALID_PARAMETER},
        {SGX_QL_ERROR_OUT_OF_MEMORY, SERVTD_ATTEST_ERROR_OUT_OF_MEMORY},
        {SGX_QL_ERROR_UNEXPECTED, SERVTD_ATTEST_ERROR_UNEXPECTED},
        {SGX_QL_PCK_CERT_CHAIN_ERROR, SERVTD_ATTEST_PCK_CERT_CHAIN_ERROR},
        {SGX_QL_TCBINFO_MISMATCH, SERVTD_ATTEST_TCBINFO_MISMATCH},
        {SGX_QL_QEIDENTITY_MISMATCH, SERVTD_ATTEST_QEIDENTITY_MISMATCH},
        {SGX_QL_TCB_OUT_OF_DATE, SERVTD_ATTEST_TCB_OUT_OF_DATE},
        {SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, SERVTD_ATTEST_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED},
        {SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, SERVTD_ATTEST_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE},
        {SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, SERVTD_ATTEST_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE},
        {SGX_QL_QE_IDENTITY_OUT_OF_DATE, SERVTD_ATTEST_QE_IDENTITY_OUT_OF_DATE},
        {SGX_QL_SGX_TCB_INFO_EXPIRED, SERVTD_ATTEST_SGX_TCB_INFO_EXPIRED},
        {SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED, SERVTD_ATTEST_SGX_PCK_CERT_CHAIN_EXPIRED},
        {SGX_QL_SGX_CRL_EXPIRED, SERVTD_ATTEST_SGX_CRL_EXPIRED},
        {SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED, SERVTD_ATTEST_SGX_SIGNING_CERT_CHAIN_EXPIRED},
        {SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED, SERVTD_ATTEST_SGX_ENCLAVE_IDENTITY_EXPIRED},
        {SGX_QL_PCK_REVOKED, SERVTD_ATTEST_PCK_REVOKED},
        {SGX_QL_TCB_REVOKED, SERVTD_ATTEST_TCB_REVOKED},
        {SGX_QL_TCB_CONFIGURATION_NEEDED, SERVTD_ATTEST_TCB_CONFIGURATION_NEEDED},
        {SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED, SERVTD_ATTEST_QUOTE_CERTIFICATION_DATA_UNSUPPORTED},
        {SGX_QL_QUOTE_FORMAT_UNSUPPORTED, SERVTD_ATTEST_QUOTE_FORMAT_UNSUPPORTED},
        {SGX_QL_UNABLE_TO_GENERATE_REPORT, SERVTD_ATTEST_UNABLE_TO_GENERATE_REPORT},
        {SGX_QL_QE_REPORT_INVALID_SIGNATURE, SERVTD_ATTEST_QE_REPORT_INVALID_SIGNATURE},
        {SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT, SERVTD_ATTEST_QE_REPORT_UNSUPPORTED_FORMAT},
        {SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT, SERVTD_ATTEST_PCK_CERT_UNSUPPORTED_FORMAT},
        {SGX_QL_TCBINFO_UNSUPPORTED_FORMAT, SERVTD_ATTEST_TCBINFO_UNSUPPORTED_FORMAT},
        {SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT, SERVTD_ATTEST_QEIDENTITY_UNSUPPORTED_FORMAT},
        {SGX_QL_TCB_SW_HARDENING_NEEDED, SERVTD_ATTEST_TCB_SW_HARDENING_NEEDED},
        {SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, SERVTD_ATTEST_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED},
        {SGX_QL_UNABLE_TO_GET_COLLATERAL, SERVTD_ATTEST_UNABLE_TO_GET_COLLATERAL},
        {SGX_QL_NO_QUOTE_COLLATERAL_DATA, SERVTD_ATTEST_NO_QUOTE_COLLATERAL_DATA},
        {SGX_QL_CRL_UNSUPPORTED_FORMAT, SERVTD_ATTEST_CRL_UNSUPPORTED_FORMAT},
        {SGX_QL_QEIDENTITY_CHAIN_ERROR, SERVTD_ATTEST_QEIDENTITY_CHAIN_ERROR},
        {SGX_QL_TCBINFO_CHAIN_ERROR, SERVTD_ATTEST_TCBINFO_CHAIN_ERROR},
        {SGX_QL_TDX_MODULE_MISMATCH, SERVTD_ATTEST_TDX_MODULE_MISMATCH},
        {SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED, SERVTD_ATTEST_COLLATERAL_VERSION_NOT_SUPPORTED}
    };

    auto it = error_map.find(quote3_err);
    if (it != error_map.end()) {
        return it->second;
    }
    return SERVTD_ATTEST_ERROR_UNEXPECTED;
}

servtd_attest_error_t get_quote(const void* p_tdx_report,
                               const uint32_t tdx_report_size, void* p_quote,
                               uint32_t* p_quote_size)
{
    servtd_attest_error_t ret = SERVTD_ATTEST_ERROR_UNEXPECTED;
    tdx_attest_error_t status = tdx_att_get_quote_by_report(
        p_tdx_report, tdx_report_size, p_quote, (uint32_t*)p_quote_size);
    // translate more error code if needed in future
    switch (status)
    {
        case TDX_ATTEST_SUCCESS:
            ret = SERVTD_ATTEST_SUCCESS;
            break;
        case TDX_ATTEST_ERROR_INVALID_PARAMETER:
            ret = SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
            break;
        case TDX_ATTEST_ERROR_OUT_OF_MEMORY:
            ret = SERVTD_ATTEST_ERROR_OUT_OF_MEMORY;
            break;
        case TDX_ATTEST_ERROR_QUOTE_FAILURE:
            ret = SERVTD_ATTEST_ERROR_QUOTE_FAILURE;
            break;
        default:
            ret = SERVTD_ATTEST_ERROR_UNEXPECTED;
    }
    return ret;
}

servtd_attest_error_t verify_quote_integrity(
                        const void* p_quote,
                        uint32_t quote_size,
                        const void* root_pub_key,
                        uint32_t root_pub_key_size,
                        void* p_tdx_servtd_suppl_data,
                        uint32_t* p_tdx_servtd_suppl_data_size)
{
    quote3_error_t verify_status = SGX_QL_SUCCESS;

    if (NULL == p_quote || quote_size < sizeof(sgx_quote4_t))
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }

    if (NULL == p_tdx_servtd_suppl_data || NULL == p_tdx_servtd_suppl_data_size)
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }

    if (NULL == root_pub_key || root_pub_key_size == 0)
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }
    // only verify quote's integrity
    verify_status = do_verify_quote_integrity(
        (const uint8_t*)p_quote, quote_size, (const uint8_t*)root_pub_key,
        root_pub_key_size,
        (const tdx_ql_qv_collateral_t *)nullptr,
        (uint8_t*)p_tdx_servtd_suppl_data,
        (uint32_t*)p_tdx_servtd_suppl_data_size);

    return map_quote3_error_to_servtd_attest_error(verify_status);
}

servtd_attest_error_t verify_quote_integrity_ex(
                        const void* p_quote,
                        uint32_t quote_size,
                        const void* root_pub_key,
                        uint32_t root_pub_key_size,
                        const tdx_ql_qv_collateral_t *p_quote_collateral,
                        void* p_tdx_servtd_suppl_data,
                        uint32_t* p_tdx_servtd_suppl_data_size)
{
    quote3_error_t verify_status = SGX_QL_SUCCESS;

    if (NULL == p_quote || quote_size < sizeof(sgx_quote4_t))
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }

    if (NULL == p_tdx_servtd_suppl_data || NULL == p_tdx_servtd_suppl_data_size)
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }

    if (NULL == root_pub_key || root_pub_key_size == 0)
    {
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;
    }

    // only verify quote's integrity
    verify_status = do_verify_quote_integrity(
                        (const uint8_t*)p_quote,
                        quote_size,
                        (const uint8_t*)root_pub_key,
                        root_pub_key_size,
                        p_quote_collateral,
                        (uint8_t*)p_tdx_servtd_suppl_data,
                        (uint32_t*)p_tdx_servtd_suppl_data_size);

    return map_quote3_error_to_servtd_attest_error(verify_status);
}

/**
 * NOTE on const-correctness:
 * The parameter p_td_heap_base is declared as `const void*`, even though the memory it points to
 * will ultimately be mutated by the heap allocator (sbrk). The const is cast away below when
 * assigning to the global `void* heap_base` (defined in SGX SDK's sbrk.c under SERVTD_ATTEST).
 * The SGX SDK's own heap_init() in trts_util.h and get_heap_base() both use non-const void*
 * consistently, so this const is somewhat at odds with the SDK convention.
 *
 * The const qualifier is retained on the public API mainly because MigTD consumes it via Rust FFI
 * (binding.rs: *const c_void). Removing const would require updating the FFI declaration to
 * *mut c_void — a source-compatible change on the Rust side (Rust auto-coerces *mut to *const),
 * but a coordinated change nonetheless.
 *
 * This function is provided by the SGX SDK tlibc (tlibc/gen/sbrk.c).
 */
extern "C" int set_heap_base(const void *_heap_base, size_t _heap_size);

// DCAP-owned shadow of the heap base, read back by get_heap_base() in
// servtd_utils.c (the SDK's own heap_base is static/private for DOP hardening).
extern "C" void *g_servtd_heap_base;

servtd_attest_error_t init_heap(const void* p_td_heap_base, const uint32_t td_heap_size)
{
    if (0 != set_heap_base(p_td_heap_base, td_heap_size)) {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }

    // Keep the shadow in sync with the value just handed to the SDK so tlibc's
    // malloc bounds check (get_heap_base()) sees the same heap base.
    g_servtd_heap_base = const_cast<void*>(p_td_heap_base);

    return SERVTD_ATTEST_SUCCESS;
}
