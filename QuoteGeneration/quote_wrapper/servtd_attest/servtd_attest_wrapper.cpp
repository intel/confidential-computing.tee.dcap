/*
 * Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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

#include "../../../QuoteVerification/QvE/Include/tdx_qve_verify.h"
#include <stddef.h>
#include "../common/inc/sgx_quote_4.h"
#include "../tdx_attest/tdx_attest.h"
#include "inc/servtd_attest.h"

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
    uint8_t verify_status = 0;

    if (NULL == p_quote || quote_size < sizeof(sgx_quote4_t))
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }

    if (NULL == p_tdx_servtd_suppl_data || NULL == p_tdx_servtd_suppl_data_size)
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }

    if (NULL == root_pub_key)
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }
    // only verify quote's integrity
    verify_status = do_verify_quote_integrity(
                        (const uint8_t*)p_quote,
                        quote_size,
                        (const uint8_t*)root_pub_key,
                        root_pub_key_size,
                        NULL,
                        (uint8_t*)p_tdx_servtd_suppl_data,
                        (uint32_t*)p_tdx_servtd_suppl_data_size);
    return verify_status;
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
    uint8_t verify_status = 0;

    if (NULL == p_quote || quote_size < sizeof(sgx_quote4_t))
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }

    if (NULL == p_tdx_servtd_suppl_data || NULL == p_tdx_servtd_suppl_data_size)
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
    }

    if (NULL == root_pub_key)
    {
        return SERVTD_ATTEST_ERROR_UNEXPECTED;
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

    return verify_status;
}

servtd_attest_error_t init_heap(const void* p_td_heap_base, const uint32_t td_heap_size)
{
    extern void* heap_base;
    extern size_t heap_size;

    if (heap_base != NULL)
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;

    if ((p_td_heap_base == NULL) ||
        (((size_t)p_td_heap_base) & (HEAP_PAGE_SIZE - 1)))
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;

    if (td_heap_size & (HEAP_PAGE_SIZE - 1))
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;

    if (td_heap_size > SIZE_MAX - (size_t)p_td_heap_base)
        return SERVTD_ATTEST_ERROR_INVALID_PARAMETER;

    heap_base = p_td_heap_base;
    heap_size = td_heap_size;

    return SERVTD_ATTEST_SUCCESS;
}
