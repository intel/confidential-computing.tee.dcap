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

// Implement ocalls for QAE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qae_u.h"
#include "opa_helper.h"
#include "qal_json.h"
#include "qal_common.h"
#include "sgx_dcap_pcs_com.h"

int ocall_malloc(uint8_t **buf, uint32_t buf_size)
{
    if (buf == NULL || buf_size == 0)
    {
        return 0;
    }
    uint8_t *tmp_buf = (uint8_t *)malloc(buf_size);
    if (tmp_buf == NULL)
    {
        return 0;
    }
    *buf = tmp_buf;
    return 1;
}

quote3_error_t ocall_get_default_platform_policy(const uint8_t *fmspc, uint32_t fmspc_size, uint8_t **pp_default_platform_policy, uint32_t *p_default_platform_policy_size)
{
    if(fmspc == NULL || fmspc_size != FMSPC_SIZE || pp_default_platform_policy == NULL || p_default_platform_policy_size == NULL)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    uint8_t *p_platform_policy_from_pccs = NULL;
    uint32_t platform_policy_size = 0;
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    ret = tee_dcap_get_default_platform_policy((uint8_t *)fmspc, FMSPC_SIZE, &p_platform_policy_from_pccs, &platform_policy_size);
    if (SGX_QL_SUCCESS != ret)
    {
        *pp_default_platform_policy = NULL;
        *p_default_platform_policy_size = 0;
    }
    else
    {
        *pp_default_platform_policy = p_platform_policy_from_pccs;
        *p_default_platform_policy_size = platform_policy_size;
    }
    return SGX_QL_SUCCESS;
}

quote3_error_t ocall_free_default_platform_policy(uint8_t *p_default_platform_policy, uint32_t default_policy_size)
{
    if(p_default_platform_policy == NULL || default_policy_size == 0)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    return tee_dcap_free_platform_policy(p_default_platform_policy);

}
