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

#ifndef _QAE_WRAPPER_H_
#define _QAE_WRAPPER_H_

#include "sgx_urts.h"
#include "sgx_error.h"
#include "sgx_ql_quote.h"
#include <time.h>

#if defined(__cplusplus)
extern "C"
{
#endif

    quote3_error_t load_enclave(sgx_enclave_id_t *eid, sgx_target_info_t *p_qae_target_info = NULL);
    void unload_enclave(sgx_enclave_id_t eid, bool force = false);

    quote3_error_t ecall_appraise_quote_result(sgx_enclave_id_t eid,
                                           uint8_t *wasm_buf,
                                           size_t wasm_size,
                                           const uint8_t *p_verification_result_token,
                                           uint8_t **p_qaps,
                                           uint8_t qaps_count,
                                           const time_t appraisal_check_date,
                                           sgx_ql_qe_report_info_t *p_qae_report_info,
                                           uint32_t *p_appraisal_result_token_buffer_size,
                                           uint8_t **p_appraisal_result_token);

    quote3_error_t ecall_authenticate_appraisal_result(sgx_enclave_id_t eid,
                                                       const uint8_t *p_quote,
                                                       uint32_t quote_size,
                                                       const uint8_t *p_appraisal_result_token,
                                                       const tee_policy_bundle_t *p_policies,
                                                       tee_policy_auth_result_t *result,
                                                       sgx_ql_qe_report_info_t *p_qae_report_info);

    quote3_error_t ecall_authenticate_policy_owner(sgx_enclave_id_t eid,
                                                   const uint8_t *p_quote,
                                                   uint32_t quote_size,
                                                   const uint8_t *p_appraisal_result_token,
                                                   const uint8_t **policy_key_list,
                                                   uint32_t list_size,
                                                   tee_policy_auth_result_t *result,
                                                   sgx_ql_qe_report_info_t *p_qae_report_info);

#if defined(__cplusplus)
}
#endif

#endif