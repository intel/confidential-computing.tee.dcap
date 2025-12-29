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

#pragma once
#include <string>
#include <stdint.h>
#include "sgx_ql_lib_common.h"
#include "sgx_dcap_qal.h"

typedef enum _internal_result_t
{
    // authentication result for each type of policies
    POLICY_NOT_IN_RESULT = -2,  // The provided policy is not used in the appraisal result
    NO_POLICY_PROVIDED,         // This type of policy is not provided. Default setting
    POLICY_AUTH_FAILED,         // This type of policy is provided but it is not the one used in the appraisal process
    POLICY_AUTH_SUCCESS,        // This type of policy is provided and used in the appraisal process

    // For signing key authentitication
    NO_SIGN_KEY_IN_RESULT,      // No signing key is used in appraisal
    SIGN_KEY_FORMAT_ERROR,      // The signing key format is not correct
    SIGN_KEY_FOUND,             // The signing key is used during appraisal and found in the input key list
    SIGN_KEY_MISSED             // The signing key is used during appraisal but not found in the input key list
}internal_result_t;

typedef struct _auth_info_t
{
    std::string description;
    internal_result_t result;
} auth_info_t;

quote3_error_t authenticate_appraisal_result_internal(const uint8_t *p_quote,
                                                    uint32_t quote_size,
                                                    const char *p_appraisal_result_token,
                                                      const tee_policy_bundle_t *p_policies,
                                                      tee_policy_auth_result_t *result);

quote3_error_t authenticate_policy_owner_internal(const uint8_t *p_quote,
                                                  uint32_t quote_size,
                                                  const char *p_appraisal_result_token,
                                                  const char **policy_key_list,
                                                  uint32_t list_size,
                                                  tee_policy_auth_result_t *result);
