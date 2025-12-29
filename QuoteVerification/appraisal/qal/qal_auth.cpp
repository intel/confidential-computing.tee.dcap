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

#include "qal_auth.h"
#include "sgx_tcrypto.h"
#include "qal_json.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include "qal_common.h"
#include "ec_key.h"
#include "format_util.h"
#include "default_policies.h"
#include <openssl/sha.h>
#include <map>

static quote3_error_t authenticate_one_policy(rapidjson::Value &report_array,
                                              const uint8_t *policy,
                                              std::map<std::string, auth_info_t> &result_map)
{
    std::string signature = "";
    std::string jwk = "";

    auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(policy), "policy_payload", PAYLOAD, signature, jwk);

    if (policy_json.empty() || signature.empty() || jwk.empty())
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    rapidjson::Document policy_doc;
    policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());
    if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false)
    {
        se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    // Access the policy array
    rapidjson::Value &policy_array = policy_doc["policy_array"];
    rapidjson::Document sub_doc1;
    std::string str;

    if (policy_array.IsString())
    {
        // If policy_array is not an array, we try to parse it as a json again, in case it was signed as a nested payload
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            policy_array.Accept(writer);
            str = buffer.GetString();
        }
        sub_doc1.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(str.c_str());
        if (sub_doc1.HasParseError() || sub_doc1.HasMember("policy_array") == false)
            return SGX_QL_ERROR_INVALID_PARAMETER;
        policy_array = sub_doc1["policy_array"];
    }

    if (policy_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    for (uint32_t i = 0; i < policy_array.Size(); i++)
    {
        if (policy_array[i].HasMember("environment") == false ||
            policy_array[i]["environment"].HasMember("class_id") == false ||
            policy_array[i]["environment"]["class_id"].IsString() == false)
        {
            se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        std::string class_id_p = policy_array[i]["environment"]["class_id"].GetString();
        if (result_map.find(class_id_p) == result_map.end())
        {
            // The policy file contains some unrecognized policy
            se_trace(SE_TRACE_ERROR, "The input policy is not correct:\n%s\n", policy);
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        uint32_t j = 0;
        for (; j < report_array.Size(); j++)
        {
            if (report_array[j].HasMember("policy") == false ||
                report_array[j]["policy"].HasMember("environment") == false ||
                report_array[j]["policy"]["environment"].HasMember("class_id") == false ||
                report_array[j]["policy"]["environment"]["class_id"].IsString() == false)
            {
                return SGX_QL_ERROR_INVALID_PARAMETER;
            }
            std::string class_id_r = report_array[j]["policy"]["environment"]["class_id"].GetString();
            if (class_id_p == class_id_r)
            {
                if (result_map[class_id_r].result != -1)
                {
                    // Some other policy has matched this result
                    se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0mThe input policies are incorrect. For a given type, only one policy is permitted.\n");
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                std::string sig_r = "";
                if (report_array[j]["policy"].HasMember("signature") == true)
                {
                    sig_r = report_array[j]["policy"]["signature"].GetString();
                }
                std::string jwk_r = "";
                if (report_array[j]["policy"].HasMember("signing_key") == true)
                {
                    rapidjson::Value &tmp_key = report_array[j]["policy"]["signing_key"];
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                    tmp_key.Accept(writer);
                    jwk_r = buffer.GetString();
                }

                if ((sig_r == "" && jwk_r != "") || (sig_r != "" && jwk_r == ""))
                {
                    // If the result is generated by QAL, this error should not be happened
                    SE_TRACE(SE_TRACE_DEBUG, "The input appraisal result format is not correct.\n");
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                if (sig_r != "" && jwk_r != "")
                {
                    std::string pem = "", pem_r = "";
                    if (convert_jwk_to_pem_str(jwk, pem) == false)
                    {
                        SE_TRACE(SE_TRACE_DEBUG, "The input policy format is not correct.\n");
                        return SGX_QL_ERROR_INVALID_PARAMETER;
                    }
                    if (convert_jwk_to_pem_str(jwk_r, pem_r) == false)
                    {
                        SE_TRACE(SE_TRACE_DEBUG, "The input appraisal result format is not correct.\n");
                        return SGX_QL_ERROR_INVALID_PARAMETER;
                    }
                    if (sig_r == signature && pem_r == pem)
                    {
                        result_map[class_id_r].result = POLICY_AUTH_SUCCESS;
                    }
                    else
                    {
                        result_map[class_id_r].result = POLICY_AUTH_FAILED;
                    }
                    break;
                }
            }
        }
        if (j == report_array.Size())
        {
            // No class_id is found in appraisal result token that matches the input policy
            // For example, you are trying to audit some tdx policies within an SGX appraisal result token
            se_trace(SE_TRACE_ERROR, "\033[0;31mERROR:\033[0m The appraisal result token doesn't utilize the policy with class_id %s:\n%s\n",
                     class_id_p.c_str(), policy);
            result_map[class_id_p].result = POLICY_NOT_IN_RESULT;
        }
    }
    return SGX_QL_SUCCESS;
}


static quote3_error_t verify_appraisal_result_quote_hash(rapidjson::Document &result_doc, const uint8_t *p_quote, uint32_t quote_size)
{
    sgx_sha384_hash_t hash;

    if (result_doc[0]["result"][0].HasMember("quote_hash") == false)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    std::string quote_hash = "";
    {
        rapidjson::Value &hash_array = result_doc[0]["result"][0]["quote_hash"];
        if (hash_array.IsArray() == false || hash_array.Size() != 1)
        {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        rapidjson::Value &v = result_doc[0]["result"][0]["quote_hash"][0];
        if (v.IsObject() == false || v.HasMember("quote_hash") == false)
        {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        quote_hash = v["quote_hash"].GetString();
    }

    // Directly use OpenSSL API here because the code will be shared between QAL and QAE
    if (SHA384(p_quote, quote_size, (unsigned char *)hash) == NULL)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    std::string hash_str = bytes_to_string(hash, sizeof(hash));
    if (hash_str != quote_hash)
    {
        return SGX_QL_QUOTE_HASH_MISMATCH;
    }

    return SGX_QL_SUCCESS;
}

quote3_error_t authenticate_appraisal_result_internal(const uint8_t *p_quote,
                                                      uint32_t quote_size,
                                                      const char *p_appraisal_result_token,
                                                      const tee_policy_bundle_t *p_policies,
                                                      tee_policy_auth_result_t *result)
{
    // Result for each type of policies:
    //      -2 - The provided policy is not used in the appraisal result
    //      -1 - This type of policy is not provided, default value
    //       0 - Failure. This type of policy is provided but it is not the one used in the appraisal process
    //       1 - Success. This type of policy is provided and used in the appraisal process
    std::map<std::string, auth_info_t> result_map = {
        {TENANT_ENCLAVE_CLASS_ID, {TENANT_ENCLAVE_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TENANT_TDX10_CLASS_ID, {TENANT_TDX10_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TENANT_TDX15_CLASS_ID, {TENANT_TDX15_DESCRIPTION, NO_POLICY_PROVIDED}},

        {SGX_PLATFORM_CLASS_ID, {SGX_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX15_PLATFORM_CLASS_ID, {TDX15_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX10_PLATFORM_CLASS_ID, {TDX10_PLATFORM_DESCRIPTION, NO_POLICY_PROVIDED}},
        {TDX_TDQE_CLASS_ID, {TDX_TDQE_DESCRIPTION, NO_POLICY_PROVIDED}}};

    // Decode appraisal_result_token
    std::string sig = "", jwk = "";
    std::string result_json = get_info_from_jwt(p_appraisal_result_token, "appraisal_result", PAYLOAD, sig, jwk);
    rapidjson::Document result_doc;

    result_doc.SetObject();
    result_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(result_json.c_str());

    if (result_doc.HasParseError() || result_doc.IsArray() == false || result_doc.Size() != 1)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    if (result_doc[0].IsObject() == false || result_doc[0].HasMember("result") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    if (result_doc[0]["result"].IsArray() == false ||
        result_doc[0]["result"].Size() != 1 ||
        result_doc[0]["result"][0].HasMember("appraised_reports") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    rapidjson::Value &report_array = result_doc[0]["result"][0]["appraised_reports"];
    if (report_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

    // Handle customized policies
    if (p_policies->p_tenant_identity_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->p_tenant_identity_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }
    if (p_policies->platform_policy.pt == CUSTOMIZED && p_policies->platform_policy.p_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->platform_policy.p_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }
    if (p_policies->tdqe_policy.pt == CUSTOMIZED && p_policies->tdqe_policy.p_policy)
    {
        ret = authenticate_one_policy(report_array, p_policies->tdqe_policy.p_policy, result_map);
        if (ret != SGX_QL_SUCCESS)
            return ret;
    }

    // Handle default policies
    for (uint32_t i = 0; i < report_array.Size(); i++)
    {
        if (report_array[i].HasMember("policy") == false ||
            report_array[i]["policy"].HasMember("environment") == false ||
            report_array[i]["policy"]["environment"].HasMember("class_id") == false ||
            report_array[i]["policy"]["environment"]["class_id"].IsString() == false ||
            report_array[i]["policy"]["environment"].HasMember("description") == false ||
            report_array[i]["policy"]["environment"]["description"].IsString() == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        std::string class_id_r = report_array[i]["policy"]["environment"]["class_id"].GetString();
        std::string description = report_array[i]["policy"]["environment"]["description"].GetString();
        std::string sig_r = "";
        if (report_array[i].HasMember("signature") == true &&
            report_array[i]["signature"].IsString() == true)
        {
            sig_r = report_array[i]["signature"].GetString();
        }
        std::string jwk_r = "";
        if (report_array[i].HasMember("signing_key") == true)
        {
            rapidjson::Value &tmp_key = report_array[i]["signing_key"];
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            tmp_key.Accept(writer);
            jwk_r = buffer.GetString();
        }
        if (sig_r == "" && jwk_r == "")
        {
            auto it = g_default_policy_map.find(class_id_r);
            if (it != g_default_policy_map.end())
            {
                if (description == it->second.description)
                {
                    // Only set the result map when there is no customized policy needed to be audited
                    if (result_map[class_id_r].result == NO_POLICY_PROVIDED)
                        result_map[class_id_r].result = POLICY_AUTH_SUCCESS;
                }
            }
        }
    }

    // Print result
    se_trace(SE_TRACE_ERROR, "\nThe final result map: \n");
    for (auto const &iter : result_map)
    {
        std::string result_desc[] = {
            /* -2 */ "This policy is provided but not used in the appraisal process",
            /* -1 */ "This type of policy is not provided",
            /*  0 */ "This type of policy is provided but it is not the one used in the appraisal process",
            /*  1 */ "This type of policy is provided and used in the appraisal process",
        };
        se_trace(SE_TRACE_ERROR, "\t\"%-30s\": class-id=%s, result=%d, \"%30s\"\n", iter.second.description.c_str(),
                 iter.first.c_str(), iter.second.result, result_desc[iter.second.result + 2].c_str());
    }

    // Check result
    if ((result_map[TENANT_ENCLAVE_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[SGX_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS) ||
        (result_map[TENANT_TDX10_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX10_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX_TDQE_CLASS_ID].result == POLICY_AUTH_SUCCESS) ||
        (result_map[TENANT_TDX15_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX15_PLATFORM_CLASS_ID].result == POLICY_AUTH_SUCCESS &&
         result_map[TDX_TDQE_CLASS_ID].result == POLICY_AUTH_SUCCESS))
    {
        *result = TEE_AUTH_SUCCESS; // The policies are audited successfully.
    }
    else
    {
        bool flag = false;
        for (auto const &iter : result_map)
        {
            if (iter.second.result == POLICY_AUTH_FAILED)
            {
                flag = true;
            }
        }
        if (flag == true)
        {
            // At least one policy is audited failed.
            *result = TEE_AUTH_FAILURE;
        }
        else
        {
            // Some policy is not audited
            *result = TEE_AUTH_INCOMPLET;
        }
    }

    // Validate quote if the optional quote is input
    if (p_quote)
    {
        // validate quote hash
        ret = verify_appraisal_result_quote_hash(result_doc, p_quote, quote_size);
    }
    return SGX_QL_SUCCESS;
}

static inline std::string extract_pub_key(std::string pub_key)
{
    const char *pem_start_str = "-----BEGIN PUBLIC KEY-----";
    const char *pem_end_str = "-----END PUBLIC KEY-----";
    size_t start_pos = pub_key.find(pem_start_str);
    size_t end_pos = pub_key.find(pem_end_str);
    if(start_pos == std::string::npos || end_pos == std::string::npos)
    {
        return "";
    }
    return pub_key.substr(start_pos, end_pos - start_pos + strlen(pem_end_str));
}

// Check whether all the signing keys used in appraisal policies are included in the policy_key_list
quote3_error_t authenticate_policy_owner_internal(const uint8_t *p_quote,
                                                  uint32_t quote_size,
                                                  const char *p_appraisal_result_token,
                                                  const char **policy_key_list,
                                                  uint32_t list_size,
                                                  tee_policy_auth_result_t *result)
{
    // Decode appraisal_result_token
    std::string result_json = "";
    {
        std::string sig = "", jwk = "";
        result_json = get_info_from_jwt(p_appraisal_result_token, "appraisal_result", PAYLOAD, sig, jwk);
    }
    rapidjson::Document result_doc;

    result_doc.SetObject();
    result_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(result_json.c_str());

    if (result_doc.HasParseError() || result_doc.IsArray() == false || result_doc.Size() != 1)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    if (result_doc[0].IsObject() == false || result_doc[0].HasMember("result") == false)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }

    if (result_doc[0]["result"].IsArray() == false ||
        result_doc[0]["result"].Size() != 1 ||
        result_doc[0]["result"][0].HasMember("appraised_reports") == false)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }
    rapidjson::Value &report_array = result_doc[0]["result"][0]["appraised_reports"];
    if (report_array.IsArray() == false)
    {
        return TEE_ERROR_INVALID_PARAMETER;
    }

    quote3_error_t ret = TEE_ERROR_UNEXPECTED;
    internal_result_t auth_res = NO_SIGN_KEY_IN_RESULT;
    for (uint32_t i = 0; i < report_array.Size(); i++)
    {
        if(report_array[i].HasMember("policy") == false)
        {
            return TEE_ERROR_INVALID_PARAMETER;
        }
        std::string class_id_r = report_array[i]["policy"]["environment"]["class_id"].GetString();
        std::string jwk_r = "";
        if (report_array[i]["policy"].HasMember("signing_key") == true)
        {
            rapidjson::Value &tmp_key = report_array[i]["policy"]["signing_key"];
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            tmp_key.Accept(writer);
            jwk_r = buffer.GetString();
        }
        if (jwk_r.empty() == true)
        {
            SE_TRACE(SE_TRACE_DEBUG, "Policy with class_id %s has no signing key.\n", class_id_r.c_str());
            continue;
        }

        std::string pem_r;
        if (convert_jwk_to_pem_str(jwk_r, pem_r) == false)
        {
            SE_TRACE(SE_TRACE_DEBUG, "The input appraisal result format is not correct.\n");
            return TEE_ERROR_INVALID_PARAMETER;
        }
        uint32_t j = 0;
        for (; j < list_size; j++)
        {
            std::string tmp_key1 = extract_pub_key(policy_key_list[j]);
            std::string tmp_key2 = extract_pub_key(pem_r);
            if(tmp_key1.empty() == true || tmp_key2.empty() == true)
            {
                auth_res = SIGN_KEY_FORMAT_ERROR;
                break;
            }
            if(tmp_key1 == tmp_key2)
            {
                break;
            }
        }
        if (j == list_size)
        {
            // The signing key is not included in the input key_list
            auth_res = SIGN_KEY_MISSED;
            break;
        }
        else if (auth_res == SIGN_KEY_FORMAT_ERROR)
        {
            break;
        }
        else
        {
            auth_res = SIGN_KEY_FOUND;
            continue;
        }
    }
    if (auth_res == NO_SIGN_KEY_IN_RESULT || auth_res == SIGN_KEY_FORMAT_ERROR)
    {
        SE_TRACE(SE_TRACE_DEBUG, "The input appraisal result format or some key format in the policy_key_list is not correct.\n");
        return TEE_ERROR_INVALID_PARAMETER;
    }
    else if (auth_res == SIGN_KEY_MISSED)
    {
        *result = TEE_AUTH_INCOMPLET;
    }
    else
    {
        *result = TEE_AUTH_SUCCESS;
    }

    ret = TEE_SUCCESS;

    // Validate quote if the optional quote is input
    if (p_quote)
    {
        // validate quote hash
        ret = verify_appraisal_result_quote_hash(result_doc, p_quote, quote_size);
    }
    return ret;
}