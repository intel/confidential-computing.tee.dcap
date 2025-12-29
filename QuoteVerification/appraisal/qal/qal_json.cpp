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

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <iostream>
#include <sstream>
#include "jwt-cpp/jwt.h"
#include "sgx_dcap_qal.h"
#include "qal_json.h"
#include "qal_common.h"
#include "ec_key.h"
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifndef BUILD_QAE
#include "sgx_dcap_pcs_com.h" // For default policy from pccs
#else 
#include "qae_t.h"
#include "sgx_trts.h"
#endif
#include "default_policies.h"


const std::map<std::string, policy_t> g_default_policy_map =
{
    {SGX_PLATFORM_CLASS_ID, {"Default Strict SGX platform TCB policy from Intel", default_sgx_platform_policy.str()}},
    {TDX10_PLATFORM_CLASS_ID, {"Default Strict TDX 1.0 platform TCB policy from Intel", default_tdx10_platform_policy.str()}},
    {TDX15_PLATFORM_CLASS_ID, {"Default Strict TDX 1.5 platform TCB policy from Intel", default_tdx15_platform_policy.str()}},
    {TDX_TDQE_CLASS_ID, {"Default Strict Verified TD QE Identity policy from Intel", default_verified_TDQE_policy.str()}}
};

std::string get_info_from_jwt(const char *p_jwt_str,
                              const char *claim_name,
                              claim_type_t ctype,
                              std::string &signature,
                              std::string &jwk)
{
    if (p_jwt_str == NULL || (ctype != HEADER && ctype != PAYLOAD))
        return "";
    std::string jwt_str(p_jwt_str);
    try
    {
        auto decoded = jwt::decode(jwt_str);
        auto alg = decoded.get_algorithm();
        auto typ = decoded.get_type();

        if ((alg == "none" && typ == "JWT"))
        {
            if (ctype == HEADER)
            {
                if(claim_name == NULL)
                {
                    auto header = decoded.get_header();
                    return header;
                    
                }
                else
                {
                    if (decoded.has_header_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_header_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
            else
            {
                if (claim_name == NULL)
                {
                    return decoded.get_payload();
                }
                else
                {
                    if (decoded.has_payload_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_payload_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
        }
        else if (alg == "ES384" && (typ == "JWS" || typ == "JWT"))
        {
            // If the jwt has alg, it should have public key in the JWT header
            // we need to get the jwk first and verify the jwt
            if (decoded.has_header_claim("jwk") == false)
            {
                return "";
            }
            auto jwk_json = decoded.get_header_claim("jwk").to_json();

            std::string pub_key;
            auto jwk_str = jwk_json.to_str();
            if (convert_jwk_to_pem_str(jwk_str, pub_key) == false)
            {
                SE_TRACE(SE_TRACE_DEBUG, "Fail to convert jwk to pem\n");
                return "";
            }
            auto verifier =
                jwt::verify()
                    .allow_algorithm(jwt::algorithm::es384(pub_key));
            try
            {
                verifier.verify(decoded);
            }
            catch (...)
            {
                SE_TRACE(SE_TRACE_DEBUG, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
                return "";
            }

            // After verify, we can get the header or payload
            signature = decoded.get_signature_base64();
            jwk = jwk_json.to_str();
            if (ctype == HEADER)
            {
                if(claim_name == NULL)
                {
                    auto header = decoded.get_header();
                    return header;
                    
                }
                else
                {
                    if (decoded.has_header_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_header_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
            else
            {
                if (claim_name == NULL)
                {
                    return decoded.get_payload();
                }
                else
                {
                    if (decoded.has_payload_claim(claim_name) == false)
                        return "";
                    auto claim = decoded.get_payload_claim(claim_name);
                    return claim.to_json().to_str();
                }
            }
        }
    }
    catch (...)
    {
        SE_TRACE(SE_TRACE_DEBUG, "Fail to verify the JWT: \n%s\n\n", jwt_str.c_str());
    }
    // Don't support other alg/types
    return "";
}

static quote3_error_t get_default_platform_policy_from_pccs(const uint8_t *fmspc,
                                                   uint32_t fmspc_size,
                                                   uint8_t **pp_default_platform_policy,
                                                   uint32_t *p_default_platform_policy_size)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;

#ifndef BUILD_QAE
    ret = tee_dcap_get_default_platform_policy(fmspc, fmspc_size, pp_default_platform_policy, p_default_platform_policy_size);
    if (SGX_QL_SUCCESS != ret)
    {
        se_trace(SE_TRACE_ERROR, "Failed to get default platform policy from PCCS. Will try to use strict policy instead\n");
    }
#else
    uint8_t *p_tmp_platform_policy = NULL;
    uint8_t **pp_tmp_platform_policy = &p_tmp_platform_policy;
    uint32_t tmp_platform_policy_size = 0;
    sgx_status_t sgx_ret = ocall_get_default_platform_policy(&ret, fmspc, fmspc_size, pp_tmp_platform_policy, &tmp_platform_policy_size);
    if(sgx_ret != SGX_SUCCESS || ret != SGX_QL_SUCCESS)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    if(tmp_platform_policy_size == 0 || p_tmp_platform_policy == NULL ||
      !sgx_is_outside_enclave(p_tmp_platform_policy, tmp_platform_policy_size))
    {
        if(p_tmp_platform_policy)
        {
            ocall_free_default_platform_policy(&ret, p_tmp_platform_policy, tmp_platform_policy_size);
        }
        return SGX_QL_ERROR_UNEXPECTED;
    }

    *pp_default_platform_policy = (uint8_t *)malloc(tmp_platform_policy_size);
    if(*pp_default_platform_policy == NULL)
    {
        ocall_free_default_platform_policy(&ret, p_tmp_platform_policy, tmp_platform_policy_size);
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    memcpy(*pp_default_platform_policy, p_tmp_platform_policy, tmp_platform_policy_size);
    sgx_ret = ocall_free_default_platform_policy(&ret, p_tmp_platform_policy, tmp_platform_policy_size);
    if(sgx_ret != SGX_SUCCESS || ret != SGX_QL_SUCCESS)
    {
        return SGX_QL_ERROR_UNEXPECTED;
    }
    *p_default_platform_policy_size = tmp_platform_policy_size;
#endif
    return ret;
}

static quote3_error_t free_default_platform_policy_from_pccs(uint8_t *p_default_platform_policy)
{
#ifndef BUILD_QAE
    return tee_dcap_free_platform_policy(p_default_platform_policy);
#else
    free(p_default_platform_policy);
    return SGX_QL_SUCCESS;
#endif
}

static quote3_error_t set_default_policies(std::map<std::string, std::string> &id_map,
                                 rapidjson::Value &report_array,
                                 uint8_t *fmspc, uint16_t fmspc_size)
{
    quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
    uint8_t *p_platform_policy = NULL;
    uint32_t platform_policy_size = 0;
    // Check if we need to use default policies
    uint32_t index = 0;
    for (; index < report_array.Size(); index++)
    {
        if (report_array[index].HasMember("environment") == false)
        {
            // The updated qvl result includes some array items which has no "environment"
            // For example, "user_data" and "quote_hash". Skip these items
            continue;
        }
        std::string class_id = report_array[index]["environment"]["class_id"].GetString();
        if (id_map.count(class_id) == 0 && g_default_policy_map.count(class_id) != 0)
        {  
            ret = get_default_platform_policy_from_pccs(fmspc, fmspc_size, &p_platform_policy, &platform_policy_size);
            if (SGX_QL_SUCCESS != ret || p_platform_policy == NULL)
            {
                // Only return the error case of out of memory
                if(ret == SGX_QL_ERROR_OUT_OF_MEMORY)
                {
                    return ret;
                }
                se_trace(SE_TRACE_ERROR, "Failed to get default platform policy from PCCS. Will try to use strict policy instead\n");
            }
            break;
        }
    }
    if (index == report_array.Size())
    {
        // The platform policies are provided by users. No need to use default policies
        return SGX_QL_SUCCESS;
    }

    // The default policies from PCCS have merged the TDQE and platform policy. If a user inputs one of the TDQE and
    // TDX platform policy, we cannot use the merged policy from PCCS. In this case, we should stop searching the policies
    // from the result from PCCS and directly use the strict default policy from QAL.
    bool finish_set = false;
    if (p_platform_policy != NULL && id_map.count(TDX_TDQE_CLASS_ID) == 0 &&
        id_map.count(TDX10_PLATFORM_CLASS_ID) == 0 && id_map.count(TDX15_PLATFORM_CLASS_ID) == 0)
    {
        std::string policies(reinterpret_cast<const char *>(p_platform_policy), platform_policy_size);

        size_t last = 0;
        size_t next = 0;
        std::vector<std::string> vec;
        while ((next = policies.find(",", last)) != std::string::npos)
        {
            std::string token = policies.substr(last, next - last);
            last = next + 1;
            vec.push_back(token);
        }
        vec.push_back(policies.substr(last));
        for (auto item : vec)
        {
            std::string signature = "";
            std::string jwk = "";
            auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(item.c_str()), "policy_payload", PAYLOAD, signature, jwk);
            if (policy_json.empty() == false && signature.empty() == false && jwk.empty() == false)
            {
                rapidjson::Document policy_doc;
                policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());

                std::map<std::string, std::string> temp_policy_map;

                if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false ||
                    policy_doc["policy_array"].IsArray() == false)
                {
                    // Seems the policy from PCCS is not acceptable, we will continue to use the strict default policies
                    break;
                }
                rapidjson::Value &policy_array = policy_doc["policy_array"];
                for (uint32_t i = 0; i < policy_array.Size(); i++)
                {
                    if (policy_array[i].HasMember("environment") == false ||
                        policy_array[i]["environment"].HasMember("class_id") == false ||
                        policy_array[i]["environment"]["class_id"].IsString() == false)
                    {
                        break;
                    }

                    for (uint32_t j = 0; j < report_array.Size(); j++)
                    {
                        if (report_array[j].HasMember("environment") == false)
                        {
                            // The updated qvl result includes some array items which has no "environment"
                            // For example, "user_data" and "quote_hash". Skip these items
                            continue;
                        }
                        // Find the policy that matches the report_array and isn't included in the id_map
                        std::string class_id = report_array[j]["environment"]["class_id"].GetString();
                        if (class_id == policy_array[i]["environment"]["class_id"].GetString() && id_map.count(class_id) == 0)
                        {
                            rapidjson::Document jwk_doc;
                            jwk_doc.Parse<rapidjson::kParseCommentsFlag>(jwk.c_str());
                            if (jwk_doc.HasParseError())
                            {
                                break;
                            }
                            std::string v;
                            {
                                rapidjson::Document d;
                                d.SetObject();
                                rapidjson::Value &p = policy_array[i];
                                d.CopyFrom(p, d.GetAllocator());
                                rapidjson::Value str_v(rapidjson::kStringType);
                                str_v.SetString(signature.c_str(), (unsigned int)signature.length());
                                d.AddMember("signature", str_v, d.GetAllocator());
                                d.AddMember("signing_key", jwk_doc, jwk_doc.GetAllocator());
                                rapidjson::StringBuffer buffer;
                                rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                                d.Accept(writer);
                                v = buffer.GetString();
                            }
                            temp_policy_map[class_id] = v;
                            break;
                        }
                    }
                }
                if ((temp_policy_map.size() == 1 && temp_policy_map.count(SGX_PLATFORM_CLASS_ID) == 1) ||
                    (temp_policy_map.size() == 2 && temp_policy_map.count(TDX_TDQE_CLASS_ID) == 1 &&
                     (temp_policy_map.count(TDX10_PLATFORM_CLASS_ID) == 1 || temp_policy_map.count(TDX15_PLATFORM_CLASS_ID) == 1)))
                {
                    id_map.insert(temp_policy_map.begin(), temp_policy_map.end());
                    finish_set = true;
                    break; // break out the for() loop
                }
            }
        }
        if(finish_set == false)
        {
            se_trace(SE_TRACE_ERROR, "The policies from PCCS are unacceptable. Will use the strict default policies.\n");
        }
    }
    if (p_platform_policy != NULL)
    {
        free_default_platform_policy_from_pccs(p_platform_policy);
    }
    if (finish_set)
    {
        return SGX_QL_SUCCESS;
    }

    for (uint32_t i = 0; i < report_array.Size(); i++)
    {
        if (report_array[i].HasMember("environment") == false)
        {
            // The updated qvl result includes some array items which has no "environment"
            // For example, "user_data" and "quote_hash". Skip these items
            continue;
        }
        auto class_id = report_array[i]["environment"]["class_id"].GetString();
        if (id_map.count(class_id) == 0)
        {
            // Use the hard coded default strict policy in QAL
            auto it = g_default_policy_map.find(class_id);
            if (it != g_default_policy_map.end())
            {
                id_map[class_id] = it->second.policy;
            }
        }
    }
    return SGX_QL_SUCCESS;
}

quote3_error_t construct_complete_json(const uint8_t *p_verification_result_token,
                                       uint8_t **p_qaps, uint8_t qaps_count,
                                       std::string &output_json)
{
    assert(p_verification_result_token != NULL && p_qaps != NULL && qaps_count != 0);

    rapidjson::Document json_doc, qvl_doc, sub_doc;
    json_doc.SetObject();
    std::map<std::string, std::string> id_map;

    // 1: qvl_result
    std::string qvl_result = "";
    {
        std::string qvl_sig = "", qvl_jwk = "";
        qvl_result = get_info_from_jwt((const char *)p_verification_result_token, "qvl_result", PAYLOAD, qvl_sig, qvl_jwk);
    }
    if (qvl_result.empty())
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    qvl_doc.Parse<rapidjson::kParseStopWhenDoneFlag>(qvl_result.c_str());
    if (qvl_doc.HasParseError() || qvl_doc.HasMember("qvl_result") == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }
    rapidjson::Value &report_array = qvl_doc["qvl_result"];
    if (report_array.IsString())
    {
        // If report_array is not an array, we try to parse it as a json again, in case it was signed as a nested payload        
        std::string str2;
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
            report_array.Accept(writer);
            str2 = buffer.GetString();
        }
        sub_doc.Parse(str2.c_str());
        if (sub_doc.HasParseError() || sub_doc.HasMember("qvl_result") == false)
            return SGX_QL_ERROR_INVALID_PARAMETER;
        report_array = sub_doc["qvl_result"];
    }
    if (report_array.IsArray() == false)
    {
        return SGX_QL_ERROR_INVALID_PARAMETER;
    }

    // 2: Handle policies from users
    std::string signature[qaps_count];
    std::string jwk[qaps_count];
    std::vector<std::string> desired_id_vec = {TENANT_ENCLAVE_CLASS_ID, TENANT_TDX10_CLASS_ID, TENANT_TDX15_CLASS_ID, SGX_PLATFORM_CLASS_ID,
                                              TDX15_PLATFORM_CLASS_ID, TDX10_PLATFORM_CLASS_ID, TDX_TDQE_CLASS_ID};
    uint8_t fmspc[FMSPC_SIZE] = {0};
    bool fmspc_parsed = false;
    for (uint32_t i = 0; i < qaps_count; i++)
    {
        signature[i] = "";
        jwk[i] = "";
        if (!p_qaps[i])
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        auto policy_json = get_info_from_jwt(reinterpret_cast<const char *>(p_qaps[i]), "policy_payload", PAYLOAD, signature[i], jwk[i]);

        if (policy_json.empty() || signature[i].empty() || jwk[i].empty())
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        rapidjson::Document policy_doc;
        policy_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(policy_json.c_str());
        if (policy_doc.HasParseError() || policy_doc.HasMember("policy_array") == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        // Access the policy array
        rapidjson::Value &policy_array = policy_doc["policy_array"];
        rapidjson::Document sub_doc1;
        std::string str;
    
        if( policy_array.IsString())
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

        if(policy_array.IsArray() == false)
        {
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        // Construct the id_map after extract the report_array and policy_array
        // to choose one policy for one class_id
        for (uint32_t j = 0; j < report_array.Size(); j++)
        {
            if (report_array[j].HasMember("environment") == false)
            {
                // The updated qvl result includes some array items which has no "environment"
                // For example, "user_data" and "quote_hash". Skip these items
                continue;
            }
            if(report_array[j].HasMember("environment") == true &&
               (report_array[j]["environment"].HasMember("class_id") == false ||
               report_array[j]["environment"]["class_id"].IsString() == false))
            {
                se_trace(SE_TRACE_ERROR, "The input QVL result is not correct.\n");
                return SGX_QL_ERROR_INVALID_PARAMETER;
            }
            std::string class_id = report_array[j]["environment"]["class_id"].GetString();
            if (fmspc_parsed == false)
            {
                // Try to retrieve fmpsc from platform tcb result
                auto it = g_default_policy_map.find(class_id);
                if (it != g_default_policy_map.end() && class_id != TDX_TDQE_CLASS_ID)
                {
                    if (report_array[j].HasMember("measurement") == true &&
                        report_array[j]["measurement"].HasMember("fmspc") == true &&
                        report_array[j]["measurement"]["fmspc"].IsString() == true)
                    {
                        const char *tmp_str = report_array[j]["measurement"]["fmspc"].GetString();
                        if (strlen(tmp_str) != FMSPC_SIZE * 2)
                        {
                            se_trace(SE_TRACE_ERROR, "The input QVL result is not correct.\n");
                            return SGX_QL_ERROR_INVALID_PARAMETER;
                        }
                        for (uint32_t z = 0; z < strlen(tmp_str) / 2; z++)
                        {
                            char a[3] = {0};
                            strncpy(a, tmp_str + z * 2, 2);
                            fmspc[z] = (uint8_t)strtoul(a, NULL, 16);
                        }
                        fmspc_parsed = true;
                    }
                }
            }

            for (uint32_t z = 0; z < policy_array.Size(); z++)
            {
                if (policy_array[z].HasMember("environment") == false ||
                    policy_array[z]["environment"].HasMember("class_id") == false ||
                    policy_array[z]["environment"]["class_id"].IsString() == false)
                {
                    se_trace(SE_TRACE_ERROR, "The policy format is not correct. Item: %d, policy:\n%s\n", i, p_qaps[i]);
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                std::string class_id_p = policy_array[z]["environment"]["class_id"].GetString();
                if(std::find(desired_id_vec.begin(), desired_id_vec.end(), class_id_p) == desired_id_vec.end())
                {
                    se_trace(SE_TRACE_ERROR, "The policy format is not correct. Item: %d, policy:\n%s\n", i, p_qaps[i]);
                    return SGX_QL_ERROR_INVALID_PARAMETER;
                }
                if (class_id_p == class_id)
                {
                    if (id_map.count(class_id) == 0)
                    {
                        rapidjson::Document jwk_doc;
                        jwk_doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(jwk[i].c_str());
                        if (jwk_doc.HasParseError())
                        {
                            return SGX_QL_ERROR_INVALID_PARAMETER;
                        }
                        std::string v;
                        {
                            rapidjson::Document d;
                            d.SetObject();
                            rapidjson::Value &p = policy_array[z];
                            d.CopyFrom(p, d.GetAllocator());
                            rapidjson::Value str_v(rapidjson::kStringType);
                            str_v.SetString(signature[i].c_str(), (unsigned int)signature[i].length());
                            d.AddMember("signature", str_v, d.GetAllocator());
                            d.AddMember("signing_key", jwk_doc, jwk_doc.GetAllocator());
                            rapidjson::StringBuffer buffer;
                            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
                            d.Accept(writer);
                            v = buffer.GetString();
                        }
                        id_map[class_id] = v;
                        break;
                    }
                    else
                    {
                        se_trace(SE_TRACE_ERROR, "The input policies are not correct. Repeatedly entering numerous policies with the same class_id is prohibited.\n");
                        return SGX_QL_ERROR_INVALID_PARAMETER;
                    }
                }
            }
        }
    }

    // 3: Set default policies in case we need to do so
    quote3_error_t ret = set_default_policies(id_map, report_array, fmspc, FMSPC_SIZE);
    if(ret != SGX_QL_SUCCESS)
    {
        return ret;
    }

    json_doc.AddMember("qvl_result", qvl_doc["qvl_result"], json_doc.GetAllocator());

    rapidjson::Value nested_obj(rapidjson::kObjectType);
    json_doc.AddMember("policies", nested_obj, json_doc.GetAllocator());

    rapidjson::Value obj(rapidjson::kArrayType);
    rapidjson::Document subdoc;
    subdoc.SetArray();
    {
        for (auto it = id_map.begin(); it != id_map.end(); ++it)
        {
            rapidjson::Document d;
            d.SetObject();
            d.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(it->second.c_str());
            if (d.HasParseError())
                return SGX_QL_ERROR_UNEXPECTED;
            rapidjson::Value object(rapidjson::Type::kObjectType);
            object.CopyFrom(d, json_doc.GetAllocator());
            subdoc.PushBack(object, json_doc.GetAllocator());
        }
    }
    json_doc["policies"].AddMember("policy_array", subdoc, json_doc.GetAllocator());

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>> writer(buffer);
    json_doc.Accept(writer);

    SE_TRACE(SE_TRACE_DEBUG, "\nWhole json: \n %s\n", buffer.GetString());
    {
        rapidjson::Document doc;
        doc.SetObject();
        if (doc.Parse<rapidjson::kParseStopWhenDoneFlag | rapidjson::kParseCommentsFlag>(buffer.GetString()).HasParseError())
        {
            SE_TRACE(SE_TRACE_DEBUG, "error with offset %lu, %d\n", doc.GetErrorOffset(), doc.GetParseError());
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
    }
    output_json = buffer.GetString();

    return SGX_QL_SUCCESS;
}