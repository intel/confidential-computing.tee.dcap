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
 * File: certification_provider.cpp
 *
 * Description: CertificationProvider class implementation
 *
 */
#include "certification_provider.h"
#include "certification_service.h"
#include "document.h"
#include "local_cache.h"
#include "pck_cert_selection.h"
#include "qcnl_util.h"
#include <algorithm>

using namespace rapidjson;

// calculate sha256 hash
string sha256_hash(const void *data, size_t data_size) {
    string hash = sha256(data, data_size);
    if (hash.empty()) {
        qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] sha256 error. \n");
    }
    return hash;
}

////////////////////// CertificationProvider class ///////////////////////////////////////
CertificationProvider::CertificationProvider(const string &base_url) {
    this->base_url_ = base_url;
}

CertificationProvider::~CertificationProvider() {
}

sgx_qcnl_error_t CertificationProvider::get_certification(const http_header_map &header_map,
                                                          const string &query_string,
                                                          PccsResponseObject *pccs_resp_obj) {

    if (this->base_url_.empty()) {
        return SGX_QCNL_INVALID_CONFIG;
    }

    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    char *resp_msg = NULL;
    uint32_t resp_size = 0;
    char *resp_header = NULL;
    uint32_t header_size = 0;
    string url = this->base_url_ + query_string;

    ret = qcnl_https_request(url.c_str(), header_map, NULL, 0, NULL, 0, &resp_msg, resp_size, &resp_header, header_size);
    if (ret != SGX_QCNL_SUCCESS) {
        return ret;
    } else if (!resp_msg || resp_size == 0) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }

    pccs_resp_obj->set_raw_header(resp_header, header_size).set_raw_body(resp_msg, resp_size);

    if (resp_msg) {
        free(resp_msg);
        resp_msg = NULL;
    }
    if (resp_header) {
        free(resp_header);
        resp_header = NULL;
    }

    return ret;
}

////////////////////// CacheProvider class ///////////////////////////////////////
CacheProvider::CacheProvider() {
}

CacheProvider::CacheProvider(const string &base_url) {
    this->base_url_ = base_url;
}

CacheProvider::~CacheProvider() {
}

sgx_qcnl_error_t CacheProvider::get_certification(const string &query_string,
                                                  PccsResponseObject *pccs_resp_obj) {
    string url = this->base_url_ + query_string;
    string cache_key = sha256_hash(url.data(), url.size());
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetching from the local cache for: '%s' \n", url.c_str());

    vector<uint8_t> value;
    if (!LocalCache::Instance().get_data(cache_key, value)) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache missed. \n");
        return SGX_QCNL_CACHE_MISSING;
    }

    do {
        // Require at least CacheItemHeader + two 4-byte length fields to avoid OOB read
        // and size_t underflow in the subsequent header_size bound check.
        if (value.size() < sizeof(CacheItemHeader) + 2 * sizeof(uint32_t) ||
            value.size() > UINT32_MAX) {
            break;
        }

        // Check expiry
        CacheItemHeader cache_header;
        if (memcpy_s(&cache_header, sizeof(CacheItemHeader), value.data(), sizeof(CacheItemHeader)) != 0)
            break;
        if (cache_header.version != 1) {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Unrecorgnized cache version : %d. \n", cache_header.version);
            ret = SGX_QCNL_CACHE_MISSING;
            break;
        }
        if (is_cache_item_expired(cache_header.expiry)) {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache expired. \n");
            ret = SGX_QCNL_CACHE_EXPIRED;
            break;
        }

        // Parse header
        // Use memcpy to avoid undefined behavior from unaligned uint32_t access
        // (CacheItemHeader is packed, so p_data may not be 4-byte aligned).
        // After the minimum-size guard, use subtraction-form checks to avoid
        // size_t addition overflow on 32-bit builds.
        uint8_t *p_data = value.data() + sizeof(CacheItemHeader);
        const size_t payload_capacity = value.size() - sizeof(CacheItemHeader) - 2 * sizeof(uint32_t);
        uint32_t header_size = 0;
        memcpy(&header_size, p_data, sizeof(uint32_t));
        if (header_size > payload_capacity)
            break;
        p_data += sizeof(uint32_t);
        pccs_resp_obj->set_raw_header((const char *)p_data, header_size);

        // Parse body
        p_data += header_size;
        uint32_t body_size = 0;
        memcpy(&body_size, p_data, sizeof(uint32_t));
        if (body_size != payload_capacity - header_size)
            break;
        p_data += sizeof(uint32_t);
        pccs_resp_obj->set_raw_body((const char *)p_data, body_size);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetched from the local cache successfully. \n");

        ret = SGX_QCNL_SUCCESS;
    } while (false);

    if (ret != SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache item expired or corrupted. \n");
        LocalCache::Instance().remove_data(cache_key);
    }

    return ret;
}

sgx_qcnl_error_t CacheProvider::set_certification(sgx_qpl_cache_type_t cache_type,
                                                  const string &query_string,
                                                  PccsResponseObject *pccs_resp_obj) {
    uint32_t default_expiry_seconds;
    if (cache_type == SGX_QPL_CACHE_CERTIFICATE) {
        default_expiry_seconds = (uint32_t)(QcnlConfig::Instance()->getCacheExpireHour() * 3600);
    } else {
        default_expiry_seconds = (uint32_t)(QcnlConfig::Instance()->getVerifyCollateralExpireHour() * 3600);
    }

    // Cache-Control:max-age has higher priority over config file
    uint32_t cache_max_age = pccs_resp_obj->get_cache_max_age();
    uint32_t expiry_seconds = (cache_max_age > 0) ? cache_max_age : default_expiry_seconds;

    if (expiry_seconds > 0) {
        string url = this->base_url_ + query_string;
        string cache_key = sha256_hash(url.data(), url.size());
        if (cache_key.empty()) {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }

        vector<uint8_t> value;

        time_t current_time = time(NULL);
        CacheItemHeader cache_header;
        memset(&cache_header, 0, sizeof(cache_header));
        cache_header.version = 1;
        cache_header.cache_type = cache_type;
        cache_header.expiry = current_time + expiry_seconds;

        // Append cache header
        uint8_t *p_data = reinterpret_cast<uint8_t *>(&cache_header);
        value.insert(value.end(), p_data, p_data + sizeof(cache_header));

        // Append repsonse header and body
        string header = pccs_resp_obj->get_raw_header();
        size_t header_size = header.size();
        string body = pccs_resp_obj->get_raw_body();
        size_t body_size = body.size();
        value.insert(value.end(), (uint8_t *)&header_size, (uint8_t *)&header_size + 4);
        value.insert(value.end(), header.data(), header.data() + header_size);
        value.insert(value.end(), (uint8_t *)&body_size, (uint8_t *)&body_size + 4);
        value.insert(value.end(), body.data(), body.data() + body_size);

        LocalCache::Instance().set_data(cache_key, value);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Caching collateral '%s' for %d seconds. \n", url.c_str(), expiry_seconds);
    }

    return SGX_QCNL_SUCCESS;
}

static bool extract_data(uint8_t *&p_data, const uint8_t *p_data_end, uint32_t &size, string &str) {
    if (p_data >= p_data_end - sizeof(uint32_t)) {
        return false;
    }
    size = *reinterpret_cast<const uint32_t *>(p_data);
    p_data += sizeof(uint32_t);
    if (p_data > p_data_end - size) {
        return false;
    }
    str.assign(reinterpret_cast<const char *>(p_data), size);
    p_data += size;
    return true;
}

bool CacheProvider::parse_certificates_json(const string &certificates_json_str, vector<string> &pck_certs, vector<string> &tcbms) {
    // Load certificates JSON
    Document doc_certs;
    ParseResult ok = doc_certs.Parse(certificates_json_str.c_str());
    if (!ok || !doc_certs.IsArray()) {
        qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to load certificates json from cache file. \n");
        return false;
    }

    for (const auto &cert_obj : doc_certs.GetArray()) {
        if (!cert_obj.IsObject()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid cache file. \n");
            continue;
        }

        if (!cert_obj.HasMember("cert") || !cert_obj["cert"].IsString()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid cache file. \n");
            continue;
        }

        if (!cert_obj.HasMember("tcbm") || !cert_obj["tcbm"].IsString()) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid cache file. \n");
            continue;
        }

        string cert = cert_obj["cert"].GetString();
        string tcbm = cert_obj["tcbm"].GetString();
        pck_certs.push_back(unescape(cert));
        tcbms.push_back(tcbm);
    }

    return true;
}

sgx_qcnl_error_t CacheProvider::get_local_certification(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                        sgx_ql_config_t **pp_quote_config) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    string cache_key = "";

    if (!concat_string_with_hex_buf(cache_key, p_pck_cert_id->p_qe3_id, p_pck_cert_id->qe3_id_size)) {
        return ret;
    }
    cache_key.append("_");
    if (!concat_string_with_hex_buf(cache_key, reinterpret_cast<const uint8_t *>(&p_pck_cert_id->pce_id), sizeof(p_pck_cert_id->pce_id))) {
        return ret;
    }

    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetching local cache from '%s' \n", cache_key.c_str());

    vector<uint8_t> value;
    if (!LocalCache::Instance().get_data(cache_key, value)) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Local cache file '%s' not found.\n", cache_key.c_str());
        // try 0000000000000000_0000
        cache_key = "0000000000000000_0000";
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetching local cache from '%s' \n", cache_key.c_str());
        if (!LocalCache::Instance().get_data(cache_key, value)) {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache missed. \n");
            return SGX_QCNL_CACHE_MISSING;
        }
    }

    do {
        if (value.size() < sizeof(CacheItemHeader) ||
            value.size() > UINT32_MAX) {
            break;
        }

        // Check expiry
        CacheItemHeader cache_header;
        if (memcpy_s(&cache_header, sizeof(CacheItemHeader), value.data(), sizeof(CacheItemHeader)) != 0)
            break;
        if (is_cache_item_expired(cache_header.expiry)) {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache expired. \n");
            ret = SGX_QCNL_CACHE_EXPIRED;
            break;
        }

        // Extract data from the cache file
        uint8_t *p_data = value.data() + sizeof(CacheItemHeader);
        const uint8_t *p_data_end = value.data() + value.size();
        uint32_t component_size, tcbinfo_size, certchain_size, certificates_size;
        string component_str, tcbinfo_str, certchain_str, certificates_str;
        if (!extract_data(p_data, p_data_end, component_size, component_str))
            break;
        if (!extract_data(p_data, p_data_end, tcbinfo_size, tcbinfo_str))
            break;
        if (!extract_data(p_data, p_data_end, certchain_size, certchain_str))
            break;
        if (!extract_data(p_data, p_data_end, certificates_size, certificates_str))
            break;

        // Parse the certificates json object in the cache file
        vector<string> pck_certs;
        vector<string> tcbms;
        if (!parse_certificates_json(certificates_str, pck_certs, tcbms)) {
            break;
        }
        vector<const char *> pck_certs_cstr(pck_certs.size());
        std::transform(pck_certs.begin(), pck_certs.end(), pck_certs_cstr.begin(),
                       [](const std::string &str) { return str.c_str(); });

        // Convert component string to buffer
        uint8_t tcb_component[CPUSVN_SIZE];
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t *>(component_str.data()),
                                      component_size,
                                      tcb_component,
                                      sizeof(tcb_component))) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Failed to read TCB component. \n");
            break;
        }

        // Call PCK Cert selection library to get the appropriate certificate for the raw TCB
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Perform PCK cert selection ... \n");

        uint32_t best_index = 0;
        pck_cert_selection_res_t res = pck_cert_select_with_component(reinterpret_cast<const cpu_svn_t *>(tcb_component),
                                                                      *(p_pck_cert_id->p_platform_pce_isv_svn),
                                                                      p_pck_cert_id->pce_id,
                                                                      tcbinfo_str.c_str(),
                                                                      pck_certs_cstr.data(),
                                                                      (uint32_t)pck_certs_cstr.size(),
                                                                      &best_index);
        if (res != PCK_CERT_SELECT_SUCCESS) {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] PCK cert selection failed : %d. \n", res);
            break;
        }

        string tcbm = tcbms[best_index];
        string pck_cert = pck_certs[best_index];
        string certchain = unescape(certchain_str);

        ret = CertificationService::setup_quote_config(tcbm, pck_cert, certchain, pp_quote_config);
        if (ret == SGX_QCNL_SUCCESS)
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Fetched from the local cache successfully. \n");
    } while (false);

    if (ret != SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Cache item expired or corrupted. \n");
        LocalCache::Instance().remove_data(cache_key);
    }

    return ret;
}
