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
 * File: certification_service.cpp
 *
 * Description: CertificationService class
 *
 */
#include "certification_service.h"
#include "qcnl_config.h"
#include "qcnl_util.h"
#include "se_memcpy.h"
#include <sgx_ql_lib_common.h>
#include <regex>

#ifdef _MSC_VER
#undef GetObject
#endif

#define HANDLE_ERROR(error_code, log_message)    \
    {                                            \
        qcnl_log(SGX_QL_LOG_ERROR, log_message); \
        ret = error_code;                        \
        break;                                   \
    }

template<typename T>
T* allocate_and_copy(const std::string& source, uint32_t size) {
    if (source.size() != size - 1) {
        return nullptr;
    }
    T* destination = (T*)malloc(size);
    if (!destination) {
        return nullptr;
    }
    if (memcpy_s(destination, size, source.data(), source.size()) != 0) {
        free(destination);
        return nullptr;
    }
    destination[source.size()] = '\0'; // NULL-terminate for safety
    return destination;
}

static sgx_qpl_cache_type_t get_cache_type_of_request(RequestType type) {
    switch (type) {
    case PCK_CERT_CHAIN:
        return SGX_QPL_CACHE_CERTIFICATE;
    default:
        return SGX_QPL_CACHE_QV_COLLATERAL;
    }
}

CertificationService::CertificationService() {
}

CertificationService::CertificationService(const char *custom_param) {
    if (custom_param)
        custom_param_ = custom_param;
}

CertificationService::~CertificationService() {
}

sgx_qcnl_error_t CertificationService::fetch_data(RequestType type, const Request &request, HandlerData *handlerData) {
    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    PccsResponseObject pccs_resp_obj;
    string query_str;

    CacheProvider cacheProvider(request.endpoint);
    if (type == PCK_CERT_CHAIN) {
        // encrypted_ppid shouldn't be part of cache key because the caller will send
        // all 0 encrypted ppid sometimes
        query_str = regex_replace(request.params, regex("&encrypted_ppid=[0-9a-zA-Z]+&"), "&");
    } else {
        query_str = request.params;
    }
    if ((ret = cacheProvider.get_certification(query_str, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        return handlerData->handler(&pccs_resp_obj, handlerData->args);
    }

    qcnl_log(SGX_QL_LOG_INFO,
             "[QCNL] Data not found in local cache. Trying to fetch response from remote URL: '%s'. \n",
             request.endpoint.c_str());
    CertificationProvider remoteProvider(request.endpoint);
    if ((ret = remoteProvider.get_certification(request.headers, request.params, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO,
                 "[QCNL] Successfully fetched certificate from remote URL: '%s'. \n",
                 request.endpoint.c_str());
        sgx_qcnl_error_t handler_ret = handlerData->handler(&pccs_resp_obj, handlerData->args);
        if (handler_ret == SGX_QCNL_SUCCESS) {
            ret = cacheProvider.set_certification(get_cache_type_of_request(type),
                                                  query_str, &pccs_resp_obj); // User query_str for caching key
        } else {
            ret = handler_ret;
        }
        else {
            // Propagate the handler's error instead of masking it with the
            // prior SGX_QCNL_SUCCESS from remoteProvider.get_certification.
            // Otherwise callers (e.g. qe_logic.cpp) believe the fetch
            // succeeded and may dereference a partially-initialized or
            // already-freed *pp_quote_config (UAF / double-free).
            ret = handler_ret;
        }
    }
    return ret;
}

sgx_qcnl_error_t CertificationService::setup_quote_config(const string &tcbm,
                                                          const string &pck_cert,
                                                          const string &certchain,
                                                          sgx_ql_config_t **pp_quote_config) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;

    do {
        if (tcbm.size() != (consts::CPUSVN_SIZE + consts::PCESVN_SIZE) * 2 || certchain.empty() || pck_cert.empty()) {
            HANDLE_ERROR(SGX_QCNL_UNEXPECTED_ERROR, "[QCNL] Response message error. \n");
        }

        // allocate output buffer
        *pp_quote_config = (sgx_ql_config_t *)malloc(sizeof(sgx_ql_config_t));
        if (*pp_quote_config == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }
        memset(*pp_quote_config, 0, sizeof(sgx_ql_config_t));

        // set version
        (*pp_quote_config)->version = SGX_QL_CONFIG_VERSION_1;

        // set tcbm
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t *>(tcbm.data()),
                                      consts::CPUSVN_SIZE * 2,
                                      reinterpret_cast<uint8_t *>(&(*pp_quote_config)->cert_cpu_svn),
                                      sizeof(sgx_cpu_svn_t))) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Failed to parse cpu svn. \n");
        }
        if (!hex_string_to_byte_array(reinterpret_cast<const uint8_t *>(tcbm.data() + consts::CPUSVN_SIZE * 2),
                                      consts::PCESVN_SIZE * 2,
                                      reinterpret_cast<uint8_t *>(&(*pp_quote_config)->cert_pce_isv_svn),
                                      sizeof(sgx_isv_svn_t))) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Failed to parse pce svn. \n");
        }

        // set certchain (leaf cert || intermediateCA || root CA || '\0')
        (*pp_quote_config)->cert_data_size = (uint32_t)(pck_cert.size() + certchain.size() + 1);
        (*pp_quote_config)->p_cert_data = allocate_and_copy<uint8_t>(pck_cert + certchain, (*pp_quote_config)->cert_data_size);
        if (!(*pp_quote_config)->p_cert_data) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_pck_cert_chain(*pp_quote_config);
    // sgx_qcnl_free_pck_cert_chain receives the struct pointer by value, so it
    // cannot null the caller's variable. Reset *pp_quote_config here so the
    // caller does not double-free or use-after-free a dangling pointer on the
    // error path.
    *pp_quote_config = NULL;
    return ret;
}

string CertificationService::get_custom_param_string() {
    if (custom_param_.empty())
        return "";

    // custom_param_ is BASE64 encoded string, so we need to escape '+','/','='
    string s = custom_param_;
    s = regex_replace(s, regex("\\+"), "%2B");
    s = regex_replace(s, regex("\\/"), "%2F");
    s = regex_replace(s, regex("\\="), "%3D");
    return "customParameter=" + s;
}

sgx_qcnl_error_t CertificationService::build_pckcert_options(Request &request, const sgx_ql_pck_cert_id_t *p_pck_cert_id) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    request.endpoint = QcnlConfig::Instance()->getServerUrl();

    // Append QE ID
    request.params.append("pckcert?qeid=");
    if (!concat_string_with_hex_buf(request.params, p_pck_cert_id->p_qe3_id, p_pck_cert_id->qe3_id_size)) {
        return ret;
    }

    // Append encrypted PPID
    request.params.append("&encrypted_ppid=");
    if (p_pck_cert_id->p_encrypted_ppid == NULL) {
        uint8_t enc_ppid_unused[consts::ENC_PPID_SIZE] = {0};
        if (!concat_string_with_hex_buf(request.params, (const uint8_t *)&enc_ppid_unused, sizeof(enc_ppid_unused))) {
            return ret;
        }
    } else {
        if (!concat_string_with_hex_buf(request.params, p_pck_cert_id->p_encrypted_ppid, p_pck_cert_id->encrypted_ppid_size)) {
            return ret;
        }
    }

    // Append cpusvn
    request.params.append("&cpusvn=");
    if (!concat_string_with_hex_buf(request.params, reinterpret_cast<const uint8_t *>(p_pck_cert_id->p_platform_cpu_svn), sizeof(sgx_cpu_svn_t))) {
        return ret;
    }

    // Append pcesvn
    request.params.append("&pcesvn=");
    if (!concat_string_with_hex_buf(request.params, reinterpret_cast<const uint8_t *>(p_pck_cert_id->p_platform_pce_isv_svn), sizeof(sgx_isv_svn_t))) {
        return ret;
    }

    // Append pceid
    request.params.append("&pceid=");
    if (!concat_string_with_hex_buf(request.params, reinterpret_cast<const uint8_t *>(&p_pck_cert_id->pce_id), sizeof(p_pck_cert_id->pce_id))) {
        return ret;
    }

    // Custom request options
    Document &custom_options = QcnlConfig::Instance()->getCustomRequestOptions();
    if (!custom_options.IsNull() && custom_options.HasMember("get_cert") && custom_options["get_cert"].IsObject()) {
        const char *members[] = {"params", "headers"};
        for (const char *member : members) {
            if (custom_options["get_cert"].HasMember(member)) {
                Value &data = custom_options["get_cert"][member];
                if (data.IsObject()) {
                    for (auto &m : data.GetObject()) {
                        if (m.name.IsString() && m.value.IsString()) {
                            string key = m.name.GetString();
                            string value = m.value.GetString();
                            
                            if (strcmp(member, "params") == 0) {
                                request.params.append("&").append(key).append("=").append(value);
                            } else if (strcmp(member, "headers") == 0) {
                                request.headers.insert(pair<string, string>(key, value));
                            }
                        }
                    }
                }
            }
        }
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_pckcrl_options(Request &request, const char *ca, uint16_t ca_size) {
    (void)ca_size;
    request.endpoint = QcnlConfig::Instance()->getCollateralServiceUrl();

    // Append ca and encoding
    request.params.append("pckcrl?ca=").append(ca);
    if (is_collateral_service_pcs() || QcnlConfig::Instance()->getCollateralVersion() == "3.1") {
        request.params.append("&encoding=der");
    }
    if (!custom_param_.empty()) {
        request.params.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_tcbinfo_options(Request &request,
                                                             const char *fmspc,
                                                             uint16_t fmspc_size,
                                                             sgx_prod_type_t prod_type) {
    request.endpoint = QcnlConfig::Instance()->getCollateralServiceUrl();
    if (prod_type == SGX_PROD_TYPE_TDX) {
        auto found = request.endpoint.find("/sgx/");
        if (found != std::string::npos) {
            request.endpoint = request.endpoint.replace(found, 5, "/tdx/");
        } else {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }
    }

    // Append fmspc
    request.params.append("tcb?fmspc=");
    if (!concat_string_with_hex_buf(request.params, reinterpret_cast<const uint8_t *>(fmspc), fmspc_size)) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    request.params.append("&update=").append(QcnlConfig::Instance()->getTcbUpdateType());
    if (!custom_param_.empty()) {
        request.params.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_qeidentity_options(Request &request, sgx_qe_type_t qe_type) {
    request.endpoint = QcnlConfig::Instance()->getCollateralServiceUrl();
    if (qe_type == SGX_QE_TYPE_TD) {
        auto found = request.endpoint.find("/sgx/");
        if (found != std::string::npos) {
            request.endpoint = request.endpoint.replace(found, 5, "/tdx/");
        } else {
            return SGX_QCNL_UNEXPECTED_ERROR;
        }
    }

    request.params.append("qe/identity");
    request.params.append("?update=").append(QcnlConfig::Instance()->getTcbUpdateType());
    if (!custom_param_.empty()) {
        request.params.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_qveidentity_options(Request &request) {
    request.endpoint = QcnlConfig::Instance()->getCollateralServiceUrl();

    request.params.append("qve/identity");
    request.params.append("?update=").append(QcnlConfig::Instance()->getTcbUpdateType());
    if (!custom_param_.empty()) {
        request.params.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

// The root CA CRL distribution point URL is parsed out of a certificate that
// was received over the network from the configured collateral service. Even
// when that service is the real Intel PCS, this string reaches us before the
// surrounding cert chain has been verified, and it can in principle carry any
// scheme that the underlying transport library is willing to dial (file://,
// gopher://, ldap://, an internal http://169.254.169.254/... metadata URL,
// etc.). Restrict CDP URLs that get promoted into request.endpoint to https
// pointing at a host that the configured PCS endpoint also accepts, so a
// tampered cert cannot turn this call site into a server-side request forgery
// primitive against the host running the QPL.
static bool is_safe_pcs_cdp_url(const std::string &cdp_url) {
    static const std::string kHttpsPrefix = "https://";
    if (cdp_url.compare(0, kHttpsPrefix.size(), kHttpsPrefix) != 0) {
        return false;
    }
    const std::string::size_type host_begin = kHttpsPrefix.size();
    const std::string::size_type host_end = cdp_url.find_first_of("/?#", host_begin);
    const std::string host = cdp_url.substr(host_begin,
        host_end == std::string::npos ? std::string::npos : host_end - host_begin);
    if (host.empty()) {
        return false;
    }
    // Reject any URL whose authority component carries a userinfo segment
    // ("user@host"). Without this, an attacker-supplied CDP like
    // "https://trustedservices.intel.com@evil.com/" would have the substring
    // host check evaluate against the userinfo while libcurl ultimately
    // connects to the host after '@', enabling an SSRF bypass.
    if (host.find('@') != std::string::npos) {
        return false;
    }
    // Strip optional :port for the host comparison.
    const std::string::size_type colon = host.find(':');
    const std::string hostname = (colon == std::string::npos) ? host : host.substr(0, colon);
    // is_collateral_service_pcs() already gated us into this branch by looking
    // for trustedservices.intel.com inside the configured collateral URL;
    // require the CDP host to be in that same DNS suffix.
    static const std::string kPcsHostSuffix = ".trustedservices.intel.com";
    if (hostname == "trustedservices.intel.com") {
        return true;
    }
    if (hostname.size() > kPcsHostSuffix.size() &&
        hostname.compare(hostname.size() - kPcsHostSuffix.size(), kPcsHostSuffix.size(),
                         kPcsHostSuffix) == 0) {
        return true;
    }
    return false;
}

// Percent-encode every character that is not in the RFC 3986 "unreserved"
// set plus the small path/scheme punctuation we expect to appear in a
// well-formed https CDP URL. Used when embedding the (already validated)
// CDP URL as a value inside a PCCS query string so that meta-characters
// like '&' or '#' in the CDP cannot inject or terminate additional query
// parameters.
static std::string percent_encode_query_value(const std::string &in) {
    static const char kHexDigits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        const bool unreserved =
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexDigits[(c >> 4) & 0x0F]);
            out.push_back(kHexDigits[c & 0x0F]);
        }
    }
    return out;
}

sgx_qcnl_error_t CertificationService::build_root_ca_crl_options(Request &request, const char *root_ca_cdp_url) {
    if (root_ca_cdp_url == NULL) {
        return SGX_QCNL_INVALID_PARAMETER;
    }
    // Snapshot the caller's URL once so the bytes we validate are the same
    // bytes we later hand to libcurl / append into the PCCS query string.
    const std::string cdp_url(root_ca_cdp_url);
    if (is_collateral_service_pcs()) {
        if (!is_safe_pcs_cdp_url(cdp_url)) {
            qcnl_log(SGX_QL_LOG_ERROR,
                "[QCNL] Refusing to fetch root CA CRL: CDP URL is not an https URL on the Intel PCS host.\n");
            return SGX_QCNL_INVALID_PARAMETER;
        }
        request.endpoint = cdp_url;
    } else {
        request.endpoint = QcnlConfig::Instance()->getCollateralServiceUrl();

        if (QcnlConfig::Instance()->getCollateralVersion() == "3.0") {
            // For PCCS API version 3.0, will call API /rootcacrl, and it will return HEX encoded CRL
            request.params.append("rootcacrl");
            if (!custom_param_.empty()) {
                request.params.append("?").append(get_custom_param_string());
            }
        } else if (QcnlConfig::Instance()->getCollateralVersion() == "3.1") {
            // For PCCS API version 3.1, will call API /crl, and it will return raw DER buffer
            if (!is_safe_pcs_cdp_url(cdp_url)) {
                qcnl_log(SGX_QL_LOG_ERROR,
                    "[QCNL] Refusing to forward root CA CRL CDP URL to PCCS: not an https URL on the Intel PCS host.\n");
                return SGX_QCNL_INVALID_PARAMETER;
            }
            request.params.append("crl?uri=").append(percent_encode_query_value(cdp_url));
            if (!custom_param_.empty()) {
                request.params.append("&").append(get_custom_param_string());
            }
        } else {
            return SGX_QCNL_INVALID_CONFIG;
        }
    }
    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::build_appraisalpolicy_options(Request &request,
                                                                     const char *fmspc,
                                                                     uint16_t fmspc_size) {
    request.endpoint = QcnlConfig::Instance()->getServerUrl();
    // Append fmspc
    request.params.append("appraisalpolicy?fmspc=");
    if (!concat_string_with_hex_buf(request.params, reinterpret_cast<const uint8_t *>(fmspc), fmspc_size)) {
        return SGX_QCNL_UNEXPECTED_ERROR;
    }
    if (!custom_param_.empty()) {
        request.params.append("&").append(get_custom_param_string());
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_pck_certchain(PccsResponseObject *pccs_resp_obj, void *args) {
    PckCertResponseObject *pckcert_resp_obj = (PckCertResponseObject *)pccs_resp_obj;
    void **argsArray = (void **)args;
    sgx_ql_config_t **pp_quote_config = (sgx_ql_config_t **)argsArray[0];

    // Get TCBm , Issuer Chain, PCK certificate from response
    string tcbm = pckcert_resp_obj->get_tcbm();
    string certchain = pckcert_resp_obj->get_pckcert_issuer_chain();
    string pck_cert = pckcert_resp_obj->get_pckcert();

    certchain = unescape(certchain);

    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-Tcbm: %s \n", tcbm.c_str());
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] pckCert: %s \n", pck_cert.c_str());
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-Pck-Certificate-Issuer-Chain: %s \n", certchain.c_str());

    return CertificationService::setup_quote_config(tcbm, pck_cert, certchain, pp_quote_config);
}

sgx_qcnl_error_t CertificationService::resp_obj_to_pck_crl(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    PckCrlResponseObject *pckcrl_resp_obj = (PckCrlResponseObject *)pccs_resp_obj;
    void **argsArray = (void **)args;
    uint8_t **pp_crl_chain = (uint8_t **)argsArray[0];
    uint16_t *p_crl_chain_size = (uint16_t *)argsArray[1];

    do {
        string certchain = pckcrl_resp_obj->get_pckcrl_issuer_chain();
        string crl = pckcrl_resp_obj->get_pckcrl();
        if (certchain.empty() || crl.empty()) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Response message error. \n");
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-pck-crl-issuer-chain: %s \n", certchain.c_str());

        // allocate_and_copy always append a NULL terminator
        *p_crl_chain_size = (uint16_t)(crl.size() + certchain.size() + 2);
        
        // set certchain (crl || ('\0) || intermediateCA || root CA || '\0')
        *pp_crl_chain = allocate_and_copy<uint8_t>(crl + '\0' + certchain, *p_crl_chain_size);
        if (*pp_crl_chain == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_pck_crl_chain(*pp_crl_chain);
    // Free helpers take their argument by value and cannot null the caller's
    // pointer. Reset out-params here so callers cannot double-free or read a
    // dangling pointer on the error path.
    *pp_crl_chain = NULL;
    *p_crl_chain_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_tcbinfo(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    TcbInfoResponseObject *tcbinfo_resp_obj = (TcbInfoResponseObject *)pccs_resp_obj;
    void **argsArray = (void **)args;
    uint8_t **pp_tcbinfo = (uint8_t **)argsArray[0];
    uint16_t *p_tcbinfo_size = (uint16_t *)argsArray[1];

    do {
        string certchain = tcbinfo_resp_obj->get_tcbinfo_issuer_chain();
        string tcbinfo = tcbinfo_resp_obj->get_tcbinfo();
        if (certchain.empty() || tcbinfo.empty()) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Response message error. \n");
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] tcbinfo: %s \n", tcbinfo.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] tcb-info-issuer-chain: %s \n", tcbinfo.c_str());

        *p_tcbinfo_size = (uint16_t)(tcbinfo.size() + certchain.size() + 2);
        *pp_tcbinfo = allocate_and_copy<uint8_t>(tcbinfo + '\0' + certchain, *p_tcbinfo_size);
        if (*pp_tcbinfo == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_tcbinfo(*pp_tcbinfo);
    *pp_tcbinfo = NULL;
    *p_tcbinfo_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_qe_identity(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    QeIdentityResponseObject *qe_identity_resp_obj = (QeIdentityResponseObject *)pccs_resp_obj;
    void **argsArray = (void **)args;
    uint8_t **pp_qe_identity = (uint8_t **)argsArray[0];
    uint16_t *p_qe_identity_size = (uint16_t *)argsArray[1];

    do {
        string certchain = qe_identity_resp_obj->get_enclave_id_issuer_chain();
        string qeidentity = qe_identity_resp_obj->get_qeidentity();
        if (certchain.empty() || qeidentity.empty()) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Response message error. \n");
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] qe identity: %s \n", qeidentity.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-enclave-identity-issuer-chain: %s \n", certchain.c_str());

        *p_qe_identity_size = (uint16_t)(qeidentity.size() + certchain.size() + 2);
        *pp_qe_identity = allocate_and_copy<uint8_t>(qeidentity + '\0' + certchain, *p_qe_identity_size);
        if (*pp_qe_identity == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_qe_identity(*pp_qe_identity);
    *pp_qe_identity = NULL;
    *p_qe_identity_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_qve_identity(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    QveIdentityResponseObject *qve_identity_resp_obj = (QveIdentityResponseObject *)pccs_resp_obj;
    void **argsArray = (void **)args;
    char **pp_qve_identity = (char **)argsArray[0];
    uint32_t *p_qve_identity_size = (uint32_t *)argsArray[1];
    char **pp_qve_identity_issuer_chain = (char **)argsArray[2];
    uint32_t *p_qve_identity_issuer_chain_size = (uint32_t *)argsArray[3];

    do {
        string certchain = qve_identity_resp_obj->get_enclave_id_issuer_chain();
        string qveidentity = qve_identity_resp_obj->get_qveidentity();
        if (certchain.empty() || qveidentity.empty()) {
            HANDLE_ERROR(SGX_QCNL_MSG_ERROR, "[QCNL] Response message error. \n");
        }

        certchain = unescape(certchain);

        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] qve identity: %s \n", qveidentity.c_str());
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] sgx-enclave-identity-issuer-chain: %s \n", certchain.c_str());

        // allocate and copy buffers for qveidentity
        *p_qve_identity_size = (uint32_t)qveidentity.size() + 1;
        *pp_qve_identity = allocate_and_copy<char>(qveidentity, *p_qve_identity_size);
        if (*pp_qve_identity == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        *p_qve_identity_issuer_chain_size = (uint32_t)(certchain.size() + 1);
        *pp_qve_identity_issuer_chain = allocate_and_copy<char>(certchain, *p_qve_identity_issuer_chain_size);
        if (*pp_qve_identity_issuer_chain == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_qve_identity(*pp_qve_identity, *pp_qve_identity_issuer_chain);
    *pp_qve_identity = NULL;
    *p_qve_identity_size = 0;
    *pp_qve_identity_issuer_chain = NULL;
    *p_qve_identity_issuer_chain_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_root_ca_crl(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    void **argsArray = (void **)args;
    uint8_t **pp_root_ca_crl = (uint8_t **)argsArray[0];
    uint16_t *p_root_ca_crl_size = (uint16_t *)argsArray[1];

    do {
        string root_ca_crl = pccs_resp_obj->get_raw_body();

        *p_root_ca_crl_size = (uint16_t)(root_ca_crl.size() + 1);
        *pp_root_ca_crl = allocate_and_copy<uint8_t>(root_ca_crl, *p_root_ca_crl_size);
        if (*pp_root_ca_crl == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    sgx_qcnl_free_root_ca_crl(*pp_root_ca_crl);
    *pp_root_ca_crl = NULL;
    *p_root_ca_crl_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::resp_obj_to_appraisalpolicy(PccsResponseObject *pccs_resp_obj, void *args) {
    sgx_qcnl_error_t ret = SGX_QCNL_UNEXPECTED_ERROR;
    void **argsArray = (void **)args;
    uint8_t **pp_platform_policy = (uint8_t **)argsArray[0];
    uint32_t *p_platform_policy_size = (uint32_t *)argsArray[1];

    do {
        string policy = pccs_resp_obj->get_raw_body();
        if (policy.empty()) {
            HANDLE_ERROR(SGX_QCNL_ERROR_STATUS_NO_CACHE_DATA, "[QCNL] No default policy found. \n");
        }

        *p_platform_policy_size = (uint32_t)(policy.size() + 1);
        *pp_platform_policy = allocate_and_copy<uint8_t>(policy, *p_platform_policy_size);
        if (*pp_platform_policy == NULL) {
            HANDLE_ERROR(SGX_QCNL_OUT_OF_MEMORY, "[QCNL] Out of memory. \n");
        }

        return SGX_QCNL_SUCCESS;
    } while (0);

    tee_qcnl_free_platform_policy(*pp_platform_policy);
    *pp_platform_policy = NULL;
    *p_platform_policy_size = 0;
    return ret;
}

sgx_qcnl_error_t CertificationService::get_pck_cert_chain(const sgx_ql_pck_cert_id_t *p_pck_cert_id,
                                                          sgx_ql_config_t **pp_quote_config) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting pck certificate and chain. \n");

    // 1. Try the local cache for local cache only mode
    if (QcnlConfig::Instance()->is_local_cache_only()) {
        CacheProvider cacheProvider;
        return cacheProvider.get_local_certification(p_pck_cert_id, pp_quote_config);
    }

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;
    PccsResponseObject pccs_resp_obj;

    // build query options for getting pck certificate
    if ((ret = build_pckcert_options(request, p_pck_cert_id)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    // 2. Try the local service provider
    void *args[] = {pp_quote_config};
    CertificationProvider localProvider(QcnlConfig::Instance()->getLocalPckUrl());
    if ((ret = localProvider.get_certification(request.headers, request.params, &pccs_resp_obj)) == SGX_QCNL_SUCCESS) {
        qcnl_log(SGX_QL_LOG_INFO,
                 "[QCNL] Successfully fetched certificate from primary URL: '%s'. \n",
                 QcnlConfig::Instance()->getLocalPckUrl().c_str());
        return resp_obj_to_pck_certchain(&pccs_resp_obj, args);
    }

    HandlerData handlerData = {resp_obj_to_pck_certchain, args};

    return fetch_data(PCK_CERT_CHAIN, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_pck_crl_chain(const char *ca,
                                                         uint16_t ca_size,
                                                         uint8_t **pp_crl_chain,
                                                         uint16_t *p_crl_chain_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting pck crl. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    // build query options for getting pck crl
    if ((ret = build_pckcrl_options(request, ca, ca_size)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_crl_chain, p_crl_chain_size};
    HandlerData handlerData = {resp_obj_to_pck_crl, args};

    return fetch_data(PCK_CRL_CHAIN, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_tcbinfo(sgx_prod_type_t prod_type,
                                                   const char *fmspc,
                                                   uint16_t fmspc_size,
                                                   uint8_t **pp_tcbinfo,
                                                   uint16_t *p_tcbinfo_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting tcb info. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    // build query options for getting tcbinfo
    if ((ret = build_tcbinfo_options(request, fmspc, fmspc_size, prod_type)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_tcbinfo, p_tcbinfo_size};
    HandlerData handlerData = {resp_obj_to_tcbinfo, args};

    return fetch_data(TCBINFO, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_qe_identity(sgx_qe_type_t qe_type,
                                                       uint8_t **pp_qe_identity,
                                                       uint16_t *p_qe_identity_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting quote enclave identity. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    if ((ret = build_qeidentity_options(request, qe_type)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_qe_identity, p_qe_identity_size};
    HandlerData handlerData = {resp_obj_to_qe_identity, args};

    return fetch_data(QE_IDENTITY, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_qve_identity(char **pp_qve_identity,
                                                        uint32_t *p_qve_identity_size,
                                                        char **pp_qve_identity_issuer_chain,
                                                        uint32_t *p_qve_identity_issuer_chain_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting quote verification enclave identity. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    if ((ret = build_qveidentity_options(request)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_qve_identity, p_qve_identity_size, pp_qve_identity_issuer_chain, p_qve_identity_issuer_chain_size};
    HandlerData handlerData = {resp_obj_to_qve_identity, args};

    return fetch_data(QVE_IDENTITY, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_root_ca_crl(const char *root_ca_cdp_url,
                                                       uint8_t **pp_root_ca_crl,
                                                       uint16_t *p_root_ca_crl_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting root ca crl. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    if ((ret = build_root_ca_crl_options(request, root_ca_cdp_url)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_root_ca_crl, p_root_ca_crl_size};
    HandlerData handlerData = {resp_obj_to_root_ca_crl, args};

    return fetch_data(ROOT_CA_CRL, request, &handlerData);
}

sgx_qcnl_error_t CertificationService::get_default_platform_policy(const char *fmspc,
                                                                   const uint16_t fmspc_size,
                                                                   uint8_t **pp_platform_policy,
                                                                   uint32_t *p_platform_policy_size) {
    qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Getting default platform policy. \n");

    sgx_qcnl_error_t ret = SGX_QCNL_SUCCESS;
    Request request;

    // build request options for getting platform policies
    if ((ret = build_appraisalpolicy_options(request, fmspc, fmspc_size)) != SGX_QCNL_SUCCESS) {
        return ret;
    }

    void *args[] = {pp_platform_policy, p_platform_policy_size};
    HandlerData handlerData = {resp_obj_to_appraisalpolicy, args};

    return fetch_data(APPRAISAL_POLICY, request, &handlerData);
}
