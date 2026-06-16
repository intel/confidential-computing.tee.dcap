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
 * File: qcnl_config_impl.cpp
 *
 * Description: Read configuration data
 *
 */

#include "istreamwrapper.h"
#include "qcnl_config.h"
#include <algorithm>
#include <curl/curl.h>
#include <fstream>
#include <cstdlib>
#include <stdexcept>

const char* get_config_path() {
    const char* env_path = std::getenv("QCNL_CONF_PATH");
    return env_path != nullptr ? env_path : "/etc/sgx_default_qcnl.conf";
}

sgx_qcnl_error_t QcnlConfigLegacy::load_config() {
    // read configuration File
    bool use_collateral_service = false;
    std::ifstream ifs(get_config_path());

    if (ifs.is_open()) {
        string line;
        auto f = [](unsigned char const c) { return std::isspace(c); };
        while (getline(ifs, line)) {
            line.erase(std::remove_if(line.begin(), line.end(), f), line.end());
            if (line[0] == '#' || line.empty())
                continue;
            size_t pos = line.find("=");
            string name = line.substr(0, pos);
            string value = line.substr(pos + 1);
            if (name.compare("PCCS_URL") == 0) {
                server_url_ = value;
            } else if (name.compare("USE_SECURE_CERT") == 0 &&
                       (value.compare("FALSE") == 0 || value.compare("false") == 0)) {
                use_secure_cert_ = false;
            } else if (name.compare("COLLATERAL_SERVICE") == 0) {
                use_collateral_service = true;
                collateral_service_url_ = value;
            } else if (name.compare("PCCS_API_VERSION") == 0) {
                collateral_version_ = value;
            } else if (name.compare("RETRY_TIMES") == 0) {
                try {
                    string::size_type sz;
                    retry_times_ = stoi(value, &sz);
                } catch (const invalid_argument &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid value for RETRY_TIMES: '%s', using default.\n", value.c_str());
                    continue;
                } catch (const out_of_range &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out-of-range value for RETRY_TIMES: '%s', using default.\n", value.c_str());
                    continue;
                }
            } else if (name.compare("RETRY_DELAY") == 0) {
                try {
                    string::size_type sz;
                    retry_delay_ = stoi(value, &sz);
                } catch (const invalid_argument &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid value for RETRY_DELAY: '%s', using default.\n", value.c_str());
                    continue;
                } catch (const out_of_range &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out-of-range value for RETRY_DELAY: '%s', using default.\n", value.c_str());
                    continue;
                }
            } else if (name.compare("LOCAL_PCK_URL") == 0) {
                local_pck_url_ = value;
            } else if (name.compare("PCK_CACHE_EXPIRE_HOURS") == 0) {
                try {
                    string::size_type sz;
                    pck_cache_expire_hours_ = (double)stoi(value, &sz);
                    if (pck_cache_expire_hours_ > CACHE_MAX_EXPIRY_HOURS)
                        pck_cache_expire_hours_ = CACHE_MAX_EXPIRY_HOURS;
                } catch (const invalid_argument &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid value for PCK_CACHE_EXPIRE_HOURS: '%s', using default.\n", value.c_str());
                    continue;
                } catch (const out_of_range &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out-of-range value for PCK_CACHE_EXPIRE_HOURS: '%s', using default.\n", value.c_str());
                    continue;
                }
            } else if (name.compare("VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS") == 0) {
                try {
                    string::size_type sz;
                    verify_collateral_expire_hours_ = (double)stoi(value, &sz);
                    if (verify_collateral_expire_hours_ > CACHE_MAX_EXPIRY_HOURS)
                        verify_collateral_expire_hours_ = CACHE_MAX_EXPIRY_HOURS;
                } catch (const invalid_argument &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Invalid value for VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS: '%s', using default.\n", value.c_str());
                    continue;
                } catch (const out_of_range &) {
                    qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Out-of-range value for VERIFY_COLLATERAL_CACHE_EXPIRE_HOURS: '%s', using default.\n", value.c_str());
                    continue;
                }
            } else if (name.compare("LOCAL_CACHE_ONLY") == 0 &&
                       (value.compare("TRUE") == 0 || value.compare("true") == 0)) {
                local_cache_only_ = true;
            } else {
                continue;
            }
        }
    }
    if (!use_collateral_service) {
        collateral_service_url_ = server_url_;
    }

    return SGX_QCNL_SUCCESS;
}

sgx_qcnl_error_t QcnlConfigJson::load_config() {
    return this->load_config_json(get_config_path());
}
