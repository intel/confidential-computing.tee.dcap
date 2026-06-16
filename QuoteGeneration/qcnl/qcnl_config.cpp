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
 * File: qcnl_config.cpp
 *
 * Description: Read configuration data
 *
 */

#include "qcnl_config.h"
#include "error/en.h"
#include "error/error.h"
#include <fstream>
#include <istreamwrapper.h>
#include <mutex>
#include <algorithm>

using namespace std;

std::shared_ptr<QcnlConfig> QcnlConfig::myInstance;
static std::mutex mutex_config_lock;

std::shared_ptr<QcnlConfig> QcnlConfig::Instance() {
    // Lock the mutex
    std::lock_guard<std::mutex> lock(mutex_config_lock);

    if (!myInstance) {
        QcnlConfigJson *pConfigJson = new QcnlConfigJson();
        if (pConfigJson->load_config() == SGX_QCNL_SUCCESS) {
            myInstance.reset(pConfigJson);
        } else {
            delete pConfigJson;
            pConfigJson = nullptr;
            QcnlConfigLegacy *pConfigLegacy = new QcnlConfigLegacy();
            pConfigLegacy->load_config();
            myInstance.reset(pConfigLegacy);
        }
    }

    return myInstance;
}

sgx_qcnl_error_t QcnlConfig::load_config_json(const TCHAR *json_file) {
    ifstream ifs(json_file);
    IStreamWrapper isw(ifs);

    Document config;
    ParseResult ok = config.ParseStream<kParseCommentsFlag>(isw);

    if (!ok) {
        // If the config file starts with '{', it's likely JSON format
        char first_byte = 0;
        ifs.clear();
        ifs.seekg(0, ifs.beg);
        if (ifs.get(first_byte) && first_byte == '{') {
            qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Load JSON config error: %s (offset %lu).\n",
                     GetParseError_En(ok.Code()), ok.Offset());
            return SGX_QCNL_CONFIG_INVALID_JSON;
        } else {
            qcnl_log(SGX_QL_LOG_INFO, "[QCNL] Failed to load config file in JSON format. \n");
            return SGX_QCNL_CONFIG_NOT_JSON;
        }
    } else {
        qcnl_log(SGX_QL_LOG_INFO, "[QCNL] JSON config file %s is loaded successfully. \n", json_file);
    }

    if (config.HasMember("pccs_url")) {
        Value &val = config["pccs_url"];
        if (val.IsString()) {
            this->server_url_ = val.GetString();
            this->collateral_service_url_ = this->server_url_;
        }
    }

    if (config.HasMember("use_secure_cert")) {
        Value &val = config["use_secure_cert"];
        if (val.IsBool())
            this->use_secure_cert_ = val.GetBool();
    }

    if (config.HasMember("collateral_service")) {
        // will overwrite the previous value
        Value &val = config["collateral_service"];
        if (val.IsString()) {
            this->collateral_service_url_ = val.GetString();
        }
    }

    if (config.HasMember("tcb_update_type")) {
        Value &val = config["tcb_update_type"];
        if (val.IsString()) {
            string tcb_update_type = val.GetString();
            // Convert to lowercase
            std::transform(tcb_update_type.begin(), tcb_update_type.end(), tcb_update_type.begin(), 
                        [](unsigned char c){ return static_cast<unsigned char>(std::tolower(c)); });
            if (tcb_update_type != "early" && tcb_update_type != "standard") {
                qcnl_log(SGX_QL_LOG_ERROR, "[QCNL] Wrong tcb_update_type configured. \n");
                return SGX_QCNL_INVALID_CONFIG;
            }

            this->tcb_update_type_ = tcb_update_type;
        }
    }

    if (config.HasMember("pccs_api_version")) {
        Value &val = config["pccs_api_version"];
        if (val.IsString()) {
            this->collateral_version_ = val.GetString();
        }
    }

    if (config.HasMember("retry_times")) {
        Value &val = config["retry_times"];
        if (val.IsInt()) {
            this->retry_times_ = val.GetInt();
        }
    }

    if (config.HasMember("retry_delay")) {
        Value &val = config["retry_delay"];
        if (val.IsInt()) {
            this->retry_delay_ = val.GetInt();
        }
    }

    if (config.HasMember("local_pck_url")) {
        Value &val = config["local_pck_url"];
        if (val.IsString()) {
            this->local_pck_url_ = val.GetString();
        }
    }

    if (config.HasMember("pck_cache_expire_hours")) {
        Value &val = config["pck_cache_expire_hours"];
        if (val.IsDouble() || val.IsInt()) {
            this->pck_cache_expire_hours_ = val.GetDouble();
            if (this->pck_cache_expire_hours_ > CACHE_MAX_EXPIRY_HOURS)
                this->pck_cache_expire_hours_ = CACHE_MAX_EXPIRY_HOURS;
        }
    }

    if (config.HasMember("verify_collateral_cache_expire_hours")) {
        Value &val = config["verify_collateral_cache_expire_hours"];
        if (val.IsDouble() || val.IsInt()) {
            this->verify_collateral_expire_hours_ = val.GetDouble();
            if (this->verify_collateral_expire_hours_ > CACHE_MAX_EXPIRY_HOURS)
                this->verify_collateral_expire_hours_ = CACHE_MAX_EXPIRY_HOURS;
        }
    }

    if (config.HasMember("custom_request_options")) {
        Value &val = config["custom_request_options"];
        if (val.IsObject())
            custom_request_options_.CopyFrom(val, custom_request_options_.GetAllocator());
    }

    if (config.HasMember("local_cache_only")) {
        Value &val = config["local_cache_only"];
        if (val.IsBool())
            this->local_cache_only_ = val.GetBool();
    }

    return SGX_QCNL_SUCCESS;
}
