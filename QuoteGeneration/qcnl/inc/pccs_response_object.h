/*
 * Copyright(c) 2011-2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef PCCSRESPONSEOBJECT_H_
#define PCCSRESPONSEOBJECT_H_
#pragma once

#include "document.h"
#include "qcnl_def.h"
#include <sstream>
#include <string>
#include <unordered_map>

using namespace std;
using namespace rapidjson;

class PccsResponseObject {
private:
public:
    PccsResponseObject();
    ~PccsResponseObject();

    PccsResponseObject &set_raw_header(const char *header, uint32_t header_size);
    PccsResponseObject &set_raw_body(const char *body, uint32_t body_size);
    string &get_raw_header();
    string &get_raw_body();
    string get_header_key_value(const char *key);
    string get_body_key_value(const char *key);
    string get_real_response_body(const char *key);
    uint32_t get_cache_max_age();

protected:
    string header_raw_;
    unordered_map<string, string> header_map_;
    string body_raw_;
    Document body_json_;
    bool is_body_json_;
};

class PckCertResponseObject : public PccsResponseObject {
private:
public:
    PckCertResponseObject() {}
    ~PckCertResponseObject() {}
    PckCertResponseObject(const PckCertResponseObject&) = delete;
    PckCertResponseObject& operator=(const PckCertResponseObject&) = delete;

    string get_tcbm() {
        string tcbm = this->get_header_key_value(intelpcs::SGX_TCBM);
        return tcbm.empty() ? this->get_body_key_value(azurepccs::SGX_TCBM) : tcbm;
    }
    string get_pckcert_issuer_chain() {
        string chain = this->get_header_key_value(intelpcs::PCK_CERT_ISSUER_CHAIN);
        return chain.empty() ? this->get_body_key_value(azurepccs::PCK_CERT_ISSUER_CHAIN) : chain;
    }
    string get_pckcert() {
        return this->get_real_response_body(azurepccs::PCK_CERT);
    }
};

class PckCrlResponseObject : public PccsResponseObject {
private:
public:
    PckCrlResponseObject() {}
    ~PckCrlResponseObject() {}
    PckCrlResponseObject(const PckCrlResponseObject&) = delete;
    PckCrlResponseObject& operator=(const PckCrlResponseObject&) = delete;

    string get_pckcrl_issuer_chain() {
        return this->get_header_key_value(intelpcs::CRL_ISSUER_CHAIN);
    }
    string get_pckcrl() {
        return this->body_raw_;
    }
};

class TcbInfoResponseObject : public PccsResponseObject {
private:
public:
    TcbInfoResponseObject() {}
    ~TcbInfoResponseObject() {}
    TcbInfoResponseObject(const TcbInfoResponseObject&) = delete;
    TcbInfoResponseObject& operator=(const TcbInfoResponseObject&) = delete;

    string get_tcbinfo_issuer_chain() {
        string chain = this->get_header_key_value(intelpcs::SGX_TCB_INFO_ISSUER_CHAIN);
        if (!chain.empty())
            return chain;

        chain = this->get_header_key_value(intelpcs::TCB_INFO_ISSUER_CHAIN);
        if (!chain.empty())
            return chain;

        return "";
    }
    string get_tcbinfo() {
        // return this->get_real_response_body();
        return body_raw_;
    }
};

class QeIdentityResponseObject : public PccsResponseObject {
private:
public:
    QeIdentityResponseObject() {}
    ~QeIdentityResponseObject() {}
    QeIdentityResponseObject(const QeIdentityResponseObject&) = delete;
    QeIdentityResponseObject& operator=(const QeIdentityResponseObject&) = delete;

    string get_enclave_id_issuer_chain() {
        return this->get_header_key_value(intelpcs::ENCLAVE_ID_ISSUER_CHAIN);
    }
    string get_qeidentity() {
        return body_raw_;
    }
};

class QveIdentityResponseObject : public PccsResponseObject {
private:
public:
    QveIdentityResponseObject() {}
    ~QveIdentityResponseObject() {}
    QveIdentityResponseObject(const QveIdentityResponseObject&) = delete;
    QveIdentityResponseObject& operator=(const QveIdentityResponseObject&) = delete;

    string get_enclave_id_issuer_chain() {
        return this->get_header_key_value(intelpcs::ENCLAVE_ID_ISSUER_CHAIN);
    }
    string get_qveidentity() {
        return body_raw_;
    }
};

#endif