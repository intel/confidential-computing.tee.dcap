/*
 * Copyright(c) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <openssl/x509.h>

#include "PckParser/CrlStore.h"

namespace intel { namespace sgx { namespace dcap { namespace pckparser {

    CrlStore::CrlStore() : _crl(nullptr, X509_CRL_free),
        _issuer{},
        _validity{},
        _revoked{},
        _extensions{},
        _signature{},
        _crlNum{ 0 }
    {}

bool CrlStore::operator==(const CrlStore& other) const {
    return _crlNum == other._crlNum; // Compare based on CRL number as a placeholder
}

bool CrlStore::operator!=(const CrlStore& other) const {
    return !(*this == other);
}

bool CrlStore::parse(const std::string& crlString) {
    // Stub implementation: return true to indicate success
    return true;
}

bool CrlStore::expired(const time_t& expirationDate) const {
    // Stub implementation: return false to indicate not expired
    return false;
}

const Issuer& CrlStore::getIssuer() const {
    return _issuer; // Return the stored issuer
}

const Validity& CrlStore::getValidity() const {
    return _validity; // Return the stored validity
}

const Signature& CrlStore::getSignature() const {
    return _signature; // Return the stored signature
}

const std::vector<Extension>& CrlStore::getExtensions() const {
    return _extensions; // Return the stored extensions
}

const std::vector<Revoked>& CrlStore::getRevoked() const {
    return _revoked; // Return the stored revoked certificates
}

long CrlStore::getCrlNum() const {
    return _crlNum; // Return the stored CRL number
}

const X509_CRL& CrlStore::getCrl() const {
    if (!_crl) {
        throw std::runtime_error("CRL not initialized");
    }
    return *_crl; // Return the stored CRL
}

bool CrlStore::isRevoked(const dcap::parser::x509::Certificate& cert) const {
    // Stub implementation: return false to indicate the certificate is not revoked
    return false;
}

}}}} // namespace intel::sgx::dcap::pckparser

// Stub implementation of X509_CRL_free
void X509_CRL_free(X509_CRL* crl) {
    // No-op for testing purposes
}